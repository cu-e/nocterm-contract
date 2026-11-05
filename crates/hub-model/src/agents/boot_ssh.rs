//! The SSH section of a managed runner's boot document (contract ADR 0011): `ssh_targets` and
//! `ssh_egress`, as a host's node writes them and the runner reads them.
//!
//! The rest of the boot document (identity, provider, policy) stays the runner's and the node's
//! format; this module fixes only what chat SSH bindings depend on, in the same JSON spelling.
//!
//! - Boot **v2** ([`BOOT_VERSION_WITHOUT_SSH_EGRESS`]): no `ssh_egress`; targets carry `host`,
//!   `user` and `port` only. A runner booted with v2 binds no chat to servers.
//! - Boot **v3** ([`BOOT_VERSION_SSH`]): `ssh_egress` lists one to eight IP addresses or CIDRs
//!   ([`crate::cloud::ssh::is_source_address`]); each target may add `host_public_key`, the
//!   server's host key as one OpenSSH line, and `session`, how a session on it starts. A target
//!   without a host key is never admitted for a binding and cannot be signed in to.
//!
//! Selection, never construction: [`BootSshTarget::admits`] admits a bound server only when its
//! host, port and user equal a target's and the binding's host key fingerprint equals the SHA-256
//! of that target's host key blob.
use crate::cloud::ssh::{MAX_SOURCE_ADDRESSES, SshTarget, is_source_address};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The boot format without SSH egress.
pub const BOOT_VERSION_WITHOUT_SSH_EGRESS: u32 = 2;
/// The boot format with SSH egress, target host keys and session settings.
pub const BOOT_VERSION_SSH: u32 = 3;
/// Most SSH targets one boot document lists.
pub const MAX_BOOT_SSH_TARGETS: usize = 64;
/// The longest target host name or address.
pub const MAX_BOOT_SSH_HOST_BYTES: usize = 253;
/// The longest login user (a binding's user is a `CloudTextId`).
pub const MAX_BOOT_SSH_USER_BYTES: usize = 128;
/// The longest OpenSSH host public key line.
pub const MAX_HOST_PUBLIC_KEY_BYTES: usize = 2048;
/// The longest terminal type.
pub const MAX_TERMINAL_BYTES: usize = 128;
/// Most arguments of a session program.
pub const MAX_SESSION_ARGS: usize = 64;
/// The longest program, directory and arguments together.
pub const MAX_SESSION_STRING_BYTES: usize = 16 * 1024;
/// The longest connection timeout.
pub const MAX_CONNECT_TIMEOUT_MS: u64 = 60_000;

/// Host key algorithms a target may name.
const HOST_KEY_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-rsa",
];

/// How a session on a boot target starts. Every field is stated when `session` is present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootSshSession {
    /// The `TERM` the runner asks for: letters, digits and `-_.+`.
    pub terminal: String,
    /// 2 to 240.
    pub columns: u16,
    /// 1 to 120.
    pub rows: u16,
    /// 1 to 60 000.
    pub connect_timeout_ms: u64,
    /// The program to start; absent starts the user's login shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// Its arguments, passed one by one, never parsed as a command line.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// The initial directory; absent uses the user's home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}
impl Default for BootSshSession {
    /// `xterm-256color`, 80 × 24, a 10 s connection timeout and the login shell.
    fn default() -> Self {
        Self {
            terminal: "xterm-256color".to_owned(),
            columns: 80,
            rows: 24,
            connect_timeout_ms: 10_000,
            program: None,
            args: Vec::new(),
            cwd: None,
        }
    }
}
impl BootSshSession {
    fn valid(&self) -> bool {
        let text = |value: &str| !value.is_empty() && !value.chars().any(char::is_control);
        let strings = self
            .program
            .as_ref()
            .map_or(0, String::len)
            .saturating_add(self.cwd.as_ref().map_or(0, String::len))
            .saturating_add(self.args.iter().map(String::len).sum::<usize>());
        !self.terminal.is_empty()
            && self.terminal.len() <= MAX_TERMINAL_BYTES
            && self
                .terminal
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+".contains(&byte))
            && (2..=240).contains(&self.columns)
            && (1..=120).contains(&self.rows)
            && (1..=MAX_CONNECT_TIMEOUT_MS).contains(&self.connect_timeout_ms)
            && self.program.as_deref().is_none_or(text)
            && self.cwd.as_deref().is_none_or(text)
            && self.args.len() <= MAX_SESSION_ARGS
            && self.args.iter().all(|arg| !arg.contains('\0'))
            && strings <= MAX_SESSION_STRING_BYTES
    }
}

/// One SSH target of a boot document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootSshTarget {
    pub host: String,
    pub user: String,
    pub port: u16,
    /// Boot v3: the server's host key, `<algorithm> <base64 blob> [comment]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_public_key: Option<String>,
    /// Boot v3: how a session starts; [`BootSshSession::default`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<BootSshSession>,
}
impl BootSshTarget {
    /// SHA-256 of the host key blob, the fingerprint a binding pins; `None` without a valid key.
    pub fn host_key_sha256(&self) -> Option<[u8; 32]> {
        host_key_blob(self.host_public_key.as_deref()?).map(|blob| Sha256::digest(blob).into())
    }
    /// How a session on this target starts.
    pub fn session_or_default(&self) -> BootSshSession {
        self.session.clone().unwrap_or_default()
    }
    /// Whether bound server `target` is this target: same host, port and user, and the binding's
    /// host key fingerprint is this target's host key.
    pub fn admits(&self, target: &SshTarget) -> bool {
        self.host == target.host.as_str()
            && self.port == target.port
            && self.user == target.user.as_str()
            && self.host_key_sha256() == Some(target.host_key_sha256)
    }
    fn check(&self, version: u32) -> Result<(), BootSshField> {
        let plain = |value: &str, maximum: usize| {
            !value.is_empty()
                && value.len() <= maximum
                && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        };
        if !plain(&self.host, MAX_BOOT_SSH_HOST_BYTES) {
            return Err(BootSshField::Host);
        }
        if !plain(&self.user, MAX_BOOT_SSH_USER_BYTES) {
            return Err(BootSshField::User);
        }
        if self.port == 0 {
            return Err(BootSshField::Port);
        }
        if version == BOOT_VERSION_WITHOUT_SSH_EGRESS
            && (self.host_public_key.is_some() || self.session.is_some())
        {
            return Err(BootSshField::NotInVersion);
        }
        if self
            .host_public_key
            .as_deref()
            .is_some_and(|key| host_key_blob(key).is_none())
        {
            return Err(BootSshField::HostKey);
        }
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.valid())
        {
            return Err(BootSshField::Session);
        }
        Ok(())
    }
}

/// The blob of one OpenSSH public key line whose leading string names its algorithm.
fn host_key_blob(line: &str) -> Option<Vec<u8>> {
    if line.len() > MAX_HOST_PUBLIC_KEY_BYTES || line.chars().any(char::is_control) {
        return None;
    }
    let mut parts = line.split(' ');
    let algorithm = parts.next()?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(parts.next()?)
        .ok()?;
    if !HOST_KEY_ALGORITHMS.contains(&algorithm) {
        return None;
    }
    let (length, rest) = blob.split_first_chunk::<4>()?;
    let named = rest.get(..usize::try_from(u32::from_be_bytes(*length)).ok()?)?;
    // `rsa-sha2-*` are signature names; the key blob of either names `ssh-rsa`.
    let expected = if algorithm.starts_with("rsa-sha2-") {
        "ssh-rsa"
    } else {
        algorithm
    };
    (named == expected.as_bytes() && rest.len() > named.len()).then_some(blob)
}

/// Checks a boot document's SSH section: its `version`, `ssh_targets` and `ssh_egress`.
pub fn check_boot_ssh(
    version: u32,
    targets: &[BootSshTarget],
    egress: Option<&[String]>,
) -> Result<(), BootSshError> {
    match (version, egress) {
        (BOOT_VERSION_WITHOUT_SSH_EGRESS, None) => {}
        (BOOT_VERSION_SSH, Some(egress))
            if (1..=MAX_SOURCE_ADDRESSES).contains(&egress.len())
                && egress.iter().all(|entry| is_source_address(entry)) => {}
        (BOOT_VERSION_WITHOUT_SSH_EGRESS | BOOT_VERSION_SSH, _) => {
            return Err(BootSshError::Egress);
        }
        _ => return Err(BootSshError::Version),
    }
    if targets.len() > MAX_BOOT_SSH_TARGETS {
        return Err(BootSshError::Targets);
    }
    for (index, target) in targets.iter().enumerate() {
        target
            .check(version)
            .map_err(|field| BootSshError::Target { index, field })?;
        let same = |known: &BootSshTarget| {
            known.host == target.host && known.port == target.port && known.user == target.user
        };
        if version == BOOT_VERSION_SSH && targets[..index].iter().any(same) {
            return Err(BootSshError::Target {
                index,
                field: BootSshField::Duplicate,
            });
        }
    }
    Ok(())
}

/// The first target of `targets` that admits bound server `target`.
pub fn admitting_target<'a>(
    targets: &'a [BootSshTarget],
    target: &SshTarget,
) -> Option<&'a BootSshTarget> {
    targets.iter().find(|known| known.admits(target))
}

/// What is wrong with one boot SSH target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootSshField {
    Host,
    User,
    Port,
    /// A v3 target with the same host, port and user as an earlier one.
    Duplicate,
    HostKey,
    Session,
    /// A v3 field in a v2 document.
    NotInVersion,
}

/// A boot document's SSH section was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BootSshError {
    #[error("unsupported boot document version")]
    Version,
    #[error(
        "boot ssh_egress does not match the version or is not one to eight IP addresses or CIDRs"
    )]
    Egress,
    #[error("boot ssh_targets lists more than {MAX_BOOT_SSH_TARGETS} targets")]
    Targets,
    #[error("boot ssh_targets[{index}] is invalid ({field:?})")]
    Target { index: usize, field: BootSshField },
}

#[cfg(test)]
mod tests;
