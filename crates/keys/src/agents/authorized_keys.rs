//! The `authorized_keys` line that makes a server trust the user's SSH CA, built and parsed.
//!
//! The line is `cert-authority,principals="nocterm-agent-<id>" ssh-ed25519 <blob> <comment>`.
//! Line version 1 (native ADR 0119) admits the CA's single agent principal
//! ([`super::ssh_ca::agent_principal`]); line version 2 (contract ADR 0009) admits only the
//! server's own principal ([`super::ssh_ca::principal_for`], built by [`CaLine::for_server`]), so
//! a certificate for one chat's servers opens no other server. Parsing is strict so that removing
//! "our" line never removes anything else.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use nocterm_hub_model::cloud::ssh::SshServerId;

use super::ssh_ca::{agent_principal, principal_for};
use super::ssh_grant::{MAX_PRINCIPAL_BYTES, PRINCIPAL_PREFIX};

const KEY_TYPE: &str = "ssh-ed25519";
/// Longest comment on the line.
pub const MAX_COMMENT_BYTES: usize = 128;
/// Most principals on one line.
pub const MAX_LINE_PRINCIPALS: usize = 8;

/// A line that is not a Nocterm CA line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LineError {
    /// Not `cert-authority,principals="…" ssh-ed25519 <key>[ comment]`.
    #[error("not a Nocterm CA authorized_keys line")]
    Malformed,
    /// A principal does not name an agent.
    #[error("a principal does not name an agent")]
    Principal,
    /// The comment is too long or contains control characters.
    #[error("the comment is invalid")]
    Comment,
}

/// A CA trusted for some agent principals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaLine {
    /// The CA's Ed25519 public key.
    pub ca_key: [u8; 32],
    /// Principals the CA may certify on this server.
    pub principals: Vec<String>,
    /// Free text after the key.
    pub comment: String,
}

fn wire_blob(key: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + KEY_TYPE.len() + 4 + 32);
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(KEY_TYPE.as_bytes());
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(key);
    blob
}

fn key_from_blob(blob: &[u8]) -> Option<[u8; 32]> {
    (blob.len() == 4 + KEY_TYPE.len() + 4 + 32
        && blob == wire_blob(blob[blob.len() - 32..].try_into().ok()?))
    .then(|| blob[blob.len() - 32..].try_into().ok())?
}

fn principal_ok(principal: &str) -> bool {
    principal.len() <= MAX_PRINCIPAL_BYTES
        && principal
            .strip_prefix(PRINCIPAL_PREFIX)
            .is_some_and(|rest| {
                !rest.is_empty()
                    && rest
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            })
}

/// How a server's `authorized_keys` trusts the current CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerLine {
    /// A line of the current CA admits this server's own principal (line version 2).
    PerServer,
    /// Only a line of the current CA with its shared principal (line version 1): certificates
    /// for this server are refused until the line is rewritten.
    Shared,
    /// No line of the current CA.
    Absent,
}

impl CaLine {
    /// The line version 2 of `server`: only that server's principal under `ca_key`.
    pub fn for_server(ca_key: [u8; 32], server: &SshServerId, comment: &str) -> Self {
        Self {
            ca_key,
            principals: vec![principal_for(&ca_key, server)],
            comment: comment.to_owned(),
        }
    }
    /// True when this line lets `ca_key` certify `server` (line version 2).
    pub fn admits_server(&self, ca_key: &[u8; 32], server: &SshServerId) -> bool {
        &self.ca_key == ca_key && self.principals.contains(&principal_for(ca_key, server))
    }
    fn validate(&self) -> Result<(), LineError> {
        if self.principals.is_empty()
            || self.principals.len() > MAX_LINE_PRINCIPALS
            || !self.principals.iter().all(|p| principal_ok(p))
        {
            return Err(LineError::Principal);
        }
        if self.comment.len() > MAX_COMMENT_BYTES || self.comment.chars().any(char::is_control) {
            return Err(LineError::Comment);
        }
        Ok(())
    }

    /// The line to append to `authorized_keys`, without a trailing newline.
    pub fn to_line(&self) -> Result<String, LineError> {
        self.validate()?;
        let mut line = format!(
            "cert-authority,principals=\"{}\" {KEY_TYPE} {}",
            self.principals.join(","),
            STANDARD.encode(wire_blob(&self.ca_key))
        );
        if !self.comment.is_empty() {
            line.push(' ');
            line.push_str(&self.comment);
        }
        Ok(line)
    }

    /// Parses one line; anything not exactly this shape is [`LineError::Malformed`].
    pub fn parse(line: &str) -> Result<Self, LineError> {
        let line = line.trim_end_matches(['\n', '\r']);
        let (options, rest) = line.split_once(' ').ok_or(LineError::Malformed)?;
        let principals = options
            .strip_prefix("cert-authority,principals=\"")
            .and_then(|o| o.strip_suffix('"'))
            .ok_or(LineError::Malformed)?;
        let (key_type, rest) = rest.split_once(' ').unwrap_or((rest, ""));
        if key_type != KEY_TYPE {
            return Err(LineError::Malformed);
        }
        let (blob, comment) = rest.split_once(' ').unwrap_or((rest, ""));
        let blob = STANDARD.decode(blob).map_err(|_| LineError::Malformed)?;
        let parsed = Self {
            ca_key: key_from_blob(&blob).ok_or(LineError::Malformed)?,
            principals: principals.split(',').map(str::to_owned).collect(),
            comment: comment.to_owned(),
        };
        parsed.validate()?;
        Ok(parsed)
    }
}

/// Which lines of an `authorized_keys` text are Nocterm CA lines for `ca_key`.
pub fn find_ca_lines(file: &str, ca_key: &[u8; 32]) -> Vec<usize> {
    file.lines()
        .enumerate()
        .filter(|(_, line)| CaLine::parse(line).is_ok_and(|l| &l.ca_key == ca_key))
        .map(|(index, _)| index)
        .collect()
}

/// How `file` trusts `ca_key` for `server`: a per-server line wins over a shared one.
pub fn server_line(file: &str, ca_key: &[u8; 32], server: &SshServerId) -> ServerLine {
    let lines: Vec<CaLine> = file
        .lines()
        .filter_map(|line| CaLine::parse(line).ok())
        .filter(|line| &line.ca_key == ca_key)
        .collect();
    if lines.iter().any(|line| line.admits_server(ca_key, server)) {
        ServerLine::PerServer
    } else if lines
        .iter()
        .any(|line| line.principals.contains(&agent_principal(ca_key)))
    {
        ServerLine::Shared
    } else {
        ServerLine::Absent
    }
}

/// The text with every Nocterm CA line of `ca_key` removed; all other bytes are kept as they
/// were, including the final newline.
pub fn remove_ca_lines(file: &str, ca_key: &[u8; 32]) -> String {
    file.split_inclusive('\n')
        .filter(|line| !CaLine::parse(line).is_ok_and(|l| &l.ca_key == ca_key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line() -> CaLine {
        CaLine {
            ca_key: [7; 32],
            principals: vec!["nocterm-agent-abc".into()],
            comment: "nocterm".into(),
        }
    }

    #[test]
    fn a_line_round_trips_and_has_the_documented_shape() {
        let text = line().to_line().unwrap();
        assert!(text.starts_with(
            "cert-authority,principals=\"nocterm-agent-abc\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
        ));
        assert_eq!(CaLine::parse(&text).unwrap(), line());
    }

    #[test]
    fn only_exact_nocterm_lines_parse() {
        for bad in [
            "ssh-ed25519 AAAA key",
            "cert-authority ssh-ed25519 AAAA",
            "cert-authority,principals=\"root\" ssh-ed25519 AAAA",
            "cert-authority,principals=\"nocterm-agent-a\" ssh-rsa AAAA",
            "cert-authority,principals=\"nocterm-agent-a\",no-pty ssh-ed25519 AAAA",
        ] {
            assert!(CaLine::parse(bad).is_err(), "{bad}");
        }
        let mut wrong = line();
        wrong.principals = vec!["root".into()];
        assert_eq!(wrong.to_line(), Err(LineError::Principal));
        let mut wrong = line();
        wrong.comment = "a\nb".into();
        assert_eq!(wrong.to_line(), Err(LineError::Comment));
    }

    #[test]
    fn removal_keeps_every_other_line_untouched() {
        let ours = line().to_line().unwrap();
        let other = CaLine {
            ca_key: [8; 32],
            ..line()
        }
        .to_line()
        .unwrap();
        let file = format!("ssh-ed25519 AAAA me\n{ours}\n{other}\n# note");
        assert_eq!(find_ca_lines(&file, &[7; 32]), vec![1]);
        assert_eq!(
            remove_ca_lines(&file, &[7; 32]),
            format!("ssh-ed25519 AAAA me\n{other}\n# note")
        );
        assert_eq!(remove_ca_lines("a\n", &[7; 32]), "a\n");
    }

    #[test]
    fn a_per_server_line_admits_only_its_server_and_parses_back() {
        let (db, cache) = (
            SshServerId::of_profile("profile-db"),
            SshServerId::of_profile("profile-cache"),
        );
        let ca = [7; 32];
        let line = CaLine::for_server(ca, &db, "nocterm agent access");
        let text = line.to_line().unwrap();
        assert!(text.starts_with(&format!(
            "cert-authority,principals=\"{}\" ssh-ed25519 ",
            principal_for(&ca, &db)
        )));
        assert_eq!(CaLine::parse(&text).unwrap(), line);
        assert!(line.admits_server(&ca, &db));
        assert!(!line.admits_server(&ca, &cache));
        assert!(!line.admits_server(&[8; 32], &db));
        let shared = CaLine {
            ca_key: ca,
            principals: vec![agent_principal(&ca)],
            comment: String::new(),
        }
        .to_line()
        .unwrap();
        assert_eq!(
            server_line(&format!("{text}\n"), &ca, &db),
            ServerLine::PerServer
        );
        assert_eq!(
            server_line(&format!("{shared}\n{text}\n"), &ca, &cache),
            ServerLine::Shared
        );
        assert_eq!(
            server_line(&format!("{shared}\n"), &[8; 32], &db),
            ServerLine::Absent
        );
        assert_eq!(find_ca_lines(&format!("{shared}\n{text}"), &ca), vec![0, 1]);
    }
}
