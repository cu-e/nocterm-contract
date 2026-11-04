//! Per-chat SSH binding, format 1: which of the person's CA-trusted servers one Cloud chat may
//! reach, and the runner's requests for short certificates inside that binding (contract
//! ADR 0009).
//!
//! A device binds a chat with `IssueGrant(GrantPayload::SshBinding)`. The binding is an
//! [`SshBinding`] signed by the account's SSH CA key ([`SignedSshBinding`]): only a device that
//! opened the CA seed from the account's encrypted `agent_ssh_trust` collection can make one, and
//! any other device verifies it without trusting the runner or the hub. The runner echoes the
//! signed binding in every [`SshCertificateRequest`] it publishes, so a device that never saw the
//! binding command still checks the exact servers, window and CA the person chose. The runner
//! reports what it made of a binding with [`SshAccessUpdate`] events. None of these values is an
//! execution permit: the certificate an account device signs is the only credential, and a hub
//! can mint neither.
//!
//! Layouts (strict, big-endian, u32-length fields, closed tags, exact EOF):
//! - binding signing bytes: field(`nocterm/cloud-ssh-binding/v1`) ‖ field(chat coordinate) ‖
//!   grant id 16 ‖ grant epoch u64 ‖ issued at i64 ‖ expires at i64 ‖ CA key 32 ‖ u8 target count ‖
//!   targets (server 16 ‖ field(host) ‖ port u16 ‖ field(user) ‖ host key SHA-256 32);
//! - signed binding: field(signing bytes) ‖ Ed25519 signature by the CA key (64);
//! - certificate request: field(`nocterm/cloud-ssh-request/v1`) ‖ request id 16 ‖ field(signed
//!   binding) ‖ subject key 32 ‖ u8 count ‖ field(source address)* ‖ u8 count ‖ server 16* ‖ not
//!   after i64;
//! - access update: field(`nocterm/cloud-ssh-access/v1`) ‖ grant id 16 ‖ grant epoch u64 ‖ access
//!   tag (1 pending, 2 active ‖ request 16 ‖ valid before i64, 3 refused ‖ reason u8, 4 revoked,
//!   5 expired) ‖ u8 count ‖ (server 16 ‖ reach u8)*.
mod codec;

use super::{ChatCoordinate, CloudTextId, CommandError, MaterialError, payload::GrantReference};
use crate::pop::{self, SignatureError};
use sha2::{Digest, Sha256};

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
/// Most servers one binding names.
pub const MAX_BINDING_TARGETS: usize = 16;
/// The longest binding window: 30 days.
pub const MAX_BINDING_WINDOW_MS: i64 = 30 * DAY_MS;
/// The window a device proposes when the person does not choose one: 7 days.
pub const DEFAULT_BINDING_WINDOW_MS: i64 = 7 * DAY_MS;
/// The longest life of one certificate: 24 hours.
pub const MAX_CERTIFICATE_VALIDITY_MS: i64 = 24 * HOUR_MS;
/// The life a runner asks for and a device grants by default: 8 hours.
pub const DEFAULT_CERTIFICATE_VALIDITY_MS: i64 = 8 * HOUR_MS;
/// Most `source-address` entries one request names.
pub const MAX_SOURCE_ADDRESSES: usize = 8;
/// The longest source address or CIDR.
pub const MAX_SOURCE_ADDRESS_BYTES: usize = 64;
/// The largest OpenSSH certificate blob an answer carries.
pub const MAX_CERTIFICATE_BYTES: usize = 4096;
/// The largest binding signing bytes (16 targets at the longest texts fit).
pub const MAX_BINDING_BYTES: usize = 8192;
/// The largest signed binding framing.
pub const MAX_SIGNED_BINDING_BYTES: usize = MAX_BINDING_BYTES + 4 + 64;
/// The largest certificate request.
pub const MAX_REQUEST_BYTES: usize = MAX_SIGNED_BINDING_BYTES + 1024;

/// One server of the account's `agent_ssh_trust` registry: the first 16 bytes of SHA-256 of the
/// connection profile id the server was trusted through. Its registry object is
/// `srv-<32 hex>` ([`SshServerId::object_id`]); its CA principal is derived from it and the CA
/// key, so a server's `authorized_keys` line and the certificates for it agree without the
/// server knowing the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SshServerId([u8; 16]);
impl SshServerId {
    const OBJECT_PREFIX: &'static str = "srv-";

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    /// The server trusted through connection profile `profile_id`.
    pub fn of_profile(profile_id: &str) -> Self {
        let digest = Sha256::digest(profile_id.as_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Self(id)
    }
    /// `srv-<32 lowercase hex>`, the object id of its `agent_ssh_trust` record.
    pub fn object_id(&self) -> String {
        format!("{}{}", Self::OBJECT_PREFIX, hex::encode(self.0))
    }
    /// The id an `agent_ssh_trust` object id names; `None` for any other object (the CA).
    pub fn from_object_id(object_id: &str) -> Option<Self> {
        let text = object_id.strip_prefix(Self::OBJECT_PREFIX)?;
        if text.len() != 32 || text.contains(|c: char| c.is_ascii_uppercase()) {
            return None;
        }
        hex::decode(text).ok()?.try_into().ok().map(Self)
    }
}

/// One server a binding names, as the device selected it from the account's CA-trusted servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshTarget {
    pub server: SshServerId,
    pub host: CloudTextId,
    pub port: u16,
    pub user: CloudTextId,
    /// SHA-256 of the server's host key blob, which the runner pins.
    pub host_key_sha256: [u8; 32],
}
impl SshTarget {
    fn validate(&self) -> Result<(), SshFormatError> {
        let plain = |text: &CloudTextId| {
            !text
                .as_str()
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        };
        if self.port == 0
            || self.host_key_sha256 == [0; 32]
            || !plain(&self.host)
            || !plain(&self.user)
        {
            return Err(SshFormatError::Value);
        }
        Ok(())
    }
}

/// When a binding is in force: `issued_at_ms <= now < expires_at_ms`, at most 30 days.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingWindow {
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}
impl BindingWindow {
    pub fn contains(&self, now_ms: i64) -> bool {
        self.issued_at_ms <= now_ms && now_ms < self.expires_at_ms
    }
}

/// What the person allows one chat: these servers, in this window, under this CA. Plain data;
/// [`SshBinding::validate`] holds the bounds every encoder and decoder applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshBinding {
    pub chat: ChatCoordinate,
    /// One id per chat binding; a binding with a higher epoch replaces it.
    pub grant: GrantReference,
    pub window: BindingWindow,
    /// The account CA's Ed25519 public key, which signs the binding and every certificate.
    pub ca_key: [u8; 32],
    pub targets: Vec<SshTarget>,
}
impl SshBinding {
    pub fn validate(&self) -> Result<(), SshFormatError> {
        let window = self.window;
        let length = window.expires_at_ms.saturating_sub(window.issued_at_ms);
        if self.grant.epoch == 0
            || window.issued_at_ms <= 0
            || length <= 0
            || length > MAX_BINDING_WINDOW_MS
            || self.ca_key == [0; 32]
            || self.targets.is_empty()
            || self.targets.len() > MAX_BINDING_TARGETS
        {
            return Err(SshFormatError::Value);
        }
        for (index, target) in self.targets.iter().enumerate() {
            target.validate()?;
            if self.targets[..index]
                .iter()
                .any(|known| known.server == target.server)
            {
                return Err(SshFormatError::Value);
            }
        }
        Ok(())
    }
    /// The target of `server`.
    pub fn target(&self, server: &SshServerId) -> Option<&SshTarget> {
        self.targets.iter().find(|target| &target.server == server)
    }
    /// The bytes the CA key signs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, SshFormatError> {
        self.validate()?;
        codec::write_binding(self)
    }
    pub fn from_signing_bytes(bytes: &[u8]) -> Result<Self, SshFormatError> {
        let binding = codec::read_binding(bytes)?;
        binding.validate()?;
        Ok(binding)
    }
}

/// A binding whose signature verified under the CA key it names. Whether that CA is the
/// account's is the verifier's decision ([`SignedSshBinding::require_ca`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSshBinding {
    binding: SshBinding,
    signature: [u8; 64],
}
impl SignedSshBinding {
    /// Verifies `signature` over the signing bytes under `binding.ca_key`.
    pub fn new(binding: SshBinding, signature: [u8; 64]) -> Result<Self, SshFormatError> {
        pop::verify(&binding.ca_key, &binding.signing_bytes()?, &signature)?;
        Ok(Self { binding, signature })
    }
    pub fn binding(&self) -> &SshBinding {
        &self.binding
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
    /// Refuses a binding signed by another CA than `trusted_ca`.
    pub fn require_ca(&self, trusted_ca: &[u8; 32]) -> Result<(), SshFormatError> {
        if &self.binding.ca_key == trusted_ca {
            Ok(())
        } else {
            Err(SshFormatError::Authority)
        }
    }
    /// field(signing bytes) ‖ signature.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SshFormatError> {
        let body = self.binding.signing_bytes()?;
        let mut bytes = Vec::with_capacity(body.len() + 68);
        super::codec::field(&mut bytes, &body)?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SshFormatError> {
        if bytes.len() > MAX_SIGNED_BINDING_BYTES {
            return Err(SshFormatError::Bounds);
        }
        let mut reader = super::codec::Reader::new(bytes);
        let body = reader.field(MAX_BINDING_BYTES)?;
        let signature = reader.array()?;
        reader.finish()?;
        Self::new(SshBinding::from_signing_bytes(body)?, signature)
    }
}

/// A runner asks for a certificate for its per-chat key (chat event `SshCertificateRequested`).
/// Plain data; [`SshCertificateRequest::validate`] holds its bounds and its relation to the
/// echoed binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshCertificateRequest {
    pub request: [u8; 16],
    pub binding: SignedSshBinding,
    /// The runner's per-chat Ed25519 public key.
    pub subject_key: [u8; 32],
    /// The runner's stated egress, for the certificate's mandatory `source-address`.
    pub source_addresses: Vec<String>,
    /// The bound servers the runner admitted and asks for, a subset of the binding.
    pub servers: Vec<SshServerId>,
    /// The end of validity the runner asks for; never after the binding ends.
    pub not_after_ms: i64,
}
impl SshCertificateRequest {
    pub fn validate(&self) -> Result<(), SshFormatError> {
        let binding = self.binding.binding();
        let address = |a: &String| {
            !a.is_empty()
                && a.len() <= MAX_SOURCE_ADDRESS_BYTES
                && a.chars()
                    .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
        };
        if self.subject_key == [0; 32]
            || self.source_addresses.is_empty()
            || self.source_addresses.len() > MAX_SOURCE_ADDRESSES
            || !self.source_addresses.iter().all(address)
            || self.servers.is_empty()
            || self.servers.len() > MAX_BINDING_TARGETS
            || self.not_after_ms <= binding.window.issued_at_ms
            || self.not_after_ms > binding.window.expires_at_ms
        {
            return Err(SshFormatError::Value);
        }
        for (index, server) in self.servers.iter().enumerate() {
            if binding.target(server).is_none() || self.servers[..index].contains(server) {
                return Err(SshFormatError::Value);
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SshFormatError> {
        self.validate()?;
        codec::write_request(self)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SshFormatError> {
        let request = codec::read_request(bytes)?;
        request.validate()?;
        Ok(request)
    }
}

/// Why a runner did not take a binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SshBindingRefusal {
    /// The runner states no egress address, so no certificate could name one.
    NoSourceAddress = 1,
    /// None of the bound servers is among the targets the runner may reach.
    NoReachableServer = 2,
    /// The binding is not valid for this chat (another chat, an older epoch, a bad signature).
    Invalid = 3,
}

/// What a runner made of a binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshAccess {
    /// Admitted; waiting for an account device to answer a request.
    Pending,
    /// A certificate answered `request` and is valid until `valid_before_ms`.
    Active {
        request: [u8; 16],
        valid_before_ms: i64,
    },
    Refused(SshBindingRefusal),
    /// The binding was revoked; the runner forgot its key and certificate.
    Revoked,
    /// The binding window ended.
    Expired,
}

/// Whether the runner may reach one bound server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SshServerReach {
    /// The server is among the runner's configured or boot targets.
    Admitted = 1,
    /// This runner cannot reach the server.
    Unreachable = 2,
}

/// One bound server's reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshServerStatus {
    pub server: SshServerId,
    pub reach: SshServerReach,
}

/// A binding's state as its runner reports it (chat event `SshAccessState`). Display data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshAccessUpdate {
    pub grant: GrantReference,
    pub access: SshAccess,
    /// At most [`MAX_BINDING_TARGETS`], each server once.
    pub servers: Vec<SshServerStatus>,
}
impl SshAccessUpdate {
    pub fn validate(&self) -> Result<(), SshFormatError> {
        if self.grant.epoch == 0
            || self.servers.len() > MAX_BINDING_TARGETS
            || matches!(self.access, SshAccess::Active { valid_before_ms, .. } if valid_before_ms <= 0)
        {
            return Err(SshFormatError::Value);
        }
        for (index, status) in self.servers.iter().enumerate() {
            if self.servers[..index]
                .iter()
                .any(|known| known.server == status.server)
            {
                return Err(SshFormatError::Value);
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SshFormatError> {
        self.validate()?;
        codec::write_update(self)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SshFormatError> {
        let update = codec::read_update(bytes)?;
        update.validate()?;
        Ok(update)
    }
}

/// An SSH binding value was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SshFormatError {
    #[error("the SSH binding value exceeds its bound")]
    Bounds,
    #[error("the SSH binding value holds an invalid or unsupported value")]
    Value,
    #[error("malformed or noncanonical SSH binding value")]
    Malformed,
    #[error("the SSH binding is signed by another CA")]
    Authority,
    #[error("the SSH binding framing is invalid")]
    Framing(#[from] CommandError),
    #[error("the SSH binding names invalid chat coordinates")]
    Chat(#[from] MaterialError),
    #[error("the SSH binding's CA signature is invalid")]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
mod tests;
