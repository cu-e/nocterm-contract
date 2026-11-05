//! A bound server as a session target (contract ADR 0011).
//!
//! A device names a bound server in `SubmitPrompt.target` with the [`TargetAccess`] this module
//! derives from the CA-signed binding's server entry; the runner derives the same value from the
//! binding it admitted and selects the server whose access is equal. Nothing here is
//! constructed from what a prompt carries: a selection that equals no bound server's selects
//! nothing.
//!
//! Fingerprints (SHA-256, big-endian, u32-length fields):
//! - host key: the binding's `host_key_sha256`;
//! - route: field(`nocterm/cloud-ssh-target-route/v1`) ‖ server 16 ‖ field(host) ‖ port u16 ‖
//!   field(user) ‖ host key 32;
//! - principal: the login user;
//! - workspace: field(`nocterm/cloud-ssh-target-workspace/v1`) ‖ server 16 ‖ field(user) ‖ host
//!   key 32 (the same account on the same server, whatever address reaches it);
//! - authentication key: the binding's CA key; credential revision:
//!   field(`nocterm/cloud-ssh-target-credential/v1`) ‖ grant id 16 ‖ grant epoch u64 ‖ CA key 32,
//!   so a newer binding epoch or another CA selects another credential.
use super::{SshBinding, SshServerId, SshTarget};
use crate::cloud::payload::{AuthenticationSelection, TargetAccess, TargetSelection};
use sha2::{Digest, Sha256};

const ROUTE_LABEL: &[u8] = b"nocterm/cloud-ssh-target-route/v1";
const WORKSPACE_LABEL: &[u8] = b"nocterm/cloud-ssh-target-workspace/v1";
const CREDENTIAL_LABEL: &[u8] = b"nocterm/cloud-ssh-target-credential/v1";

/// Appends a u32-length field. Every input here is a label or a checked `CloudTextId` (at most
/// `MAX_ID_BYTES`), so the length always fits.
fn field(hash: &mut Sha256, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hash.update(length.to_be_bytes());
    hash.update(bytes);
}

impl SshTarget {
    /// The route fingerprint of this server entry.
    pub fn route_fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        field(&mut hash, ROUTE_LABEL);
        hash.update(self.server.as_bytes());
        field(&mut hash, self.host.as_str().as_bytes());
        hash.update(self.port.to_be_bytes());
        field(&mut hash, self.user.as_str().as_bytes());
        hash.update(self.host_key_sha256);
        hash.finalize().into()
    }
    /// The workspace fingerprint of this server entry: its server, login user and host key.
    pub fn workspace_fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        field(&mut hash, WORKSPACE_LABEL);
        hash.update(self.server.as_bytes());
        field(&mut hash, self.user.as_str().as_bytes());
        hash.update(self.host_key_sha256);
        hash.finalize().into()
    }
    /// The target half of the session access that names this server.
    pub fn target_selection(&self) -> TargetSelection {
        TargetSelection {
            host_key: self.host_key_sha256,
            route: self.route_fingerprint(),
            principal: self.user.clone(),
            workspace: self.workspace_fingerprint(),
        }
    }
}

impl SshBinding {
    /// The credential revision of this binding's certificates.
    pub fn credential_revision(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        field(&mut hash, CREDENTIAL_LABEL);
        hash.update(self.grant.id);
        hash.update(self.grant.epoch.to_be_bytes());
        hash.update(self.ca_key);
        hash.finalize().into()
    }
    /// The authentication half of every bound server's session access: the CA key and the
    /// credential revision of this binding.
    pub fn authentication(&self) -> AuthenticationSelection {
        AuthenticationSelection {
            public_key: self.ca_key,
            credential_revision: self.credential_revision(),
        }
    }
    /// The session access that names bound server `server`; `None` when it is not bound.
    pub fn target_access(&self, server: &SshServerId) -> Option<TargetAccess> {
        self.target(server).map(|target| TargetAccess {
            target: target.target_selection(),
            authentication: self.authentication(),
        })
    }
    /// The bound server `access` names; `None` when it names none of this binding's servers
    /// (another binding epoch, another CA, or a target that is not bound).
    pub fn target_of_access(&self, access: &TargetAccess) -> Option<&SshTarget> {
        if access.authentication != self.authentication() {
            return None;
        }
        self.targets
            .iter()
            .find(|target| target.target_selection() == access.target)
    }
}
