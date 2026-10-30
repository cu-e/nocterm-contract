use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OrgId;

/// Which area owns an agent, a pool or a quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    /// One account's own agents.
    Account,
    /// An organization's agents.
    Org,
    /// The whole hub instance.
    Instance,
}

impl ScopeKind {
    /// Stable lowercase name used in storage and signed layouts.
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeKind::Account => "account",
            ScopeKind::Org => "org",
            ScopeKind::Instance => "instance",
        }
    }
}

/// An owner area that is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    /// The scope kind is unknown.
    #[error("unknown agent scope kind")]
    UnknownKind,
    /// An organization scope needs an organization id, other kinds forbid one.
    #[error("the scope id does not match the scope kind")]
    IdMismatch,
}

/// The area that owns an agent or a pool.
///
/// The account of a personal agent is the caller and therefore not repeated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AgentScope {
    /// The caller's personal agents.
    Account,
    /// Agents of one organization.
    Org(OrgId),
    /// Agents of the whole server.
    Instance,
}

impl AgentScope {
    /// Kind of the scope.
    pub fn kind(&self) -> ScopeKind {
        match self {
            AgentScope::Account => ScopeKind::Account,
            AgentScope::Org(_) => ScopeKind::Org,
            AgentScope::Instance => ScopeKind::Instance,
        }
    }

    /// Organization id of an organization scope.
    pub fn org(&self) -> Option<OrgId> {
        match self {
            AgentScope::Org(org) => Some(*org),
            _ => None,
        }
    }

    /// Scope from its kind and optional organization id (the shape of the wire message).
    pub fn from_parts(kind: ScopeKind, org: Option<OrgId>) -> Result<Self, ScopeError> {
        match (kind, org) {
            (ScopeKind::Account, None) => Ok(AgentScope::Account),
            (ScopeKind::Instance, None) => Ok(AgentScope::Instance),
            (ScopeKind::Org, Some(org)) => Ok(AgentScope::Org(org)),
            _ => Err(ScopeError::IdMismatch),
        }
    }

    /// Canonical text bound into authenticated data: `account`, `instance` or `org:<uuid>`.
    pub fn canonical_text(&self) -> String {
        match self {
            AgentScope::Account => "account".to_owned(),
            AgentScope::Instance => "instance".to_owned(),
            AgentScope::Org(org) => format!("org:{org}"),
        }
    }
}

impl fmt::Display for AgentScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_text())
    }
}

/// The two public keys a pool is pinned by.
///
/// Hosts of a pool hold the matching private keys. The encryption key receives sealed agent
/// definitions; the signing key attests runner setup documents. Both are pinned together, by
/// one fingerprint, the first time an owner or device meets the pool (trust on first use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolKeys {
    /// X25519 public key definitions are sealed to.
    pub encryption: [u8; 32],
    /// Ed25519 public key that signs host attestations.
    pub signing: [u8; 32],
}

impl PoolKeys {
    /// Full SHA-256 fingerprint as uppercase hexadecimal groups of four separated by dashes,
    /// for people to compare out of band.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"nocterm/agents-pool-keys/v1");
        hasher.update(self.encryption);
        hasher.update(self.signing);
        hex::encode_upper(hasher.finalize())
            .as_bytes()
            .chunks(4)
            .map(|group| String::from_utf8_lossy(group))
            .collect::<Vec<_>>()
            .join("-")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_round_trips_through_its_parts() {
        let org = OrgId::new();
        for scope in [
            AgentScope::Account,
            AgentScope::Instance,
            AgentScope::Org(org),
        ] {
            assert_eq!(AgentScope::from_parts(scope.kind(), scope.org()), Ok(scope));
        }
        assert_eq!(
            AgentScope::from_parts(ScopeKind::Org, None),
            Err(ScopeError::IdMismatch)
        );
        assert_eq!(
            AgentScope::from_parts(ScopeKind::Account, Some(org)),
            Err(ScopeError::IdMismatch)
        );
    }

    #[test]
    fn canonical_text_separates_scopes() {
        let org = OrgId::new();
        assert_eq!(AgentScope::Account.canonical_text(), "account");
        assert_eq!(AgentScope::Org(org).canonical_text(), format!("org:{org}"));
        assert_ne!(
            AgentScope::Org(org).canonical_text(),
            AgentScope::Org(OrgId::new()).canonical_text()
        );
    }

    #[test]
    fn pool_fingerprint_covers_both_keys() {
        let base = PoolKeys {
            encryption: [1; 32],
            signing: [2; 32],
        };
        let swapped = PoolKeys {
            encryption: [1; 32],
            signing: [3; 32],
        };
        assert_ne!(base.fingerprint(), swapped.fingerprint());
        assert_eq!(base.fingerprint().split('-').count(), 16);
    }
}
