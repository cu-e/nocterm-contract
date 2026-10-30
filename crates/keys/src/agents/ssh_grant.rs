//! The grant a device signs to let a runner's ephemeral key use the user's SSH CA.
//!
//! The grant is the contract between the device that holds the CA and the code that turns it
//! into an OpenSSH certificate. It fixes the restrictions the design requires: principal of
//! the agent only, at most 24 hours, bound source addresses, and never port, agent or X11
//! forwarding. Layout `v1` (see [`SshCaGrant::canonical_bytes`]).
use nocterm_hub_model::InstanceId;
use nocterm_hub_model::pop::{self, SignatureError};

use super::canon::{Reader, Writer};
use crate::DeviceKey;

const DOMAIN: &[u8] = b"nocterm/agents-ssh-ca-grant/v1";
/// Longest life of a certificate: 24 hours.
pub const MAX_GRANT_LIFETIME_MS: i64 = 24 * 60 * 60 * 1000;
/// Required prefix of the principal.
pub const PRINCIPAL_PREFIX: &str = "nocterm-agent-";
/// Longest principal.
pub const MAX_PRINCIPAL_BYTES: usize = 64;
/// Most source addresses in one grant.
pub const MAX_SOURCE_ADDRESSES: usize = 8;
/// Longest source address or CIDR.
pub const MAX_SOURCE_ADDRESS_BYTES: usize = 64;

/// A grant that cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// Not the canonical layout.
    #[error("malformed SSH CA grant")]
    Malformed,
    /// The principal does not name an agent.
    #[error("the principal does not name an agent")]
    Principal,
    /// The validity window is empty or longer than 24 hours.
    #[error("the validity window is empty or longer than 24 hours")]
    Lifetime,
    /// Source addresses are missing, too many or not plain addresses.
    #[error("the source addresses are missing or invalid")]
    SourceAddress,
    /// The grant is not yet valid or already expired.
    #[error("the grant is outside its validity window")]
    Window,
    /// It names another CA than the one the verifier trusts.
    #[error("the grant names another CA")]
    Authority,
    /// The signature does not verify.
    #[error("the grant signature is invalid")]
    Signature(#[from] SignatureError),
}

/// What the CA is asked to certify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCaGrant {
    /// The instance whose runner holds the subject key.
    pub instance: InstanceId,
    /// Principal inside the certificate: `nocterm-agent-<id>`.
    pub principal: String,
    /// The CA's Ed25519 public key.
    pub ca_key: [u8; 32],
    /// The runner's ephemeral Ed25519 public key.
    pub subject_key: [u8; 32],
    /// Certificate serial, unique per CA.
    pub serial: u64,
    /// Start of validity, Unix milliseconds.
    pub valid_after_ms: i64,
    /// End of validity, Unix milliseconds.
    pub valid_before_ms: i64,
    /// Addresses or CIDRs the key may connect from (`source-address`).
    pub source_addresses: Vec<String>,
}

impl SshCaGrant {
    /// Checks the rules that make a grant safe to sign or to honour.
    pub fn validate(&self) -> Result<(), GrantError> {
        let principal = self.principal.strip_prefix(PRINCIPAL_PREFIX);
        let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_');
        if self.principal.len() > MAX_PRINCIPAL_BYTES
            || !principal.is_some_and(|rest| !rest.is_empty() && rest.chars().all(plain))
        {
            return Err(GrantError::Principal);
        }
        let life = self.valid_before_ms.saturating_sub(self.valid_after_ms);
        if life <= 0 || life > MAX_GRANT_LIFETIME_MS {
            return Err(GrantError::Lifetime);
        }
        let address = |a: &String| {
            !a.is_empty()
                && a.len() <= MAX_SOURCE_ADDRESS_BYTES
                && a.chars()
                    .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
        };
        if self.source_addresses.is_empty()
            || self.source_addresses.len() > MAX_SOURCE_ADDRESSES
            || !self.source_addresses.iter().all(address)
        {
            return Err(GrantError::SourceAddress);
        }
        Ok(())
    }

    /// The signed bytes: `lp(domain) lp(instance 16) lp(principal) lp(ca 32) lp(subject 32)
    /// lp(serial u64) lp(after i64) lp(before i64) lp(count u64) lp(address)*`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut layout = Writer::new(DOMAIN);
        layout
            .field(self.instance.as_uuid().as_bytes())
            .field(self.principal.as_bytes())
            .field(&self.ca_key)
            .field(&self.subject_key)
            .u64(self.serial)
            .i64(self.valid_after_ms)
            .i64(self.valid_before_ms)
            .list(&self.source_addresses);
        layout.finish()
    }

    /// Decodes and validates canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GrantError> {
        let parse = || {
            let mut r = Reader::new(bytes, DOMAIN)?;
            let grant = Self {
                instance: InstanceId::from_uuid(uuid_from(r.array::<16>()?)),
                principal: r.string()?,
                ca_key: r.array()?,
                subject_key: r.array()?,
                serial: r.u64()?,
                valid_after_ms: r.i64()?,
                valid_before_ms: r.i64()?,
                source_addresses: r.list(MAX_SOURCE_ADDRESSES)?,
            };
            r.end()?;
            Some(grant)
        };
        let grant = parse().ok_or(GrantError::Malformed)?;
        grant.validate()?;
        Ok(grant)
    }

    /// Signs the grant with the CA key; the key must be the one the grant names.
    pub fn sign(self, ca: &DeviceKey) -> Result<SignedSshCaGrant, GrantError> {
        self.validate()?;
        if ca.public_key() != self.ca_key {
            return Err(GrantError::Authority);
        }
        let signature = ca.sign(&self.canonical_bytes());
        Ok(SignedSshCaGrant {
            grant: self,
            signature,
        })
    }
}

fn uuid_from(bytes: [u8; 16]) -> uuid::Uuid {
    uuid::Uuid::from_bytes(bytes)
}

/// A grant with its CA signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSshCaGrant {
    /// The signed statement.
    pub grant: SshCaGrant,
    /// Ed25519 signature over [`SshCaGrant::canonical_bytes`].
    pub signature: [u8; 64],
}

impl SignedSshCaGrant {
    /// Verifies the grant for the CA the verifier trusts at `now_ms`.
    pub fn verify(&self, trusted_ca: &[u8; 32], now_ms: i64) -> Result<(), GrantError> {
        self.grant.validate()?;
        if &self.grant.ca_key != trusted_ca {
            return Err(GrantError::Authority);
        }
        pop::verify(trusted_ca, &self.grant.canonical_bytes(), &self.signature)?;
        if now_ms < self.grant.valid_after_ms || now_ms >= self.grant.valid_before_ms {
            return Err(GrantError::Window);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca() -> DeviceKey {
        DeviceKey::from_seed(&[8; 32])
    }

    fn grant() -> SshCaGrant {
        SshCaGrant {
            instance: InstanceId::from_uuid(uuid_from([3; 16])),
            principal: "nocterm-agent-abc".into(),
            ca_key: ca().public_key(),
            subject_key: [6; 32],
            serial: 7,
            valid_after_ms: 1_000,
            valid_before_ms: 1_000 + MAX_GRANT_LIFETIME_MS,
            source_addresses: vec!["203.0.113.7/32".into(), "2001:db8::1".into()],
        }
    }

    #[test]
    fn a_signed_grant_verifies_for_its_ca_inside_its_window() {
        let signed = grant().sign(&ca()).unwrap();
        signed.verify(&ca().public_key(), 5_000).unwrap();
        assert_eq!(
            signed.verify(&ca().public_key(), 999),
            Err(GrantError::Window)
        );
        assert_eq!(
            signed.verify(&ca().public_key(), 1_000 + MAX_GRANT_LIFETIME_MS),
            Err(GrantError::Window)
        );
        assert_eq!(signed.verify(&[1; 32], 5_000), Err(GrantError::Authority));
    }

    #[test]
    fn a_tampered_grant_fails_the_signature() {
        let mut signed = grant().sign(&ca()).unwrap();
        signed.grant.serial += 1;
        assert!(matches!(
            signed.verify(&ca().public_key(), 5_000),
            Err(GrantError::Signature(_))
        ));
    }

    #[test]
    fn the_rules_refuse_unsafe_grants() {
        let mut g = grant();
        g.valid_before_ms += 1;
        assert_eq!(g.validate(), Err(GrantError::Lifetime));
        let mut g = grant();
        g.valid_before_ms = g.valid_after_ms;
        assert_eq!(g.validate(), Err(GrantError::Lifetime));
        let mut g = grant();
        g.principal = "root".into();
        assert_eq!(g.validate(), Err(GrantError::Principal));
        let mut g = grant();
        g.principal = "nocterm-agent-a\"b".into();
        assert_eq!(g.validate(), Err(GrantError::Principal));
        let mut g = grant();
        g.source_addresses.clear();
        assert_eq!(g.validate(), Err(GrantError::SourceAddress));
        let mut g = grant();
        g.source_addresses = vec!["a b".into()];
        assert_eq!(g.validate(), Err(GrantError::SourceAddress));
        assert_eq!(
            grant().sign(&DeviceKey::from_seed(&[9; 32])).unwrap_err(),
            GrantError::Authority
        );
    }

    #[test]
    fn canonical_bytes_round_trip_and_match_the_independent_vector() {
        let bytes = grant().canonical_bytes();
        assert_eq!(SshCaGrant::from_canonical_bytes(&bytes).unwrap(), grant());
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            SshCaGrant::from_canonical_bytes(&longer),
            Err(GrantError::Malformed)
        );
        let ca_hex = include_str!("../../../../fixtures/agents-v1/ca-public.hex").trim();
        assert_eq!(hex::encode(ca().public_key()), ca_hex);
        let expected = include_str!("../../../../fixtures/agents-v1/ssh-ca-grant.hex").trim();
        assert_eq!(hex::encode(bytes), expected);
    }
}
