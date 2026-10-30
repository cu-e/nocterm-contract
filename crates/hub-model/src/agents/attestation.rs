//! The statement a pool host signs about a freshly initialised runner.
//!
//! The device that starts an instance verifies the signature against the pool's pinned signing
//! key before it imports the runner setup document, so a hub cannot substitute a host or a
//! runner of its own. Layout `v1`, every field length-prefixed with a big-endian `u32`:
//!
//! ```text
//! lp("nocterm/agents-host-runner-attestation/v1")
//! lp(pool uuid, 16 bytes) lp(host uuid, 16) lp(instance uuid, 16)
//! lp(runner_setup_digest, 32)  lp(issued_at_ms, 8 bytes big-endian i64)
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::pop::{self, SignatureError};
use crate::{HostId, InstanceId, PoolId};

const DOMAIN: &[u8] = b"nocterm/agents-host-runner-attestation/v1";
const MAX_BYTES: usize = 256;

/// An attestation that cannot be decoded or verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    /// Not the canonical layout, wrong domain, or trailing bytes.
    #[error("malformed host runner attestation")]
    Malformed,
    /// The attestation names another pool, host or instance than the caller expects.
    #[error("the attestation names another pool, host or instance")]
    Identity,
    /// The signature does not verify under the pinned pool key.
    #[error("the attestation signature is invalid")]
    Signature(#[from] SignatureError),
}

/// What a host attests: the runner setup document of one instance, by digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRunnerAttestation {
    /// Pool the host belongs to.
    pub pool: PoolId,
    /// Host that initialised the runner.
    pub host: HostId,
    /// The seat the runner belongs to.
    pub instance: InstanceId,
    /// SHA-256 of the exact public runner setup document bytes.
    pub runner_setup_digest: [u8; 32],
    /// Issue time in Unix milliseconds.
    pub issued_at_ms: i64,
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take<'a>(rest: &mut &'a [u8], expected: usize) -> Result<&'a [u8], AttestationError> {
    let (len, tail) = rest
        .split_first_chunk::<4>()
        .ok_or(AttestationError::Malformed)?;
    if usize::try_from(u32::from_be_bytes(*len)) != Ok(expected) {
        return Err(AttestationError::Malformed);
    }
    let (value, tail) = tail
        .split_at_checked(expected)
        .ok_or(AttestationError::Malformed)?;
    *rest = tail;
    Ok(value)
}

impl HostRunnerAttestation {
    /// The exact bytes that are signed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        put(&mut out, DOMAIN);
        put(&mut out, self.pool.as_uuid().as_bytes());
        put(&mut out, self.host.as_uuid().as_bytes());
        put(&mut out, self.instance.as_uuid().as_bytes());
        put(&mut out, &self.runner_setup_digest);
        put(&mut out, &self.issued_at_ms.to_be_bytes());
        out
    }

    /// Strict decoder: the domain, every length and the end of input must match.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AttestationError> {
        if bytes.len() > MAX_BYTES {
            return Err(AttestationError::Malformed);
        }
        let mut rest = bytes;
        if take(&mut rest, DOMAIN.len())? != DOMAIN {
            return Err(AttestationError::Malformed);
        }
        let uuid =
            |value: &[u8]| uuid::Uuid::from_slice(value).map_err(|_| AttestationError::Malformed);
        let pool = PoolId::from_uuid(uuid(take(&mut rest, 16)?)?);
        let host = HostId::from_uuid(uuid(take(&mut rest, 16)?)?);
        let instance = InstanceId::from_uuid(uuid(take(&mut rest, 16)?)?);
        let runner_setup_digest = take(&mut rest, 32)?
            .try_into()
            .map_err(|_| AttestationError::Malformed)?;
        let issued_at_ms = i64::from_be_bytes(
            take(&mut rest, 8)?
                .try_into()
                .map_err(|_| AttestationError::Malformed)?,
        );
        if !rest.is_empty() {
            return Err(AttestationError::Malformed);
        }
        Ok(Self {
            pool,
            host,
            instance,
            runner_setup_digest,
            issued_at_ms,
        })
    }

    /// Signs the attestation with a pool signing key.
    pub fn sign(&self, key: &SigningKey) -> SignedHostRunnerAttestation {
        let signature: Signature = key.sign(&self.canonical_bytes());
        SignedHostRunnerAttestation {
            attestation: *self,
            signature: signature.to_bytes(),
        }
    }
}

/// An attestation with its signature. Construction does not verify; call
/// [`SignedHostRunnerAttestation::verify`] with the pinned pool signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedHostRunnerAttestation {
    /// The signed statement.
    pub attestation: HostRunnerAttestation,
    /// Ed25519 signature over [`HostRunnerAttestation::canonical_bytes`].
    pub signature: [u8; 64],
}

impl SignedHostRunnerAttestation {
    /// Decodes the wire form (canonical bytes and signature) without verifying.
    pub fn from_wire(attestation: &[u8], signature: &[u8]) -> Result<Self, AttestationError> {
        Ok(Self {
            attestation: HostRunnerAttestation::from_canonical_bytes(attestation)?,
            signature: signature
                .try_into()
                .map_err(|_| SignatureError::MalformedSignature)?,
        })
    }

    /// Verifies the signature under the pinned pool signing key and that the statement is
    /// about the expected pool and instance.
    pub fn verify(
        &self,
        pool_signing_key: &[u8; 32],
        pool: PoolId,
        instance: InstanceId,
    ) -> Result<(), AttestationError> {
        pop::verify(
            pool_signing_key,
            &self.attestation.canonical_bytes(),
            &self.signature,
        )?;
        if self.attestation.pool != pool || self.attestation.instance != instance {
            return Err(AttestationError::Identity);
        }
        Ok(())
    }

    /// Whether `digest` is the digest of the setup document the host attested.
    pub fn covers_setup(&self, digest: &[u8; 32]) -> bool {
        &self.attestation.runner_setup_digest == digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample() -> HostRunnerAttestation {
        HostRunnerAttestation {
            pool: PoolId::from_uuid(Uuid::from_bytes([1; 16])),
            host: HostId::from_uuid(Uuid::from_bytes([2; 16])),
            instance: InstanceId::from_uuid(Uuid::from_bytes([3; 16])),
            runner_setup_digest: [4; 32],
            issued_at_ms: 1_700_000_000_123,
        }
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let bytes = sample().canonical_bytes();
        assert_eq!(
            HostRunnerAttestation::from_canonical_bytes(&bytes),
            Ok(sample())
        );
    }

    #[test]
    fn trailing_and_truncated_bytes_are_refused() {
        let mut bytes = sample().canonical_bytes();
        let short = &bytes[..bytes.len() - 1];
        assert_eq!(
            HostRunnerAttestation::from_canonical_bytes(short),
            Err(AttestationError::Malformed)
        );
        bytes.push(0);
        assert_eq!(
            HostRunnerAttestation::from_canonical_bytes(&bytes),
            Err(AttestationError::Malformed)
        );
    }

    #[test]
    fn a_valid_signature_verifies_only_for_its_pool_and_instance() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signed = sample().sign(&key);
        let public = key.verifying_key().to_bytes();
        let a = sample();
        assert_eq!(signed.verify(&public, a.pool, a.instance), Ok(()));
        assert_eq!(
            signed.verify(&public, PoolId::new(), a.instance),
            Err(AttestationError::Identity)
        );
        let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert!(matches!(
            signed.verify(&other, a.pool, a.instance),
            Err(AttestationError::Signature(_))
        ));
    }

    #[test]
    fn a_tampered_digest_breaks_the_signature() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut signed = sample().sign(&key);
        signed.attestation.runner_setup_digest[0] ^= 1;
        let a = sample();
        assert!(
            signed
                .verify(&key.verifying_key().to_bytes(), a.pool, a.instance)
                .is_err()
        );
    }
}
