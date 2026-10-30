use nocterm_hub_model::agents::{AttestationError, PoolKeys, SignedHostRunnerAttestation};
use nocterm_hub_model::{InstanceId, PoolId};
use nocterm_hub_proto::v1;
use sha2::{Digest, Sha256};

/// A runner setup document the pool's pinned key vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSetup {
    /// The exact bytes of the public runner setup document to import.
    pub setup_document: Vec<u8>,
    /// The verified statement, including the host that produced it.
    pub attestation: SignedHostRunnerAttestation,
}

/// Why an instance's setup document cannot be trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SetupError {
    /// The instance carries no setup document or attestation yet.
    #[error("the instance has no setup document to verify")]
    Missing,
    /// An identifier on the instance is not valid.
    #[error("the instance carries an invalid identifier")]
    Identity,
    /// The attestation does not verify under the pinned pool keys, or names another instance.
    #[error(transparent)]
    Attestation(#[from] AttestationError),
    /// The document differs from the one the host attested.
    #[error("the setup document is not the one the host attested")]
    DocumentMismatch,
}

/// Verifies, against the pool keys the device has pinned, that a host of the pool produced the
/// setup document of `instance`. Nothing may be imported or registered if this fails, so a hub
/// cannot substitute a host or a runner of its own.
pub fn verify_instance_setup(
    instance: &v1::Instance,
    pinned: &PoolKeys,
) -> Result<VerifiedSetup, SetupError> {
    if instance.setup_document.is_empty() || instance.attestation.is_empty() {
        return Err(SetupError::Missing);
    }
    let pool: PoolId = instance.pool_id.parse().map_err(|_| SetupError::Identity)?;
    let id: InstanceId = instance
        .instance_id
        .parse()
        .map_err(|_| SetupError::Identity)?;
    let attestation = SignedHostRunnerAttestation::from_wire(
        &instance.attestation,
        &instance.attestation_signature,
    )?;
    attestation.verify(&pinned.signing, pool, id)?;
    let digest: [u8; 32] = Sha256::digest(&instance.setup_document).into();
    if !attestation.covers_setup(&digest) {
        return Err(SetupError::DocumentMismatch);
    }
    Ok(VerifiedSetup {
        setup_document: instance.setup_document.clone(),
        attestation,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use nocterm_hub_model::HostId;
    use nocterm_hub_model::agents::HostRunnerAttestation;

    use super::*;

    struct Fixture {
        keys: PoolKeys,
        instance: v1::Instance,
    }

    fn fixture() -> Fixture {
        let signing = SigningKey::from_bytes(&[5; 32]);
        let keys = PoolKeys {
            encryption: [1; 32],
            signing: signing.verifying_key().to_bytes(),
        };
        let (pool, id) = (PoolId::new(), InstanceId::new());
        let document = b"runner setup".to_vec();
        let signed = HostRunnerAttestation {
            pool,
            host: HostId::new(),
            instance: id,
            runner_setup_digest: Sha256::digest(&document).into(),
            issued_at_ms: 10,
        }
        .sign(&signing);
        let instance = v1::Instance {
            instance_id: id.to_string(),
            pool_id: pool.to_string(),
            setup_document: document,
            attestation: signed.attestation.canonical_bytes(),
            attestation_signature: signed.signature.to_vec(),
            ..v1::Instance::default()
        };
        Fixture { keys, instance }
    }

    #[test]
    fn a_setup_attested_by_the_pinned_pool_verifies() {
        let f = fixture();
        let verified = verify_instance_setup(&f.instance, &f.keys).unwrap();
        assert_eq!(verified.setup_document, b"runner setup");
    }

    #[test]
    fn a_setup_without_attestation_is_missing() {
        let mut f = fixture();
        f.instance.attestation.clear();
        assert_eq!(
            verify_instance_setup(&f.instance, &f.keys),
            Err(SetupError::Missing)
        );
    }

    #[test]
    fn a_host_of_another_pool_key_is_refused() {
        let f = fixture();
        let other = PoolKeys {
            signing: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
            ..f.keys
        };
        assert!(matches!(
            verify_instance_setup(&f.instance, &other),
            Err(SetupError::Attestation(AttestationError::Signature(_)))
        ));
    }

    #[test]
    fn a_swapped_document_does_not_match_the_attested_digest() {
        let mut f = fixture();
        f.instance.setup_document = b"attacker setup".to_vec();
        assert_eq!(
            verify_instance_setup(&f.instance, &f.keys),
            Err(SetupError::DocumentMismatch)
        );
    }

    #[test]
    fn an_attestation_for_another_instance_is_refused() {
        let mut f = fixture();
        f.instance.instance_id = InstanceId::new().to_string();
        assert!(matches!(
            verify_instance_setup(&f.instance, &f.keys),
            Err(SetupError::Attestation(AttestationError::Identity))
        ));
    }
}
