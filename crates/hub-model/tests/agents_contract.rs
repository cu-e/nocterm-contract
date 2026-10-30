use ed25519_dalek::SigningKey;
use nocterm_hub_model::agents::{HostRunnerAttestation, SignedHostRunnerAttestation};
use nocterm_hub_model::cloud::capabilities::{
    CLOUD_FEATURE_RECEIPT_RECLAIM, CLOUD_FEATURE_SESSION_START, CLOUD_REQUIRED_FEATURES,
    CapabilitiesClaim, CapabilityLimits, CapabilityWindow, SignedCapabilities,
};
use nocterm_hub_model::cloud::reclaim::{
    ChatDeletionTombstone, MAX_RETRY_HORIZON_MS, RECLAIM_GRACE_MS, ReclaimError, RetiredStream,
    RevokedRunner, receipt_reclaimable, validate_retry_until,
};
use nocterm_hub_model::cloud::{CloudNamespace, CloudTextId, RunnerCoordinate};
use nocterm_hub_model::{HostId, InstanceId, PoolId};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(text: &str) -> Vec<u8> {
    hex::decode(text.trim()).unwrap_or_default()
}

#[test]
fn host_attestation_bytes_match_the_independent_vector() -> TestResult {
    let attestation = HostRunnerAttestation {
        pool: PoolId::from_uuid(Uuid::from_bytes([1; 16])),
        host: HostId::from_uuid(Uuid::from_bytes([2; 16])),
        instance: InstanceId::from_uuid(Uuid::from_bytes([3; 16])),
        runner_setup_digest: [4; 32],
        issued_at_ms: 1_700_000_000_123,
    };
    let expected = fixture(include_str!("../../../fixtures/agents-v1/attestation.hex"));
    assert_eq!(attestation.canonical_bytes(), expected);
    assert_eq!(
        HostRunnerAttestation::from_canonical_bytes(&expected)?,
        attestation
    );

    let key = SigningKey::from_bytes(&[9; 32]);
    let signed = attestation.sign(&key);
    let wire = SignedHostRunnerAttestation::from_wire(&expected, &signed.signature)?;
    wire.verify(
        &key.verifying_key().to_bytes(),
        attestation.pool,
        attestation.instance,
    )?;
    assert!(wire.covers_setup(&[4; 32]));
    assert!(!wire.covers_setup(&[5; 32]));
    Ok(())
}

#[test]
fn tombstone_hashes_match_the_independent_vectors() {
    let stream = RetiredStream {
        account_id: "account-1",
        runner_id: [5; 16],
        runner_key_epoch: 7,
        chat_id: [6; 16],
    };
    assert_eq!(
        stream.tombstone_hash().to_vec(),
        fixture(include_str!(
            "../../../fixtures/agents-v1/retired-stream.hex"
        ))
    );
    let runner = RevokedRunner {
        account_id: "account-1",
        runner_id: [5; 16],
    };
    assert_eq!(
        runner.tombstone_hash().to_vec(),
        fixture(include_str!(
            "../../../fixtures/agents-v1/revoked-runner.hex"
        ))
    );
    assert_ne!(stream.tombstone_hash(), runner.tombstone_hash());
}

#[test]
fn a_retired_id_changes_with_every_coordinate() {
    let base = RetiredStream {
        account_id: "a",
        runner_id: [1; 16],
        runner_key_epoch: 1,
        chat_id: [2; 16],
    };
    let hash = base.tombstone_hash();
    for other in [
        RetiredStream {
            account_id: "b",
            ..base
        },
        RetiredStream {
            runner_id: [9; 16],
            ..base
        },
        RetiredStream {
            runner_key_epoch: 2,
            ..base
        },
        RetiredStream {
            chat_id: [9; 16],
            ..base
        },
    ] {
        assert_ne!(other.tombstone_hash(), hash);
    }
}

fn tombstone() -> Result<ChatDeletionTombstone, Box<dyn std::error::Error>> {
    Ok(ChatDeletionTombstone {
        namespace: CloudNamespace {
            hub_instance_id: CloudTextId::new("namespace")?,
            account_id: CloudTextId::new("account-1")?,
        },
        runner: RunnerCoordinate {
            id: [5; 16],
            key_epoch: 7,
        },
        chat_id: [6; 16],
        requested_by: CloudTextId::new("device-1")?,
        deleted_at_ms: 1_700_000_000_000,
    })
}

#[test]
fn chat_deletion_tombstone_round_trips_and_is_signed_by_the_runner() -> TestResult {
    let tombstone = tombstone()?;
    let key = SigningKey::from_bytes(&[3; 32]);
    let public = key.verifying_key().to_bytes();
    let bytes = tombstone.canonical_bytes()?;
    assert_eq!(
        ChatDeletionTombstone::from_canonical_bytes(&bytes)?,
        tombstone
    );
    let signature = tombstone.sign(&key)?;
    tombstone.verify(&public, &signature)?;

    let mut forged = tombstone.clone();
    forged.chat_id = [7; 16];
    assert!(matches!(
        forged.verify(&public, &signature),
        Err(ReclaimError::Signature(_))
    ));
    assert_eq!(
        tombstone.retired_stream_hash(),
        RetiredStream {
            account_id: "account-1",
            runner_id: [5; 16],
            runner_key_epoch: 7,
            chat_id: [6; 16],
        }
        .tombstone_hash()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ChatDeletionTombstone::from_canonical_bytes(&trailing).is_err());
    Ok(())
}

#[test]
fn retry_horizon_is_bounded_and_zero_means_never_reclaimed() {
    let now = 1_000_000;
    assert_eq!(validate_retry_until(now, 0), Ok(()));
    assert_eq!(validate_retry_until(now, now + 1), Ok(()));
    assert_eq!(
        validate_retry_until(now, now + MAX_RETRY_HORIZON_MS),
        Ok(())
    );
    assert_eq!(validate_retry_until(now, now), Err(ReclaimError::Horizon));
    assert_eq!(
        validate_retry_until(now, now + MAX_RETRY_HORIZON_MS + 1),
        Err(ReclaimError::Horizon)
    );
    assert!(!receipt_reclaimable(0, i64::MAX));
    assert!(!receipt_reclaimable(now, now + RECLAIM_GRACE_MS - 1));
    assert!(receipt_reclaimable(now, now + RECLAIM_GRACE_MS));
    assert!(!receipt_reclaimable(i64::MAX, i64::MAX));
}

fn claim(features: u64) -> Result<CapabilitiesClaim, Box<dyn std::error::Error>> {
    Ok(CapabilitiesClaim::new(
        CloudTextId::new("hub")?,
        SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
        CapabilityLimits {
            features,
            ..CapabilityLimits::v1()
        },
        [7; 16],
        CapabilityWindow {
            issued_at_ms: 1000,
            expires_at_ms: 2000,
        },
    )?)
}

#[test]
fn reclaim_is_an_optional_bit_and_old_claims_still_verify() -> TestResult {
    assert_eq!(CLOUD_FEATURE_RECEIPT_RECLAIM & CLOUD_REQUIRED_FEATURES, 0);
    assert_eq!(
        CLOUD_FEATURE_RECEIPT_RECLAIM & CLOUD_FEATURE_SESSION_START,
        0
    );
    let key = SigningKey::from_bytes(&[1; 32]);
    for features in [
        CLOUD_REQUIRED_FEATURES,
        CLOUD_REQUIRED_FEATURES | CLOUD_FEATURE_RECEIPT_RECLAIM,
    ] {
        let claim = claim(features)?;
        let signature = ed25519_dalek::Signer::sign(&key, &claim.canonical_bytes()?).to_bytes();
        let signed = SignedCapabilities::new(claim.clone(), signature)?;
        assert_eq!(signed.claim().limits().features, features);
        assert_eq!(
            CapabilitiesClaim::from_canonical_bytes(&claim.canonical_bytes()?)?
                .limits()
                .features,
            features
        );
    }
    Ok(())
}
