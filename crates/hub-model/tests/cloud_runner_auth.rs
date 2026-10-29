use ed25519_dalek::{Signer, SigningKey};
use nocterm_hub_model::cloud::{
    CloudNamespace, CloudTextId,
    runner_auth::{RunnerProofClaim, RunnerProofKind, RunnerProofSubject},
};
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn subject(key: &SigningKey) -> Result<RunnerProofSubject, Box<dyn std::error::Error>> {
    Ok(RunnerProofSubject {
        raw_hub_id: CloudTextId::new("hub-1")?,
        namespace: CloudNamespace {
            hub_instance_id: CloudTextId::new("namespace")?,
            account_id: CloudTextId::new("account")?,
        },
        runner_id: [2; 16],
        proof_key: key.verifying_key().to_bytes(),
    })
}

#[test]
fn runner_ticket_and_refresh_proofs_have_separate_purposes_and_redacted_lifetimes() -> TestResult {
    let key = SigningKey::from_bytes(&[7; 32]);
    for kind in [RunnerProofKind::Redeem, RunnerProofKind::Refresh] {
        let claim = RunnerProofClaim::new(
            subject(&key)?,
            kind,
            Zeroizing::new("private-bearer".into()),
            [3; 16],
            100_000,
        )?;
        let encoded = claim.canonical_bytes()?;
        let signature = key.sign(&encoded).to_bytes();
        claim.verify(kind, &subject(&key)?, &signature, 110_000)?;
        let decoded = RunnerProofClaim::from_canonical_bytes(&encoded)?;
        decoded.verify(kind, &subject(&key)?, &signature, 110_000)?;
        assert_eq!(decoded.token(), "private-bearer");
        assert!(!format!("{decoded:?}").contains("private-bearer"));
        let wrong_kind = if kind == RunnerProofKind::Redeem {
            RunnerProofKind::Refresh
        } else {
            RunnerProofKind::Redeem
        };
        assert!(
            decoded
                .verify(wrong_kind, &subject(&key)?, &signature, 110_000)
                .is_err()
        );
        assert!(
            decoded
                .verify(kind, &subject(&key)?, &[0; 64], 110_000)
                .is_err()
        );
        assert!(
            decoded
                .verify(kind, &subject(&key)?, &signature, 160_001)
                .is_err()
        );
        assert!(
            decoded
                .verify(kind, &subject(&key)?, &signature, 39_999)
                .is_err()
        );
        assert!(
            decoded
                .verify(kind, &subject(&key)?, &signature, i64::MIN)
                .is_err()
        );
        for length in 0..encoded.len() {
            assert!(RunnerProofClaim::from_canonical_bytes(&encoded[..length]).is_err());
        }
        let mut suffix = encoded.to_vec();
        suffix.push(0);
        assert!(RunnerProofClaim::from_canonical_bytes(&suffix).is_err());
    }
    Ok(())
}

#[test]
fn runner_proof_cannot_change_hub_account_runner_or_bound_key() -> TestResult {
    let key = SigningKey::from_bytes(&[7; 32]);
    let original = subject(&key)?;
    let claim = RunnerProofClaim::new(
        original.clone(),
        RunnerProofKind::Redeem,
        Zeroizing::new("ticket".into()),
        [3; 16],
        100_000,
    )?;
    let signature = key.sign(&claim.canonical_bytes()?).to_bytes();
    let mut changed = Vec::new();
    let mut row = original.clone();
    row.raw_hub_id = CloudTextId::new("other")?;
    changed.push(row);
    let mut row = original.clone();
    row.namespace.hub_instance_id = CloudTextId::new("other")?;
    changed.push(row);
    let mut row = original.clone();
    row.namespace.account_id = CloudTextId::new("other")?;
    changed.push(row);
    let mut row = original.clone();
    row.runner_id[0] ^= 1;
    changed.push(row);
    let mut row = original;
    row.proof_key[0] ^= 1;
    changed.push(row);
    for expected in changed {
        assert!(
            claim
                .verify(RunnerProofKind::Redeem, &expected, &signature, 110_000)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn excessive_or_empty_runner_tokens_are_rejected_before_serialization() -> TestResult {
    let key = SigningKey::from_bytes(&[7; 32]);
    for token in [String::new(), "x".repeat(257)] {
        assert!(
            RunnerProofClaim::new(
                subject(&key)?,
                RunnerProofKind::Redeem,
                Zeroizing::new(token),
                [3; 16],
                100_000
            )
            .is_err()
        );
    }
    Ok(())
}
