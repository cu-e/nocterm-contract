//! Cross-language fixtures catch a mutually consistent encoder/decoder mistake.
use ed25519_dalek::{Signer, SigningKey};
use nocterm_hub_model::cloud::{
    capabilities::{CapabilitiesClaim, SignedCapabilities},
    relay::RelayBinding,
    runner_auth::{RunnerProofClaim, RunnerProofKind},
    runner_request::{RunnerMethod, RunnerRequestClaim},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex.trim())
}

#[test]
fn python_capability_binding_and_runner_proofs_match_exact_canonical_bytes() -> TestResult {
    let caps = bytes(include_str!(
        "../../../fixtures/cloud-relay-v1/capabilities.hex"
    ))?;
    let signature = bytes(include_str!(
        "../../../fixtures/cloud-relay-v1/capabilities-signature.hex"
    ))?
    .try_into()
    .map_err(|_| "signature")?;
    let claim = CapabilitiesClaim::from_canonical_bytes(&caps)?;
    assert_eq!(claim.canonical_bytes()?, caps);
    let signed = SignedCapabilities::new(claim, signature)?;
    signed.require_expected("hub-test", &signed.claim().authority(), &[3; 16], 110_000)?;
    let binding = bytes(include_str!(
        "../../../fixtures/cloud-relay-v1/binding-command.hex"
    ))?;
    let decoded = RelayBinding::from_canonical_bytes(&binding)?;
    assert_eq!(decoded.canonical_bytes()?, binding);
    assert_eq!(decoded.runner().id, [2; 16]);
    for (encoded, signature, kind) in [
        (
            include_str!("../../../fixtures/cloud-relay-v1/redeem.hex"),
            include_str!("../../../fixtures/cloud-relay-v1/redeem-signature.hex"),
            RunnerProofKind::Redeem,
        ),
        (
            include_str!("../../../fixtures/cloud-relay-v1/refresh.hex"),
            include_str!("../../../fixtures/cloud-relay-v1/refresh-signature.hex"),
            RunnerProofKind::Refresh,
        ),
    ] {
        let encoded = bytes(encoded)?;
        let claim = RunnerProofClaim::from_canonical_bytes(&encoded)?;
        assert_eq!(claim.canonical_bytes()?.as_slice(), encoded);
        let signature = bytes(signature)?.try_into().map_err(|_| "signature")?;
        claim.verify(kind, claim.subject(), &signature, 110_000)?;
    }
    let encoded = bytes(include_str!("../../../fixtures/cloud-relay-v1/request.hex"))?;
    let signature = bytes(include_str!(
        "../../../fixtures/cloud-relay-v1/request-signature.hex"
    ))?
    .try_into()
    .map_err(|_| "signature")?;
    let request = RunnerRequestClaim::from_canonical_bytes(&encoded)?;
    assert_eq!(request.canonical_bytes()?, encoded);
    request.verify(
        request.subject(),
        RunnerMethod::Publish,
        &request.access_digest(),
        &signature,
        110_000,
    )?;
    Ok(())
}

#[test]
fn runner_request_proofs_bind_every_field_and_cannot_authorize_account_services() -> TestResult {
    let encoded = bytes(include_str!("../../../fixtures/cloud-relay-v1/request.hex"))?;
    let signature: [u8; 64] = bytes(include_str!(
        "../../../fixtures/cloud-relay-v1/request-signature.hex"
    ))?
    .try_into()
    .map_err(|_| "signature")?;
    let request = RunnerRequestClaim::from_canonical_bytes(&encoded)?;
    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        if let Ok(changed) = RunnerRequestClaim::from_canonical_bytes(&changed) {
            assert!(
                changed
                    .verify(
                        request.subject(),
                        RunnerMethod::Publish,
                        &request.access_digest(),
                        &signature,
                        110_000
                    )
                    .is_err(),
                "byte {index}"
            );
        }
    }
    for length in 0..encoded.len() {
        assert!(RunnerRequestClaim::from_canonical_bytes(&encoded[..length]).is_err());
    }
    let mut suffix = encoded;
    suffix.push(0);
    assert!(RunnerRequestClaim::from_canonical_bytes(&suffix).is_err());
    for (service, method) in [
        ("nocterm.hub.v1.StoreService", "Put"),
        ("nocterm.hub.v1.CloudService", "RevokeRunner"),
        ("nocterm.hub.v1.CloudService", "CreateRunnerGrant"),
        ("nocterm.hub.v1.SessionService", "List"),
    ] {
        assert!(RunnerMethod::from_rpc(service, method).is_err());
    }
    for method in [
        RunnerMethod::Publish,
        RunnerMethod::Replay,
        RunnerMethod::Acknowledge,
        RunnerMethod::Watch,
        RunnerMethod::ListStreams,
        RunnerMethod::Heartbeat,
        RunnerMethod::Purge,
    ] {
        let claim = RunnerRequestClaim::new(
            request.subject().clone(),
            method,
            request.access_digest(),
            [3; 16],
            100_000,
        );
        let signature = SigningKey::from_bytes(&[0x72; 32])
            .sign(&claim.canonical_bytes()?)
            .to_bytes();
        claim.verify(
            request.subject(),
            method,
            &request.access_digest(),
            &signature,
            110_000,
        )?;
        assert_eq!(
            RunnerMethod::from_rpc("nocterm.hub.v1.CloudService", method.name())?,
            method
        );
        assert!(
            claim
                .verify(request.subject(), method, &[0; 32], &signature, 110_000)
                .is_err()
        );
        assert!(
            claim
                .verify(
                    request.subject(),
                    method,
                    &request.access_digest(),
                    &signature,
                    160_001
                )
                .is_err()
        );
    }
    Ok(())
}
