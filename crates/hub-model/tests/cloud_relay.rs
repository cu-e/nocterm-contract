use ed25519_dalek::{Signer, SigningKey};
use nocterm_hub_model::cloud::{
    CloudNamespace, CloudRoute, CloudTextId, RunnerCoordinate,
    capabilities::{CapabilitiesClaim, CapabilityLimits, CapabilityWindow, SignedCapabilities},
    relay::{MAX_RELAY_FRAME_BYTES, PublicationMetadata, PublicationVerifier, RelayBinding},
};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn binding() -> Result<RelayBinding, Box<dyn std::error::Error>> {
    Ok(RelayBinding::command(CloudRoute {
        namespace: CloudNamespace {
            hub_instance_id: CloudTextId::new("hub")?,
            account_id: CloudTextId::new("account")?,
        },
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat_id: [4; 16],
        command_id: [5; 16],
    })?)
}
fn publication(bytes: &[u8]) -> Result<PublicationMetadata, Box<dyn std::error::Error>> {
    Ok(PublicationMetadata::new(
        [6; 16],
        binding()?,
        u32::try_from(bytes.len())?,
        Sha256::digest(bytes).into(),
    )?)
}

#[test]
fn incremental_chunks_verify_without_a_logical_payload_buffer() -> TestResult {
    let bytes = vec![7; 3 * MAX_RELAY_FRAME_BYTES + 1];
    let metadata = publication(&bytes)?;
    let mut receiver = PublicationVerifier::new(metadata.clone());
    let mut offset = 0u32;
    for chunk in bytes.chunks(MAX_RELAY_FRAME_BYTES) {
        assert_eq!(receiver.chunk(chunk)?, offset);
        offset += u32::try_from(chunk.len())?;
    }
    receiver.finish_marker()?;
    assert_eq!(receiver.end_of_stream()?.metadata(), &metadata);
    Ok(())
}

#[test]
fn incomplete_or_wrong_ciphertext_never_yields_a_verified_publication() -> TestResult {
    let mut early = PublicationVerifier::new(publication(b"hello")?);
    early.chunk(b"hell")?;
    assert!(early.finish_marker().is_err());
    assert!(early.chunk(b"o").is_err());
    assert!(early.end_of_stream().is_err());
    let mut wrong = PublicationVerifier::new(publication(b"hello")?);
    wrong.chunk(b"jello")?;
    assert!(wrong.finish_marker().is_err());
    assert!(wrong.end_of_stream().is_err());
    let mut missing_marker = PublicationVerifier::new(publication(b"hello")?);
    missing_marker.chunk(b"hello")?;
    assert!(missing_marker.end_of_stream().is_err());
    Ok(())
}

#[test]
fn extra_empty_oversized_and_post_finish_chunks_terminally_fail_upload() -> TestResult {
    for invalid in [
        vec![],
        vec![7; MAX_RELAY_FRAME_BYTES + 1],
        b"toolong".to_vec(),
    ] {
        let mut receiver = PublicationVerifier::new(publication(b"hello")?);
        assert!(receiver.chunk(&invalid).is_err());
        assert!(receiver.chunk(b"hello").is_err());
        assert!(receiver.finish_marker().is_err());
        assert!(receiver.end_of_stream().is_err());
    }
    let mut receiver = PublicationVerifier::new(publication(b"hello")?);
    receiver.chunk(b"hello")?;
    receiver.finish_marker()?;
    assert!(receiver.chunk(b"x").is_err());
    assert!(receiver.end_of_stream().is_err());
    let mut receiver = PublicationVerifier::new(publication(b"hello")?);
    receiver.chunk(b"hello")?;
    receiver.finish_marker()?;
    assert!(receiver.finish_marker().is_err());
    assert!(receiver.end_of_stream().is_err());
    Ok(())
}

#[test]
fn excessive_advertised_length_is_rejected_without_body_allocation() -> TestResult {
    let too_large = u32::try_from(nocterm_hub_model::cloud::MAX_ENVELOPE_BYTES + 1)?;
    assert!(PublicationMetadata::new([0; 16], binding()?, too_large, [0; 32]).is_err());
    assert!(PublicationMetadata::new([0; 16], binding()?, 0, [0; 32]).is_err());
    Ok(())
}

#[test]
fn routing_round_trip_refuses_unknown_kinds_suffixes_and_truncation() -> TestResult {
    let original = binding()?;
    let bytes = original.canonical_bytes()?;
    assert_eq!(RelayBinding::from_canonical_bytes(&bytes)?, original);
    for length in 0..bytes.len() {
        assert!(RelayBinding::from_canonical_bytes(&bytes[..length]).is_err());
    }
    let mut suffixed = bytes.clone();
    suffixed.push(0);
    assert!(RelayBinding::from_canonical_bytes(&suffixed).is_err());
    let kind_index = 4 + b"nocterm/cloud-relay-binding/v1".len();
    for kind in [0, 5, 255] {
        let mut changed = bytes.clone();
        changed[kind_index] = kind;
        assert!(RelayBinding::from_canonical_bytes(&changed).is_err());
    }
    Ok(())
}

#[test]
fn transport_publication_identity_is_distinct_from_signed_command_identity() -> TestResult {
    let one = publication(b"first encryption")?;
    let two = PublicationMetadata::new(
        [9; 16],
        binding()?,
        17,
        Sha256::digest(b"second encryption").into(),
    )?;
    assert_ne!(one.id(), two.id());
    assert_eq!(one.binding().object_id(), two.binding().object_id());
    assert_ne!(one.digest(), two.digest());
    Ok(())
}

fn capabilities(
    key: &SigningKey,
    nonce: [u8; 16],
) -> Result<SignedCapabilities, Box<dyn std::error::Error>> {
    let claim = CapabilitiesClaim::new(
        CloudTextId::new("hub-1")?,
        key.verifying_key().to_bytes(),
        CapabilityLimits::v1(),
        nonce,
        CapabilityWindow {
            issued_at_ms: 100_000,
            expires_at_ms: 160_000,
        },
    )?;
    let signature = key.sign(&claim.canonical_bytes()?).to_bytes();
    Ok(SignedCapabilities::new(claim, signature)?)
}

#[test]
fn stable_authority_proof_requires_original_pin_hub_nonce_and_freshness() -> TestResult {
    let key = SigningKey::from_bytes(&[7; 32]);
    let signed = capabilities(&key, [8; 16])?;
    let authority = key.verifying_key().to_bytes();
    signed.require_expected("hub-1", &authority, &[8; 16], 110_000)?;
    assert!(
        signed
            .require_expected("hub-2", &authority, &[8; 16], 110_000)
            .is_err()
    );
    assert!(
        signed
            .require_expected("hub-1", &[9; 32], &[8; 16], 110_000)
            .is_err()
    );
    assert!(
        signed
            .require_expected("hub-1", &authority, &[9; 16], 110_000)
            .is_err()
    );
    assert!(
        signed
            .require_expected("hub-1", &authority, &[8; 16], 160_000)
            .is_err()
    );
    assert!(
        signed
            .require_expected("hub-1", &authority, &[8; 16], 39_999)
            .is_err()
    );
    assert!(
        signed
            .require_expected("hub-1", &authority, &[8; 16], i64::MIN)
            .is_err()
    );
    let other = SigningKey::from_bytes(&[9; 32]);
    assert!(
        capabilities(&other, [8; 16])?
            .require_expected("hub-1", &authority, &[8; 16], 110_000)
            .is_err()
    );
    Ok(())
}

#[test]
fn capability_decoder_rejects_unsupported_limits_window_and_bad_signature() -> TestResult {
    let key = SigningKey::from_bytes(&[7; 32]);
    let signed = capabilities(&key, [8; 16])?;
    let bytes = signed.claim().canonical_bytes()?;
    assert_eq!(
        CapabilitiesClaim::from_canonical_bytes(&bytes)?,
        *signed.claim()
    );
    for length in 0..bytes.len() {
        assert!(CapabilitiesClaim::from_canonical_bytes(&bytes[..length]).is_err());
    }
    let mut suffix = bytes;
    suffix.push(0);
    assert!(CapabilitiesClaim::from_canonical_bytes(&suffix).is_err());
    assert!(SignedCapabilities::new(signed.claim().clone(), [0; 64]).is_err());
    for limits in [
        CapabilityLimits {
            version: 2,
            ..CapabilityLimits::v1()
        },
        CapabilityLimits {
            features: 0,
            ..CapabilityLimits::v1()
        },
        CapabilityLimits {
            max_frame_bytes: 16 * 1024 + 1,
            ..CapabilityLimits::v1()
        },
        CapabilityLimits {
            max_envelope_bytes: u32::MAX,
            ..CapabilityLimits::v1()
        },
    ] {
        assert!(
            CapabilitiesClaim::new(
                CloudTextId::new("hub-1")?,
                key.verifying_key().to_bytes(),
                limits,
                [8; 16],
                CapabilityWindow {
                    issued_at_ms: 0,
                    expires_at_ms: 1
                }
            )
            .is_err()
        );
    }
    for window in [
        CapabilityWindow {
            issued_at_ms: 0,
            expires_at_ms: 60_001,
        },
        CapabilityWindow {
            issued_at_ms: 0,
            expires_at_ms: 0,
        },
        CapabilityWindow {
            issued_at_ms: i64::MIN,
            expires_at_ms: i64::MAX,
        },
    ] {
        assert!(
            CapabilitiesClaim::new(
                CloudTextId::new("hub-1")?,
                key.verifying_key().to_bytes(),
                CapabilityLimits::v1(),
                [8; 16],
                window
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn key_material_routing_is_a_bounded_separate_inbox_kind() -> TestResult {
    use nocterm_hub_model::cloud::{
        ChatCoordinate,
        relay::{MAX_RELAY_KEY_MATERIAL_BYTES, RelayKind},
    };
    let original = binding()?;
    let chat = ChatCoordinate::new(
        original.namespace().clone(),
        original.runner(),
        original.chat_id(),
        5,
    )?;
    let material = RelayBinding::chat_key_grant(chat.clone());
    assert_eq!(material.kind(), RelayKind::ChatKeyGrant);
    assert_eq!(material.material_coordinate(), Some(&chat));
    assert!(material.command_route().is_none());
    assert!(material.record_context().is_none());
    let bytes = material.canonical_bytes()?;
    assert_eq!(RelayBinding::from_canonical_bytes(&bytes)?, material);
    for length in 0..bytes.len() {
        assert!(RelayBinding::from_canonical_bytes(&bytes[..length]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(RelayBinding::from_canonical_bytes(&extra).is_err());
    assert!(
        PublicationMetadata::new(
            [1; 16],
            material.clone(),
            MAX_RELAY_KEY_MATERIAL_BYTES,
            [0; 32]
        )
        .is_ok()
    );
    assert!(
        PublicationMetadata::new([1; 16], material, MAX_RELAY_KEY_MATERIAL_BYTES + 1, [0; 32])
            .is_err()
    );
    let vector =
        hex::decode(include_str!("../../../fixtures/cloud-relay-v1/binding-key-grant.hex").trim())?;
    let parsed = RelayBinding::from_canonical_bytes(&vector)?;
    assert_eq!(parsed.canonical_bytes()?, vector);
    assert_eq!(
        parsed.material_coordinate().ok_or("material")?.key_epoch(),
        5
    );
    assert_eq!(parsed.runner(), original.runner());
    Ok(())
}
