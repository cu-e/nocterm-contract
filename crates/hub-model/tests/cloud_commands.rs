use ed25519_dalek::{Signer, SigningKey};
use nocterm_hub_model::{
    cloud::{
        CloudTextId, CommandContext, CommandError, CommandHeader, CommandKind, MAX_HEADER_BYTES,
        MAX_PLAINTEXT_BYTES, SignedCommand, hub_namespace_id,
    },
    pop,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
const PAYLOAD: &[u8] = b"fixture secret\n\x00payload";

fn fixture_header() -> Result<CommandHeader, Box<dyn Error>> {
    Ok(CommandHeader::from_canonical_bytes(&hex::decode(
        include_str!("../../../fixtures/cloud-command-v1/header.hex").trim(),
    )?)?)
}
fn plaintext() -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(include_str!("../../../fixtures/cloud-command-v1/plaintext.hex").trim())
}
fn signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    for (value, byte) in (0xa0u8..=0xbf).zip(&mut bytes) {
        *byte = value;
    }
    SigningKey::from_bytes(&bytes)
}
fn with_context(context: CommandContext, payload: &[u8]) -> Result<CommandHeader, Box<dyn Error>> {
    let h = fixture_header()?;
    Ok(CommandHeader::new(
        h.route().clone(),
        h.keys(),
        h.issuer().clone(),
        context,
        payload,
    )?)
}
fn sign(header: CommandHeader, payload: &[u8]) -> Result<SignedCommand<'_>, Box<dyn Error>> {
    let signature = signing_key().sign(&header.canonical_bytes()?).to_bytes();
    Ok(SignedCommand::new(header, payload, signature)?)
}

#[test]
fn independent_header_and_device_signature_vectors_are_byte_exact() -> TestResult {
    let header = fixture_header()?;
    let rebuilt = CommandHeader::new(
        header.route().clone(),
        header.keys(),
        header.issuer().clone(),
        header.context(),
        PAYLOAD,
    )?;
    assert_eq!(header, rebuilt);
    assert_eq!(
        rebuilt.canonical_bytes()?,
        hex::decode(include_str!("../../../fixtures/cloud-command-v1/header.hex").trim())?
    );
    let bytes = plaintext()?;
    let packet = SignedCommand::from_plaintext(&bytes)?;
    assert_eq!(packet.header(), &header);
    assert_eq!(packet.payload(), PAYLOAD);
    assert_eq!(sign(header, PAYLOAD)?.plaintext_bytes()?, bytes);
    Ok(())
}

#[test]
fn namespace_binds_full_hub_authority_without_addresses_or_normalization() -> TestResult {
    let expected = include_str!("../../../fixtures/cloud-command-v1/namespace.hex").trim();
    let namespace = hub_namespace_id("hub-1", [0x31; 32])?;
    assert_eq!(namespace.as_str(), expected);
    assert_eq!(namespace.as_str().len(), 64);
    assert_eq!(namespace, hub_namespace_id("hub-1", [0x31; 32])?);
    assert_ne!(namespace, hub_namespace_id("hub-1", [0x32; 32])?);
    assert_ne!(namespace, hub_namespace_id(" hub-1", [0x31; 32])?);
    assert_ne!(
        hub_namespace_id("é", [1; 32])?,
        hub_namespace_id("e\u{301}", [1; 32])?
    );
    assert!(matches!(
        hub_namespace_id("", [0; 32]),
        Err(CommandError::IdentityLength)
    ));
    assert!(matches!(
        hub_namespace_id(&"x".repeat(129), [0; 32]),
        Err(CommandError::IdentityLength)
    ));
    Ok(())
}

#[test]
fn textual_identity_bounds_count_utf8_bytes_and_preserve_exact_values() -> TestResult {
    assert!(CloudTextId::new("x".repeat(128)).is_ok());
    assert!(CloudTextId::new("界".repeat(42)).is_ok());
    for text in [String::new(), "x".repeat(129), "界".repeat(43)] {
        assert!(matches!(
            CloudTextId::new(text),
            Err(CommandError::IdentityLength)
        ));
    }
    assert_eq!(CloudTextId::new("  a\0b  ")?.as_str(), "  a\0b  ");
    Ok(())
}

#[test]
fn unknown_kind_and_noncanonical_option_tags_are_refused() -> TestResult {
    for n in 1..=8 {
        assert_eq!(CommandKind::try_from(n)? as u16, n);
    }
    for n in [0, 9, u16::MAX] {
        assert!(matches!(
            CommandKind::try_from(n),
            Err(CommandError::UnsupportedKind)
        ));
    }
    let h = fixture_header()?;
    let mut bytes = h.canonical_bytes()?;
    let kind = bytes.len() - 54;
    bytes[kind..kind + 2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(matches!(
        CommandHeader::from_canonical_bytes(&bytes),
        Err(CommandError::UnsupportedKind)
    ));
    let mut bytes = h.canonical_bytes()?;
    let run_tag = bytes.len() - 79;
    bytes[run_tag] = 2;
    assert!(matches!(
        CommandHeader::from_canonical_bytes(&bytes),
        Err(CommandError::Malformed)
    ));
    Ok(())
}

#[test]
fn header_parser_refuses_every_truncated_prefix_suffix_and_bad_lengths() -> TestResult {
    let bytes = fixture_header()?.canonical_bytes()?;
    for end in 0..bytes.len() {
        assert!(
            CommandHeader::from_canonical_bytes(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(matches!(
        CommandHeader::from_canonical_bytes(&extra),
        Err(CommandError::Malformed)
    ));
    let mut oversized = bytes.clone();
    oversized[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CommandHeader::from_canonical_bytes(&oversized).is_err());
    let mut payload_overflow = bytes.clone();
    let at = payload_overflow.len() - 36;
    payload_overflow[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        CommandHeader::from_canonical_bytes(&payload_overflow),
        Err(CommandError::PlaintextTooLarge)
    ));
    assert!(matches!(
        CommandHeader::from_canonical_bytes(&vec![0; MAX_HEADER_BYTES + 1]),
        Err(CommandError::HeaderTooLarge)
    ));
    Ok(())
}

#[test]
fn header_rejects_unknown_version_and_invalid_utf8() -> TestResult {
    let mut bytes = fixture_header()?.canonical_bytes()?;
    let label_end = 4 + b"nocterm/cloud-command/v1".len();
    bytes[label_end - 1] = b'2';
    assert!(matches!(
        CommandHeader::from_canonical_bytes(&bytes),
        Err(CommandError::UnsupportedVersion)
    ));
    let mut bytes = fixture_header()?.canonical_bytes()?;
    let at = bytes
        .windows(b"device-1".len())
        .position(|part| part == b"device-1")
        .ok_or("fixture device id")?;
    bytes[at] = 0xff;
    assert!(matches!(
        CommandHeader::from_canonical_bytes(&bytes),
        Err(CommandError::Malformed)
    ));
    Ok(())
}

#[test]
fn packet_parser_refuses_prefixes_suffixes_substituted_payload_and_signature() -> TestResult {
    let bytes = plaintext()?;
    for end in 0..bytes.len() {
        assert!(
            SignedCommand::from_plaintext(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(matches!(
        SignedCommand::from_plaintext(&extra),
        Err(CommandError::Malformed)
    ));
    let mut altered = bytes.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert!(matches!(
        SignedCommand::from_plaintext(&altered),
        Err(CommandError::Signature(_))
    ));
    let mut altered = bytes.clone();
    altered[fixture_header()?.canonical_bytes()?.len() + 8] ^= 1;
    assert!(matches!(
        SignedCommand::from_plaintext(&altered),
        Err(CommandError::PayloadMismatch)
    ));
    let mut oversized = bytes;
    oversized[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        SignedCommand::from_plaintext(&oversized),
        Err(CommandError::Malformed)
    ));
    Ok(())
}

#[test]
fn signatures_for_old_request_purposes_never_authenticate_cloud_commands() -> TestResult {
    let header = fixture_header()?;
    let old = pop::request_message("hub", "/rpc", "token", "nonce", 1);
    let signature = signing_key().sign(&old).to_bytes();
    let error = SignedCommand::new(header, PAYLOAD, signature)
        .err()
        .ok_or("signature accepted")?;
    assert!(matches!(
        error,
        CommandError::Signature(pop::SignatureError::Invalid)
    ));
    assert!(
        error
            .source()
            .is_some_and(<dyn Error>::is::<pop::SignatureError>)
    );
    Ok(())
}

#[test]
fn packet_binds_raw_payload_bytes_without_reserializing_them() -> TestResult {
    let payload = br#"{ "text" : "literal" }"#;
    let header = with_context(fixture_header()?.context(), payload)?;
    let signed = sign(header.clone(), payload)?;
    assert_eq!(signed.payload(), payload);
    let changed = br#"{"text":"literal"}"#;
    assert!(matches!(
        SignedCommand::new(header, changed, signed.signature()),
        Err(CommandError::PayloadMismatch)
    ));
    assert!(!format!("{signed:?}").contains("literal"));
    Ok(())
}

#[test]
fn full_plaintext_limit_includes_header_lengths_and_signature() -> TestResult {
    let h = fixture_header()?;
    let capacity = MAX_PLAINTEXT_BYTES - h.canonical_bytes()?.len() - 72;
    let mut payload = vec![b'x'; capacity];
    let header = with_context(h.context(), &payload)?;
    assert_eq!(
        sign(header, &payload)?.plaintext_bytes()?.len(),
        MAX_PLAINTEXT_BYTES
    );
    payload.push(b'x');
    assert!(matches!(
        CommandHeader::new(
            h.route().clone(),
            h.keys(),
            h.issuer().clone(),
            h.context(),
            &payload
        ),
        Err(CommandError::PlaintextTooLarge)
    ));
    assert!(matches!(
        SignedCommand::from_plaintext(&vec![0; MAX_PLAINTEXT_BYTES + 1]),
        Err(CommandError::PlaintextTooLarge)
    ));
    Ok(())
}

#[test]
fn admission_time_is_pure_overflow_safe_and_separate_from_authentication() -> TestResult {
    let mut context = fixture_header()?.context();
    context.issued_at_ms = 100_000;
    context.accept_before_ms = 100_100;
    let h = with_context(context, PAYLOAD)?;
    assert!(h.validate_admission_time(40_000).is_ok());
    assert!(matches!(
        h.validate_admission_time(39_999),
        Err(CommandError::IssuedInFuture)
    ));
    assert!(matches!(
        h.validate_admission_time(100_100),
        Err(CommandError::Expired)
    ));
    assert!(matches!(
        h.validate_admission_time(i64::MAX),
        Err(CommandError::Expired)
    ));
    assert!(matches!(
        h.validate_admission_time(i64::MIN),
        Err(CommandError::IssuedInFuture)
    ));
    let bytes = sign(h, PAYLOAD)?.plaintext_bytes()?;
    // Old idempotent receipts may be read: opening does not claim fresh effect admission.
    assert!(SignedCommand::from_plaintext(&bytes).is_ok());
    for (issued, expires) in [(0, 1_800_001), (2, 1), (i64::MIN, i64::MAX)] {
        context.issued_at_ms = issued;
        context.accept_before_ms = expires;
        let h = fixture_header()?;
        assert!(matches!(
            CommandHeader::new(
                h.route().clone(),
                h.keys(),
                h.issuer().clone(),
                context,
                PAYLOAD
            ),
            Err(CommandError::InvalidTimeWindow)
        ));
    }
    Ok(())
}
