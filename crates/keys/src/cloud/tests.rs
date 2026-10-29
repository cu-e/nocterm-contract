use super::*;
use crate::{CollectionKey, DeviceKey, OpenError};
use nocterm_hub_model::cloud::{
    CloudNamespace, CloudRoute, CloudTextId, CommandContext, CommandHeader, CommandIssuer,
    CommandKeys, CommandKind, MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES, RunCoordinate,
    RunnerCoordinate, SignedCommand, hub_namespace_id,
};
use sha2::{Digest, Sha256};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
const PAYLOAD: &[u8] = b"fixture secret\n\x00payload";
const VALID: &str = include_str!("../../../../fixtures/cloud-command-v1/valid.hex");

fn seed(first: u8) -> [u8; 32] {
    let mut seed = [0; 32];
    let mut next = first;
    for byte in &mut seed {
        *byte = next;
        next = next.wrapping_add(1);
    }
    seed
}
fn account() -> AccountKeyPair {
    AccountKeyPair::from_seed(&seed(0x10))
}
fn runner() -> RunnerEncryptionKey {
    RunnerEncryptionKey::from_seed(&seed(0x40))
}
fn device() -> DeviceKey {
    DeviceKey::from_seed(&seed(0xa0))
}
fn vector(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.trim())
}
fn route() -> Result<CloudRoute, CommandError> {
    Ok(CloudRoute {
        namespace: CloudNamespace {
            hub_instance_id: hub_namespace_id("hub-1", [0x31; 32])?,
            account_id: CloudTextId::new("account-2")?,
        },
        runner: RunnerCoordinate {
            id: [0x21; 16],
            key_epoch: 3,
        },
        chat_id: [0x23; 16],
        command_id: [0x24; 16],
    })
}
fn header(
    payload: &[u8],
    sender: &AccountKeyPair,
    recipient: &PublicKey,
    signer: &DeviceKey,
) -> Result<CommandHeader, CommandError> {
    CommandHeader::new(
        route()?,
        CommandKeys {
            account: sender.public_key().to_bytes(),
            runner: recipient.to_bytes(),
        },
        CommandIssuer {
            device_id: CloudTextId::new("device-1")?,
            signing_key: signer.public_key(),
            access_token_digest: Sha256::digest(b"fixture-token").into(),
        },
        CommandContext {
            nonce: [0x25; 16],
            expected_chat_revision: 9,
            run: Some(RunCoordinate {
                id: [0x26; 16],
                expected_epoch: 7,
            }),
            kind: CommandKind::SubmitPrompt,
            issued_at_ms: 1_700_000_000_000,
            accept_before_ms: 1_700_000_060_000,
        },
        payload,
    )
}
fn sign<'a>(
    header: CommandHeader,
    payload: &'a [u8],
    signer: &DeviceKey,
) -> Result<SignedCommand<'a>, CommandError> {
    let signature = signer.sign(&header.canonical_bytes()?);
    SignedCommand::new(header, payload, signature)
}
fn sealed() -> Result<Vec<u8>, Box<dyn Error>> {
    let command = sign(
        header(PAYLOAD, &account(), &runner().public_key(), &device())?,
        PAYLOAD,
        &device(),
    )?;
    Ok(seal_command(&account(), &runner().public_key(), &command)?)
}
fn open(bytes: &[u8]) -> Result<OpenedCommand, CloudCommandError> {
    open_command(&runner(), &account().public_key(), &route()?, bytes)
}

#[test]
fn independent_python_command_box_opens_with_exact_signed_bytes() -> TestResult {
    let bytes = vector(VALID)?;
    let opened = open(&bytes)?;
    let command = opened.command()?;
    assert_eq!(command.payload(), PAYLOAD);
    assert_eq!(command.header().route(), &route()?);
    assert_eq!(command.header().issuer().signing_key, device().public_key());
    assert_eq!(
        command.header().canonical_bytes()?,
        vector(include_str!(
            "../../../../fixtures/cloud-command-v1/header.hex"
        ))?
    );
    assert_eq!(
        command.plaintext_bytes()?,
        vector(include_str!(
            "../../../../fixtures/cloud-command-v1/plaintext.hex"
        ))?
    );
    Ok(())
}

#[test]
fn public_sealing_round_trips_and_never_prints_or_exposes_payload() -> TestResult {
    let bytes = sealed()?;
    assert_eq!(&bytes[..2], &[1, 8]);
    assert!(!bytes.windows(PAYLOAD.len()).any(|window| window == PAYLOAD));
    let opened = open(&bytes)?;
    assert_eq!(opened.command()?.payload(), PAYLOAD);
    assert!(!format!("{opened:?}").contains("fixture secret"));
    assert!(!format!("{:?}", opened.command()?).contains("fixture secret"));
    Ok(())
}

#[test]
fn fresh_boxes_preserve_one_semantic_command_without_claiming_replay_admission() -> TestResult {
    let (a, b) = (sealed()?, sealed()?);
    assert_ne!(a, b);
    assert_ne!(&a[2..34], &b[2..34]);
    assert_ne!(&a[34..58], &b[34..58]);
    assert_eq!(
        open(&a)?.command()?.plaintext_bytes()?,
        open(&b)?.command()?.plaintext_bytes()?
    );
    assert_eq!(
        open(&a)?.command()?.header().route().command_id,
        route()?.command_id
    );
    // Authentication itself is stateless: a journal must prevent duplicate effects.
    assert_eq!(
        open(&a)?.command()?.payload(),
        open(&a)?.command()?.payload()
    );
    Ok(())
}

#[test]
fn wrong_account_pin_or_recipient_private_key_cannot_open() -> TestResult {
    let ciphertext = vector(VALID)?;
    let other = AccountKeyPair::generate()?;
    assert!(matches!(
        open_command(&runner(), &other.public_key(), &route()?, &ciphertext),
        Err(CloudCommandError::Authentication(_))
    ));
    let other_runner = RunnerEncryptionKey::generate()?;
    assert!(matches!(
        open_command(
            &other_runner,
            &account().public_key(),
            &route()?,
            &ciphertext
        ),
        Err(CloudCommandError::Authentication(_))
    ));
    Ok(())
}

#[test]
fn hub_chosen_account_and_device_keys_do_not_create_account_membership() -> TestResult {
    let hub = AccountKeyPair::generate()?;
    let fake_device = DeviceKey::generate()?;
    let command = sign(
        header(PAYLOAD, &hub, &runner().public_key(), &fake_device)?,
        PAYLOAD,
        &fake_device,
    )?;
    let forged = seal_command(&hub, &runner().public_key(), &command)?;
    assert!(matches!(
        open(&forged),
        Err(CloudCommandError::Authentication(_))
    ));
    assert!(open_command(&runner(), &hub.public_key(), &route()?, &forged).is_ok());
    Ok(())
}

#[test]
fn every_route_coordinate_and_trusted_authority_are_authenticated() -> TestResult {
    let bytes = vector(VALID)?;
    let base = route()?;
    let mut cases = Vec::new();
    let mut changed = base.clone();
    changed.namespace.hub_instance_id = hub_namespace_id("hub-1", [0x32; 32])?;
    cases.push(changed);
    let mut changed = base.clone();
    changed.namespace.hub_instance_id = hub_namespace_id("hub-2", [0x31; 32])?;
    cases.push(changed);
    let mut changed = base.clone();
    changed.namespace.account_id = CloudTextId::new("account-3")?;
    cases.push(changed);
    let mut changed = base.clone();
    changed.runner.id[0] ^= 1;
    cases.push(changed);
    let mut changed = base.clone();
    changed.runner.key_epoch += 1;
    cases.push(changed);
    let mut changed = base.clone();
    changed.chat_id[0] ^= 1;
    cases.push(changed);
    let mut changed = base;
    changed.command_id[0] ^= 1;
    cases.push(changed);
    for expected in cases {
        assert!(matches!(
            open_command(&runner(), &account().public_key(), &expected, &bytes),
            Err(CloudCommandError::Authentication(_))
        ));
    }
    Ok(())
}

#[test]
fn authenticated_boxes_still_require_matching_repeated_inner_keys_and_route() -> TestResult {
    for fixture in [
        include_str!("../../../../fixtures/cloud-command-v1/wrong-inner-account.hex"),
        include_str!("../../../../fixtures/cloud-command-v1/wrong-inner-runner.hex"),
        include_str!("../../../../fixtures/cloud-command-v1/wrong-inner-route.hex"),
    ] {
        assert!(matches!(
            open(&vector(fixture)?),
            Err(CloudCommandError::ContextMismatch)
        ));
    }
    Ok(())
}

#[test]
fn account_box_authentication_does_not_replace_device_signature_or_payload_binding() -> TestResult {
    for fixture in [
        include_str!("../../../../fixtures/cloud-command-v1/bad-device-signature.hex"),
        include_str!("../../../../fixtures/cloud-command-v1/bad-device-key.hex"),
    ] {
        assert!(matches!(
            open(&vector(fixture)?),
            Err(CloudCommandError::Command(CommandError::Signature(_)))
        ));
    }
    assert!(matches!(
        open(&vector(include_str!(
            "../../../../fixtures/cloud-command-v1/bad-payload.hex"
        ))?),
        Err(CloudCommandError::Command(CommandError::PayloadMismatch))
    ));
    Ok(())
}

#[test]
fn purpose_separation_rejects_old_grant_kdf_and_ad_even_with_the_command_tag() -> TestResult {
    for fixture in [
        include_str!("../../../../fixtures/cloud-command-v1/wrong-kdf-purpose.hex"),
        include_str!("../../../../fixtures/cloud-command-v1/wrong-aad-purpose.hex"),
    ] {
        assert!(matches!(
            open(&vector(fixture)?),
            Err(CloudCommandError::Authentication(_))
        ));
    }
    let old = CollectionKey::generate()?.seal_to(
        &account(),
        &runner().public_key(),
        "collection",
        "recipient",
    )?;
    assert!(matches!(open(&old), Err(CloudCommandError::WrongPurpose)));
    assert!(matches!(
        CollectionKey::open_from(
            &AccountKeyPair::from_seed(&seed(0x40)),
            &account().public_key(),
            "collection",
            "recipient",
            &vector(VALID)?
        ),
        Err(OpenError::Malformed)
    ));
    Ok(())
}

#[test]
fn seal_refuses_header_keys_different_from_the_actual_pairs() -> TestResult {
    let command = sign(
        header(PAYLOAD, &account(), &runner().public_key(), &device())?,
        PAYLOAD,
        &device(),
    )?;
    let other = AccountKeyPair::generate()?;
    assert!(matches!(
        seal_command(&other, &runner().public_key(), &command),
        Err(CloudCommandError::ContextMismatch)
    ));
    assert!(matches!(
        seal_command(&account(), &other.public_key(), &command),
        Err(CloudCommandError::ContextMismatch)
    ));
    Ok(())
}

#[test]
fn noncontributory_sender_recipient_and_ephemeral_keys_fail_closed() -> TestResult {
    for low in [[0u8; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    }] {
        let public = PublicKey::from_bytes(&low)?;
        let command = sign(
            header(PAYLOAD, &account(), &public, &device())?,
            PAYLOAD,
            &device(),
        )?;
        assert!(matches!(
            seal_command(&account(), &public, &command),
            Err(CloudCommandError::UnusablePeer)
        ));
        assert!(matches!(
            open_command(&runner(), &public, &route()?, &vector(VALID)?),
            Err(CloudCommandError::UnusablePeer)
        ));
        let mut bytes = vector(VALID)?;
        bytes[2..34].copy_from_slice(&low);
        assert!(matches!(open(&bytes), Err(CloudCommandError::UnusablePeer)));
    }
    Ok(())
}

#[test]
fn envelope_parser_refuses_truncation_suffixes_and_oversized_advertisements_before_allocation()
-> TestResult {
    let bytes = vector(VALID)?;
    for end in 0..bytes.len() {
        assert!(open(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(matches!(
        open(&extra),
        Err(CloudCommandError::MalformedEnvelope)
    ));
    let mut huge = bytes;
    huge[58..62].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        open(&huge),
        Err(CloudCommandError::EnvelopeTooLarge)
    ));
    assert!(matches!(
        open(&vec![0; MAX_ENVELOPE_BYTES + 1]),
        Err(CloudCommandError::EnvelopeTooLarge)
    ));
    let mut no_tag = vec![0u8; 62 + 15];
    no_tag[..2].copy_from_slice(&[1, 8]);
    no_tag[58..62].copy_from_slice(&15u32.to_be_bytes());
    assert!(matches!(
        open(&no_tag),
        Err(CloudCommandError::MalformedEnvelope)
    ));
    Ok(())
}

#[test]
fn all_unknown_versions_and_purposes_are_rejected_without_fallback() -> TestResult {
    for version in [0, 2, u8::MAX] {
        let mut bytes = vector(VALID)?;
        bytes[0] = version;
        assert!(matches!(
            open(&bytes),
            Err(CloudCommandError::UnsupportedVersion)
        ));
    }
    for purpose in [0, 1, 2, 3, 4, 5, 6, 7, 9, u8::MAX] {
        let mut bytes = vector(VALID)?;
        bytes[1] = purpose;
        assert!(matches!(open(&bytes), Err(CloudCommandError::WrongPurpose)));
    }
    Ok(())
}

#[test]
fn encrypted_body_nonce_and_ephemeral_key_tampering_are_rejected() -> TestResult {
    let bytes = vector(VALID)?;
    for index in [2, 33, 34, 57, 62, 100, bytes.len() - 1] {
        let mut tampered = bytes.clone();
        tampered[index] ^= 1;
        assert!(
            matches!(open(&tampered), Err(CloudCommandError::Authentication(_))),
            "index {index}"
        );
    }
    Ok(())
}

#[test]
fn two_devices_of_the_same_open_account_need_no_pairing_or_shared_signer() -> TestResult {
    let account = account();
    let runner = runner();
    for (index, key) in [device(), DeviceKey::from_seed(&seed(0xb0))]
        .into_iter()
        .enumerate()
    {
        let first = header(PAYLOAD, &account, &runner.public_key(), &key)?;
        let mut issuer = first.issuer().clone();
        issuer.device_id = CloudTextId::new(format!("device-{index}"))?;
        let own = CommandHeader::new(
            first.route().clone(),
            first.keys(),
            issuer,
            first.context(),
            PAYLOAD,
        )?;
        let command = sign(own, PAYLOAD, &key)?;
        let bytes = seal_command(&account, &runner.public_key(), &command)?;
        let opened = open_command(&runner, &account.public_key(), &route()?, &bytes)?;
        assert_eq!(
            opened.command()?.header().issuer().signing_key,
            key.public_key()
        );
        assert_eq!(
            opened.command()?.header().issuer().device_id.as_str(),
            format!("device-{index}")
        );
    }
    Ok(())
}

#[test]
fn exact_envelope_limit_counts_header_and_tag() -> TestResult {
    let empty = header(&[], &account(), &runner().public_key(), &device())?;
    let payload = vec![b'x'; MAX_PLAINTEXT_BYTES - empty.canonical_bytes()?.len() - 72];
    let command = sign(
        header(&payload, &account(), &runner().public_key(), &device())?,
        &payload,
        &device(),
    )?;
    let bytes = seal_command(&account(), &runner().public_key(), &command)?;
    assert_eq!(bytes.len(), MAX_ENVELOPE_BYTES);
    assert_eq!(open(&bytes)?.command()?.payload(), payload);
    Ok(())
}

#[test]
fn authentication_does_not_re_admit_expired_commands_or_invent_receipts() -> TestResult {
    let opened = open(&vector(VALID)?)?;
    let command = opened.command()?;
    assert!(matches!(
        command.header().validate_admission_time(1_700_000_060_000),
        Err(CommandError::Expired)
    ));
    assert_eq!(command.header().route().command_id, route()?.command_id);
    Ok(())
}

#[test]
fn boundary_errors_keep_original_typed_sources_without_plaintext() -> TestResult {
    let mut bytes = vector(VALID)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let error = open(&bytes).err().ok_or("tamper accepted")?;
    assert!(
        error
            .source()
            .is_some_and(<dyn Error>::is::<chacha20poly1305::Error>)
    );
    assert!(!error.to_string().contains("fixture secret"));
    let error = CloudCommandError::Command(CommandError::Malformed);
    assert!(error.source().is_some_and(<dyn Error>::is::<CommandError>));
    let error = CloudCommandError::Key(KeyError::Expand(hkdf::InvalidLength));
    assert!(error.source().is_some_and(<dyn Error>::is::<KeyError>));
    assert!(error.source().and_then(Error::source).is_some());
    let error = CloudCommandError::Encrypt(chacha20poly1305::Error);
    assert!(error.source().is_some());
    Ok(())
}
