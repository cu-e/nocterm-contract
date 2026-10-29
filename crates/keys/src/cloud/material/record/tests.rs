use super::*;
use crate::{AccountKey, cloud::material::tests::chat};
use nocterm_hub_model::cloud::{RecordPosition, RunCoordinate};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BODY: &[u8] = b"private signed transcript";

fn context() -> Result<RecordContext, Box<dyn std::error::Error>> {
    Ok(RecordContext::new(
        chat()?,
        RecordPosition {
            writer_epoch: 9,
            sequence: 10,
            journal_sequence: 11,
            revision: 12,
        },
        [0x77; 16],
        Some(RunCoordinate {
            id: [0x88; 16],
            expected_epoch: 13,
        }),
    )?)
}
fn fixture_key() -> Result<ChatKey, Box<dyn std::error::Error>> {
    Ok(ChatKey::open_for_account(
        &AccountKey([0x55; 32]),
        &chat()?,
        &hex::decode(
            include_str!("../../../../../../fixtures/cloud-material-v1/account-wrap.hex").trim(),
        )?,
    )?)
}

#[test]
fn events_and_snapshots_require_exact_runner_signature_and_distinct_purpose() -> TestResult {
    let key = ChatKey::generate()?;
    let signer = RunnerSigningKey::generate()?;
    let event = seal_event(&key, &signer, context()?, BODY)?;
    let snapshot = seal_snapshot(&key, &signer, context()?, BODY)?;
    assert_eq!(&event[..2], &[1, 11]);
    assert_eq!(&snapshot[..2], &[1, 12]);
    assert_eq!(
        open_event(&key, &signer.public_key(), &context()?, &event)?
            .record()?
            .payload(),
        BODY
    );
    assert_eq!(
        open_snapshot(&key, &signer.public_key(), &context()?, &snapshot)?
            .record()?
            .payload(),
        BODY
    );
    assert!(open_snapshot(&key, &signer.public_key(), &context()?, &event).is_err());
    assert!(open_event(&key, &signer.public_key(), &context()?, &snapshot).is_err());
    assert!(
        open_event(
            &key,
            &RunnerSigningKey::generate()?.public_key(),
            &context()?,
            &event
        )
        .is_err()
    );
    assert!(
        open_event(
            &ChatKey::generate()?,
            &signer.public_key(),
            &context()?,
            &event
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn signed_record_binds_all_positions_ids_and_optional_run() -> TestResult {
    let key = ChatKey::generate()?;
    let signer = RunnerSigningKey::generate()?;
    let original = context()?;
    let event = seal_event(&key, &signer, original.clone(), BODY)?;
    let p = original.position();
    for position in [
        RecordPosition {
            writer_epoch: 10,
            ..p
        },
        RecordPosition { sequence: 11, ..p },
        RecordPosition {
            journal_sequence: 12,
            ..p
        },
        RecordPosition { revision: 13, ..p },
    ] {
        let changed = RecordContext::new(chat()?, position, original.id(), original.run())?;
        assert!(open_event(&key, &signer.public_key(), &changed, &event).is_err());
    }
    for run in [
        None,
        Some(RunCoordinate {
            id: [0; 16],
            expected_epoch: 13,
        }),
        Some(RunCoordinate {
            id: [0x88; 16],
            expected_epoch: 14,
        }),
    ] {
        let changed = RecordContext::new(chat()?, p, original.id(), run)?;
        assert!(open_event(&key, &signer.public_key(), &changed, &event).is_err());
    }
    let changed = RecordContext::new(chat()?, p, [0; 16], original.run())?;
    assert!(open_event(&key, &signer.public_key(), &changed, &event).is_err());
    for chat in crate::cloud::material::tests::moved_chats()? {
        let changed = RecordContext::new(chat, p, original.id(), original.run())?;
        assert!(open_event(&key, &signer.public_key(), &changed, &event).is_err());
    }
    Ok(())
}

#[test]
fn every_event_byte_tamper_truncation_suffix_and_unknown_tag_is_refused() -> TestResult {
    let key = ChatKey::generate()?;
    let signer = RunnerSigningKey::generate()?;
    let event = seal_event(&key, &signer, context()?, BODY)?;
    for i in 0..event.len() {
        let mut changed = event.clone();
        changed[i] ^= 1;
        assert!(open_event(&key, &signer.public_key(), &context()?, &changed).is_err());
        assert!(open_event(&key, &signer.public_key(), &context()?, &event[..i]).is_err());
    }
    let mut suffix = event;
    suffix.push(0);
    assert!(open_event(&key, &signer.public_key(), &context()?, &suffix).is_err());
    Ok(())
}

#[test]
fn unknown_record_kinds_noncanonical_options_and_suffixes_are_not_snapshots() -> TestResult {
    let signer = RunnerSigningKey::generate()?;
    let header = RecordHeader::new(context()?, RecordKind::Event, signer.public_key(), BODY)?;
    let encoded = header.canonical_bytes()?;
    assert_eq!(RecordHeader::from_canonical_bytes(&encoded)?, header);
    let mut suffix = encoded.clone();
    suffix.push(0);
    assert!(RecordHeader::from_canonical_bytes(&suffix).is_err());
    let kind_index = 4 + b"nocterm/cloud-record/v1".len();
    for tag in [0, 3, 255] {
        let mut changed = encoded.clone();
        changed[kind_index] = tag;
        assert!(RecordHeader::from_canonical_bytes(&changed).is_err());
    }
    let context_bytes = context()?.canonical_bytes()?;
    let option_index = context_bytes.len() - 25;
    let context_start = kind_index + 1 + 4;
    let mut changed = encoded;
    changed[context_start + option_index] = 2;
    assert!(RecordHeader::from_canonical_bytes(&changed).is_err());
    Ok(())
}

#[test]
fn independent_python_signed_events_and_snapshots_open() -> TestResult {
    let key = fixture_key()?;
    let signer = RunnerSigningKey::from_seed(&[0x66; 32]);
    let event =
        hex::decode(include_str!("../../../../../../fixtures/cloud-material-v1/event.hex").trim())?;
    let snapshot = hex::decode(
        include_str!("../../../../../../fixtures/cloud-material-v1/snapshot.hex").trim(),
    )?;
    let opened = open_event(&key, &signer.public_key(), &context()?, &event)?;
    assert_eq!(opened.record()?.payload(), BODY);
    assert_eq!(
        open_snapshot(&key, &signer.public_key(), &context()?, &snapshot)?
            .record()?
            .payload(),
        BODY
    );
    assert!(!format!("{opened:?}").contains("private signed"));
    assert!(!format!("{:?}", opened.record()?).contains("private signed"));
    assert!(!format!("{signer:?}").contains(&hex::encode([0x66; 32])));
    let restored = RunnerSigningKey::from_seed(&signer.seed());
    assert_eq!(signer.public_key(), restored.public_key());
    Ok(())
}

#[test]
fn knowing_chat_key_does_not_authorize_forged_runner_events() -> TestResult {
    let key = fixture_key()?;
    let signer = RunnerSigningKey::from_seed(&[0x66; 32]);
    for fixture in [
        include_str!("../../../../../../fixtures/cloud-material-v1/event-invalid-signature.hex"),
        include_str!("../../../../../../fixtures/cloud-material-v1/event-altered-payload.hex"),
        include_str!("../../../../../../fixtures/cloud-material-v1/event-wrong-inner-context.hex"),
        include_str!("../../../../../../fixtures/cloud-material-v1/event-wrong-inner-kind.hex"),
    ] {
        let ciphertext = hex::decode(fixture.trim())?;
        assert!(open_event(&key, &signer.public_key(), &context()?, &ciphertext).is_err());
    }
    Ok(())
}

#[test]
fn opening_a_signed_event_is_not_an_admission_or_replay_receipt() -> TestResult {
    let key = ChatKey::generate()?;
    let signer = RunnerSigningKey::generate()?;
    let ciphertext = seal_event(&key, &signer, context()?, BODY)?;
    let a = open_event(&key, &signer.public_key(), &context()?, &ciphertext)?;
    let b = open_event(&key, &signer.public_key(), &context()?, &ciphertext)?;
    assert_eq!(a.record()?.header(), b.record()?.header());
    Ok(())
}

#[test]
fn zero_positions_and_oversized_contexts_are_refused_before_opening() -> TestResult {
    let original = context()?;
    let p = original.position();
    for position in [
        RecordPosition {
            writer_epoch: 0,
            ..p
        },
        RecordPosition { sequence: 0, ..p },
        RecordPosition {
            journal_sequence: 0,
            ..p
        },
        RecordPosition { revision: 0, ..p },
    ] {
        assert!(RecordContext::new(chat()?, position, original.id(), original.run()).is_err());
    }
    assert!(
        RecordContext::new(
            chat()?,
            p,
            original.id(),
            Some(RunCoordinate {
                id: [0; 16],
                expected_epoch: 0
            })
        )
        .is_err()
    );
    let bytes = original.canonical_bytes()?;
    assert_eq!(RecordContext::from_canonical_bytes(&bytes)?, original);
    let mut suffix = bytes;
    suffix.push(0);
    assert!(RecordContext::from_canonical_bytes(&suffix).is_err());
    assert!(
        RecordContext::from_canonical_bytes(&vec![
            0;
            nocterm_hub_model::cloud::MAX_HEADER_BYTES + 1
        ])
        .is_err()
    );
    let key = ChatKey::generate()?;
    let signer = RunnerSigningKey::generate()?;
    let oversized = vec![0; MAX_PLAINTEXT_BYTES + OVERHEAD + 1];
    assert!(matches!(
        open_event(&key, &signer.public_key(), &context()?, &oversized),
        Err(CloudRecordError::Capacity)
    ));
    assert!(matches!(
        RecordHeader::new(
            context()?,
            RecordKind::Event,
            signer.public_key(),
            &oversized
        ),
        Err(RecordError::Capacity)
    ));
    Ok(())
}

mod session;
