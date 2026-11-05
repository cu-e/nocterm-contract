#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::testing::{NOW, World};
use nocterm_hub_model::cloud::{
    RecordContext, RecordKind, RecordPosition, RunCoordinate,
    events::{CloudEvent, CloudEventPayload, CloudSnapshotPayload, CloudTextChannel},
    relay::{RelayBinding, RelayKind},
};
use nocterm_keys::cloud::{ChatKey, RunnerSigningKey, seal_event, seal_snapshot};
use sha2::{Digest, Sha256};

const RUN: RunCoordinate = RunCoordinate {
    id: [0x21; 16],
    expected_epoch: 1,
};

/// One record as the hub would deliver it.
struct Delivered {
    id: [u8; 16],
    binding: Vec<u8>,
    ciphertext: Vec<u8>,
    cursor: u64,
    anchor: HeadRecordAnchor,
}
impl Delivered {
    fn header(&self) -> DeliveredRecord<'_> {
        self.header_from(&[0x71; 32])
    }
    fn header_from<'a>(&'a self, proof: &'a [u8]) -> DeliveredRecord<'a> {
        DeliveredRecord {
            publication_id: &self.id,
            binding: &self.binding,
            total_bytes: u32::try_from(self.ciphertext.len()).unwrap(),
            ciphertext_sha256: &self.anchor.ciphertext_digest,
            cursor: self.cursor,
            origin: DeliveredOrigin {
                account_id: "account-0001",
                signing_key: proof,
                runner_id: Some(&[0x02; 16]),
            },
        }
    }
}

fn context(world: &World, sequence: u64, run: Option<RunCoordinate>) -> RecordContext {
    RecordContext::new(
        world.selector.coordinate().unwrap(),
        RecordPosition {
            writer_epoch: 1,
            sequence,
            journal_sequence: sequence,
            revision: sequence,
        },
        [u8::try_from(sequence).unwrap(); 16],
        run,
    )
    .unwrap()
}
fn text(sequence: u64, value: &'static str) -> CloudEvent<'static> {
    CloudEvent {
        control_revision: sequence,
        timestamp_ms: 1_000 + sequence,
        payload: CloudEventPayload::Text {
            run: RUN,
            step: Some([u8::try_from(sequence).unwrap(); 16]),
            channel: CloudTextChannel::Assistant,
            text: value,
        },
    }
}
fn deliver(
    context: &RecordContext,
    kind: RelayKind,
    ciphertext: Vec<u8>,
    cursor: u64,
) -> Delivered {
    let binding = match kind {
        RelayKind::Snapshot => RelayBinding::snapshot(context.clone()),
        _ => RelayBinding::event(context.clone()),
    };
    Delivered {
        id: [0xa0 + u8::try_from(cursor).unwrap(); 16],
        binding: binding.canonical_bytes().unwrap(),
        anchor: HeadRecordAnchor {
            kind: if kind == RelayKind::Snapshot {
                RecordKind::Snapshot
            } else {
                RecordKind::Event
            },
            position: context.position(),
            id: context.id(),
            run: context.run(),
            ciphertext_digest: Sha256::digest(&ciphertext).into(),
        },
        ciphertext,
        cursor,
    }
}
fn event(world: &World, key: &ChatKey, signer: &RunnerSigningKey, sequence: u64) -> Delivered {
    let context = context(world, sequence, Some(RUN));
    let body = text(sequence, "hi ").canonical_bytes().unwrap();
    let sealed = seal_event(key, signer, context.clone(), &body).unwrap();
    deliver(&context, RelayKind::Event, sealed, sequence)
}
fn snapshot(world: &World, key: &ChatKey, sequence: u64) -> Delivered {
    let context = context(world, sequence, None);
    let body = CloudSnapshotPayload {
        control_revision: sequence,
        timestamp_ms: 1_000 + sequence,
        omitted_earlier: true,
        events: vec![text(1, "earlier ")],
    }
    .canonical_bytes()
    .unwrap();
    let sealed = seal_snapshot(key, &world.runner_signer, context.clone(), &body).unwrap();
    deliver(&context, RelayKind::Snapshot, sealed, sequence)
}
fn head(last: &Delivered, snapshot: Option<&Delivered>) -> ChatHead {
    ChatHead {
        chat_id: [0x05; 16],
        chat_key_epoch: 1,
        current_writer: Some(1),
        control_revision: last.cursor,
        deleted: false,
        head: Some(last.anchor.clone()),
        retained_from: snapshot.map_or(1, |s| s.anchor.position.sequence),
        snapshot: snapshot.map(|s| s.anchor.clone()),
    }
}
fn feed(
    reader: &mut ChatReader,
    record: &Delivered,
    key: &ChatKey,
) -> Result<AcceptedRecord, CloudDeviceError> {
    reader.record_header(&record.header())?;
    for chunk in record.ciphertext.chunks(7) {
        reader.record_data(chunk)?;
    }
    reader.record_end(&record.id, key)
}
/// A reader that witnessed `head` now.
fn witnessed(world: &World, head: ChatHead) -> ChatReader {
    let mut reader = ChatReader::new(&world.selector, &world.capabilities).unwrap();
    reader.witness(head, NOW).unwrap();
    reader
}
const CURRENT: RoundEnd = RoundEnd::Complete(Freshness::Current {
    witnessed_at_ms: NOW,
});
fn chain(world: &World, key: &ChatKey, count: u64) -> Vec<Delivered> {
    (1..=count)
        .map(|n| event(world, key, &world.runner_signer, n))
        .collect()
}

#[test]
fn records_in_order_from_the_pinned_runner_reach_the_witnessed_head() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 3);
    let mut reader = witnessed(&world, head(&records[2], None));
    for record in &records {
        feed(&mut reader, record, &key).unwrap();
    }
    assert_eq!(reader.page_end(3, false).unwrap(), CURRENT);
    assert_eq!(reader.cursor(), 3);
    assert_eq!(reader.transcript().rows().len(), 3);
    assert_eq!(reader.transcript().control_revision(), 3);
}

#[test]
fn a_page_with_more_records_continues_from_its_cursor() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 2);
    let mut reader = witnessed(&world, head(&records[1], None));
    feed(&mut reader, &records[0], &key).unwrap();
    assert_eq!(reader.page_end(1, true).unwrap(), RoundEnd::More);
    feed(&mut reader, &records[1], &key).unwrap();
    assert_eq!(reader.page_end(2, false).unwrap(), CURRENT);
}

#[test]
fn a_round_that_ends_below_the_witnessed_head_is_withheld_until_a_later_round_reaches_it() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 3);
    let mut reader = witnessed(&world, head(&records[2], None));
    feed(&mut reader, &records[0], &key).unwrap();
    feed(&mut reader, &records[1], &key).unwrap();
    assert_eq!(
        reader.page_end(2, false).unwrap(),
        RoundEnd::Complete(Freshness::Withheld {
            witnessed_at_ms: NOW
        })
    );
    assert_eq!(
        reader.transcript().rows().len(),
        2,
        "the verified prefix stays"
    );
    feed(&mut reader, &records[2], &key).unwrap();
    assert_eq!(reader.page_end(3, false).unwrap(), CURRENT);
}

#[test]
fn without_an_answer_the_records_are_an_unconfirmed_prefix() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 2);
    let mut reader = ChatReader::new(&world.selector, &world.capabilities).unwrap();
    reader.unanswered();
    for record in &records {
        feed(&mut reader, record, &key).unwrap();
    }
    assert_eq!(
        reader.page_end(2, false).unwrap(),
        RoundEnd::Complete(Freshness::Unconfirmed {
            last_witnessed_at_ms: None
        })
    );
    assert_eq!(reader.transcript().rows().len(), 2);
}

#[test]
fn a_reader_is_opening_until_its_first_round_and_never_opening_again() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 1);
    let mut reader = ChatReader::new(&world.selector, &world.capabilities).unwrap();
    assert_eq!(
        reader.freshness(),
        Freshness::Opening {
            last_witnessed_at_ms: None
        }
    );
    // A round without a witness or a probe confirms nothing: unconfirmed, not opening.
    feed(&mut reader, &records[0], &key).unwrap();
    let unconfirmed = Freshness::Unconfirmed {
        last_witnessed_at_ms: None,
    };
    assert_eq!(
        reader.page_end(1, false).unwrap(),
        RoundEnd::Complete(unconfirmed)
    );
    assert_eq!(
        reader.page_end(1, false).unwrap(),
        RoundEnd::Complete(unconfirmed)
    );
}

#[test]
fn watch_driven_rounds_after_a_current_read_stay_current() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 3);
    let mut reader = witnessed(&world, head(&records[0], None));
    feed(&mut reader, &records[0], &key).unwrap();
    assert_eq!(reader.page_end(1, false).unwrap(), CURRENT);
    feed(&mut reader, &records[1], &key).unwrap();
    feed(&mut reader, &records[2], &key).unwrap();
    assert_eq!(reader.page_end(3, false).unwrap(), CURRENT);
    assert_eq!(reader.sequence(), 3);
}

#[test]
fn another_record_at_the_witnessed_head_position_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 2);
    let other = event(&world, &key, &world.runner_signer, 2);
    let mut reader = witnessed(&world, head(&other, None));
    feed(&mut reader, &records[0], &key).unwrap();
    assert!(matches!(
        feed(&mut reader, &records[1], &key),
        Err(CloudDeviceError::Withheld)
    ));
}

#[test]
fn a_skipped_sequence_or_cursor_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 3);
    let mut reader = witnessed(&world, head(&records[2], None));
    feed(&mut reader, &records[0], &key).unwrap();
    assert!(matches!(
        reader.record_header(&records[2].header()),
        Err(CloudDeviceError::ReplayOrder)
    ));
    let mut reader = witnessed(&world, head(&records[2], None));
    feed(&mut reader, &records[0], &key).unwrap();
    let mut skipped = event(&world, &key, &world.runner_signer, 3);
    skipped.cursor = 2;
    assert!(matches!(
        reader.record_header(&skipped.header()),
        Err(CloudDeviceError::ReplayOrder)
    ));
}

#[test]
fn a_record_from_another_publisher_or_chat_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 1);
    let mut reader = witnessed(&world, head(&records[0], None));
    assert!(matches!(
        reader.record_header(&records[0].header_from(&[0x72; 32])),
        Err(CloudDeviceError::ReplaySource)
    ));
    let mut other = World::new();
    other.selector = ChatSelector::new(
        world.selector.scope().clone(),
        world.selector.runner(),
        [0x06; 16],
        1,
        world.selector.pins(),
    )
    .unwrap();
    let foreign = event(&other, &key, &world.runner_signer, 1);
    let mut reader = witnessed(&world, head(&records[0], None));
    assert!(matches!(
        reader.record_header(&foreign.header()),
        Err(CloudDeviceError::ReplaySource)
    ));
}

#[test]
fn a_truncated_or_altered_ciphertext_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 1);
    let mut reader = witnessed(&world, head(&records[0], None));
    reader.record_header(&records[0].header()).unwrap();
    let body = &records[0].ciphertext;
    reader.record_data(&body[..body.len() - 1]).unwrap();
    assert!(matches!(
        reader.record_end(&records[0].id, &key),
        Err(CloudDeviceError::ReplayIntegrity)
    ));
    reader.abandon();
    reader.record_header(&records[0].header()).unwrap();
    let mut altered = body.clone();
    altered[10] ^= 1;
    reader.record_data(&altered).unwrap();
    assert!(matches!(
        reader.record_end(&records[0].id, &key),
        Err(CloudDeviceError::ReplayIntegrity)
    ));
    assert!(matches!(
        reader.record_data(&altered),
        Err(CloudDeviceError::ReplayOrder)
    ));
}

#[test]
fn a_record_signed_by_another_runner_key_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let impostor = RunnerSigningKey::from_seed(&[0x52; 32]);
    let forged = event(&world, &key, &impostor, 1);
    let mut reader = witnessed(&world, head(&forged, None));
    assert!(matches!(
        feed(&mut reader, &forged, &key),
        Err(CloudDeviceError::Record(_))
    ));
    assert!(reader.transcript().rows().is_empty());
}

#[test]
fn a_gap_recovers_from_the_named_snapshot_and_continues() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let snap = snapshot(&world, &key, 4);
    let next = event(&world, &key, &world.runner_signer, 5);
    let mut reader = witnessed(&world, head(&next, Some(&snap)));
    let recovery = reader.gap(4, &snap.id).unwrap();
    assert_eq!(recovery.after_cursor, 3);
    let accepted = feed(&mut reader, &snap, &key).unwrap();
    assert!(accepted.restored);
    assert!(reader.transcript().omitted_earlier());
    feed(&mut reader, &next, &key).unwrap();
    assert_eq!(reader.page_end(5, false).unwrap(), CURRENT);
    assert_eq!(reader.transcript().rows().len(), 2);
    assert_eq!(reader.transcript().rows()[0].text, "earlier ");
}

#[test]
fn after_a_gap_only_the_named_snapshot_is_accepted_and_an_abandoned_recovery_resumes_its_cursor() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let snap = snapshot(&world, &key, 4);
    let next = event(&world, &key, &world.runner_signer, 5);
    let mut reader = witnessed(&world, head(&next, Some(&snap)));
    reader.gap(4, &[0xee; 16]).unwrap();
    assert!(matches!(
        reader.record_header(&snap.header()),
        Err(CloudDeviceError::SnapshotRequired)
    ));
    reader.abandon();
    assert_eq!(reader.cursor(), 0, "the gap's cursor is not kept");
    reader.gap(4, &snap.id).unwrap();
    let mut early = event(&world, &key, &world.runner_signer, 4);
    early.id = snap.id;
    assert!(matches!(
        reader.record_header(&early.header()),
        Err(CloudDeviceError::SnapshotRequired)
    ));
}

#[test]
fn a_gap_after_records_or_behind_the_cursor_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 2);
    let mut reader = witnessed(&world, head(&records[1], None));
    feed(&mut reader, &records[0], &key).unwrap();
    assert!(matches!(
        reader.gap(5, &[1; 16]),
        Err(CloudDeviceError::ReplayOrder)
    ));
    let mut reader = witnessed(&world, head(&records[1], None));
    assert!(matches!(
        reader.gap(1, &[1; 16]),
        Err(CloudDeviceError::ReplayOrder)
    ));
}

#[test]
fn a_head_for_another_generation_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 1);
    let mut stale = head(&records[0], None);
    stale.chat_key_epoch = 2;
    let mut reader = ChatReader::new(&world.selector, &world.capabilities).unwrap();
    assert!(matches!(
        reader.witness(stale, NOW),
        Err(CloudDeviceError::Withheld)
    ));
}

#[test]
fn a_checkpoint_restore_resumes_at_its_cursor_and_refuses_a_rollback() {
    let world = World::new();
    let keys = world.keys();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 3);
    let mut reader = witnessed(&world, head(&records[1], None));
    feed(&mut reader, &records[0], &key).unwrap();
    feed(&mut reader, &records[1], &key).unwrap();
    assert_eq!(reader.page_end(2, false).unwrap(), CURRENT);
    let checkpoint = reader.checkpoint(&world.selector, &keys).unwrap();

    let mut restored =
        ChatReader::restore(&world.selector, &world.capabilities, &keys, &checkpoint).unwrap();
    assert_eq!(restored.cursor(), 2);
    assert_eq!(restored.sequence(), 2);
    assert_eq!(restored.transcript().rows(), reader.transcript().rows());
    assert_eq!(
        restored.freshness(),
        Freshness::Opening {
            last_witnessed_at_ms: Some(NOW)
        }
    );
    // A restored transcript is shown whole first.
    assert!(restored.transcript_mut().take_delta().unwrap().reset);
    feed(&mut restored, &records[2], &key).unwrap();
    assert_eq!(restored.cursor(), 3);

    // A witness behind the verified position is a rollback.
    let mut again =
        ChatReader::restore(&world.selector, &world.capabilities, &keys, &checkpoint).unwrap();
    assert!(matches!(
        again.witness(head(&records[0], None), NOW),
        Err(CloudDeviceError::Rollback)
    ));
    let other = event(&world, &key, &world.runner_signer, 2);
    assert!(matches!(
        again.witness(head(&other, None), NOW),
        Err(CloudDeviceError::Rollback)
    ));
    let mut empty = head(&records[0], None);
    empty.head = None;
    assert!(matches!(
        again.witness(empty, NOW),
        Err(CloudDeviceError::Rollback)
    ));
    // The hub cannot replay an older record at the restored cursor either.
    assert!(matches!(
        again.record_header(&records[0].header()),
        Err(CloudDeviceError::ReplayOrder)
    ));
}

#[test]
fn a_checkpoint_opens_only_for_its_chat_and_account() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 1);
    let mut reader = witnessed(&world, head(&records[0], None));
    feed(&mut reader, &records[0], &key).unwrap();
    reader.page_end(1, false).unwrap();
    let checkpoint = reader.checkpoint(&world.selector, &world.keys()).unwrap();
    let other_chat = ChatSelector::new(
        world.selector.scope().clone(),
        world.selector.runner(),
        [0x06; 16],
        1,
        world.selector.pins(),
    )
    .unwrap();
    assert!(matches!(
        ChatReader::restore(&other_chat, &world.capabilities, &world.keys(), &checkpoint),
        Err(CloudDeviceError::CheckpointCrypto(_))
    ));
    let mut tampered = checkpoint.into_bytes();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        ChatReader::restore(
            &world.selector,
            &world.capabilities,
            &world.keys(),
            &VerifiedChat::from_bytes(tampered)
        ),
        Err(CloudDeviceError::CheckpointCrypto(_))
    ));
    // Mid-record there is no consistent state to seal.
    reader.record_header(&records[0].header()).ok();
    let mut busy = witnessed(&world, head(&records[0], None));
    busy.record_header(&records[0].header()).unwrap();
    assert!(matches!(
        busy.checkpoint(&world.selector, &world.keys()),
        Err(CloudDeviceError::Checkpoint)
    ));
}
