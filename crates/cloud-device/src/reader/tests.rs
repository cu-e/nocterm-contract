#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::testing::World;
use nocterm_hub_model::cloud::{
    RecordContext, RecordPosition, RunCoordinate,
    events::{CloudEventPayload, CloudTextChannel},
};
use nocterm_keys::cloud::{RunnerSigningKey, seal_event, seal_snapshot};
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
    replay: &mut ChatReplay,
    record: &Delivered,
    key: &ChatKey,
    transcript: &mut Transcript,
) -> Result<AcceptedRecord, CloudDeviceError> {
    replay.record_header(&record.header())?;
    for chunk in record.ciphertext.chunks(7) {
        replay.record_data(chunk)?;
    }
    replay.record_end(&record.id, key, transcript)
}
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
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[2], None),
        &world.capabilities,
    )
    .unwrap();
    let mut transcript = Transcript::new();
    for record in &records {
        feed(&mut replay, record, &key, &mut transcript).unwrap();
    }
    assert_eq!(replay.page_end(3, false).unwrap(), PageEnd::Complete);
    assert_eq!(replay.cursor(), 3);
    assert_eq!(transcript.rows().len(), 3);
    assert_eq!(transcript.control_revision(), 3);
}

#[test]
fn a_page_with_more_records_continues_from_its_cursor() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 2);
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[1], None),
        &world.capabilities,
    )
    .unwrap();
    let mut transcript = Transcript::new();
    feed(&mut replay, &records[0], &key, &mut transcript).unwrap();
    assert_eq!(replay.page_end(1, true).unwrap(), PageEnd::More);
    feed(&mut replay, &records[1], &key, &mut transcript).unwrap();
    assert_eq!(replay.page_end(2, false).unwrap(), PageEnd::Complete);
}

#[test]
fn a_replay_that_ends_before_the_witnessed_head_is_withheld() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 3);
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[2], None),
        &world.capabilities,
    )
    .unwrap();
    let mut transcript = Transcript::new();
    feed(&mut replay, &records[0], &key, &mut transcript).unwrap();
    feed(&mut replay, &records[1], &key, &mut transcript).unwrap();
    assert!(matches!(
        replay.page_end(2, false),
        Err(CloudDeviceError::Withheld)
    ));
}

#[test]
fn another_record_at_the_witnessed_head_position_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 2);
    let other = event(&world, &key, &world.runner_signer, 2);
    let mut replay =
        ChatReplay::new(&world.selector, head(&other, None), &world.capabilities).unwrap();
    let mut transcript = Transcript::new();
    feed(&mut replay, &records[0], &key, &mut transcript).unwrap();
    assert!(matches!(
        feed(&mut replay, &records[1], &key, &mut transcript),
        Err(CloudDeviceError::Withheld)
    ));
}

#[test]
fn a_skipped_sequence_or_cursor_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 3);
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[2], None),
        &world.capabilities,
    )
    .unwrap();
    let mut transcript = Transcript::new();
    feed(&mut replay, &records[0], &key, &mut transcript).unwrap();
    assert!(matches!(
        replay.record_header(&records[2].header()),
        Err(CloudDeviceError::ReplayOrder)
    ));
    // The same record under the next cursor still skips a sequence.
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[2], None),
        &world.capabilities,
    )
    .unwrap();
    feed(&mut replay, &records[0], &key, &mut transcript).unwrap();
    let mut skipped = event(&world, &key, &world.runner_signer, 3);
    skipped.cursor = 2;
    assert!(matches!(
        replay.record_header(&skipped.header()),
        Err(CloudDeviceError::ReplayOrder)
    ));
}

#[test]
fn a_record_from_another_publisher_or_chat_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 1);
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[0], None),
        &world.capabilities,
    )
    .unwrap();
    assert!(matches!(
        replay.record_header(&records[0].header_from(&[0x72; 32])),
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
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[0], None),
        &world.capabilities,
    )
    .unwrap();
    assert!(matches!(
        replay.record_header(&foreign.header()),
        Err(CloudDeviceError::ReplaySource)
    ));
}

#[test]
fn a_truncated_or_altered_ciphertext_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 1);
    let mut transcript = Transcript::new();
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[0], None),
        &world.capabilities,
    )
    .unwrap();
    replay.record_header(&records[0].header()).unwrap();
    let body = &records[0].ciphertext;
    replay.record_data(&body[..body.len() - 1]).unwrap();
    assert!(matches!(
        replay.record_end(&records[0].id, &key, &mut transcript),
        Err(CloudDeviceError::ReplayIntegrity)
    ));
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[0], None),
        &world.capabilities,
    )
    .unwrap();
    replay.record_header(&records[0].header()).unwrap();
    let mut altered = body.clone();
    altered[10] ^= 1;
    replay.record_data(&altered).unwrap();
    assert!(matches!(
        replay.record_end(&records[0].id, &key, &mut transcript),
        Err(CloudDeviceError::ReplayIntegrity)
    ));
    assert!(matches!(
        replay.record_data(&altered),
        Err(CloudDeviceError::ReplayOrder)
    ));
}

#[test]
fn a_record_signed_by_another_runner_key_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let impostor = RunnerSigningKey::from_seed(&[0x52; 32]);
    let forged = event(&world, &key, &impostor, 1);
    let mut replay =
        ChatReplay::new(&world.selector, head(&forged, None), &world.capabilities).unwrap();
    let mut transcript = Transcript::new();
    assert!(matches!(
        feed(&mut replay, &forged, &key, &mut transcript),
        Err(CloudDeviceError::Record(_))
    ));
    assert!(transcript.rows().is_empty());
}

#[test]
fn a_gap_recovers_from_the_named_snapshot_and_continues() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let snap = snapshot(&world, &key, 4);
    let next = event(&world, &key, &world.runner_signer, 5);
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&next, Some(&snap)),
        &world.capabilities,
    )
    .unwrap();
    let recovery = replay.gap(4, &snap.id).unwrap();
    assert_eq!(recovery.after_cursor, 3);
    let mut transcript = Transcript::new();
    let accepted = feed(&mut replay, &snap, &key, &mut transcript).unwrap();
    assert!(accepted.restored);
    assert!(transcript.omitted_earlier());
    feed(&mut replay, &next, &key, &mut transcript).unwrap();
    assert_eq!(replay.page_end(5, false).unwrap(), PageEnd::Complete);
    assert_eq!(transcript.rows().len(), 2);
    assert_eq!(transcript.rows()[0].text, "earlier ");
}

#[test]
fn after_a_gap_only_the_named_snapshot_is_accepted() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let snap = snapshot(&world, &key, 4);
    let next = event(&world, &key, &world.runner_signer, 5);
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&next, Some(&snap)),
        &world.capabilities,
    )
    .unwrap();
    replay.gap(4, &[0xee; 16]).unwrap();
    assert!(matches!(
        replay.record_header(&snap.header()),
        Err(CloudDeviceError::SnapshotRequired)
    ));
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&next, Some(&snap)),
        &world.capabilities,
    )
    .unwrap();
    replay.gap(4, &snap.id).unwrap();
    let mut early = event(&world, &key, &world.runner_signer, 4);
    early.id = snap.id;
    assert!(matches!(
        replay.record_header(&early.header()),
        Err(CloudDeviceError::SnapshotRequired)
    ));
}

#[test]
fn a_gap_after_records_or_behind_the_cursor_is_refused() {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let records = chain(&world, &key, 2);
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[1], None),
        &world.capabilities,
    )
    .unwrap();
    let mut transcript = Transcript::new();
    feed(&mut replay, &records[0], &key, &mut transcript).unwrap();
    assert!(matches!(
        replay.gap(5, &[1; 16]),
        Err(CloudDeviceError::ReplayOrder)
    ));
    let mut replay = ChatReplay::new(
        &world.selector,
        head(&records[1], None),
        &world.capabilities,
    )
    .unwrap();
    assert!(matches!(
        replay.gap(1, &[1; 16]),
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
    assert!(matches!(
        ChatReplay::new(&world.selector, stale, &world.capabilities),
        Err(CloudDeviceError::Withheld)
    ));
}
