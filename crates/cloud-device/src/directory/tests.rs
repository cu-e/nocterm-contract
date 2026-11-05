#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::{merge::Catalog, merge::WitnessedChat, *};
use crate::testing::{NOW, World, hub::FakeHub};
use nocterm_hub_model::cloud::{
    ChatCoordinate, RecordKind, RecordPosition,
    head::{ChatHead, HeadRecordAnchor},
    summary::{ChatState, ChatSummary, SummaryContext, SummaryHead, SummaryHost},
};
use nocterm_keys::{
    AccountKeyPair,
    cloud::{RunnerEncryptionKey, RunnerSigningKey, seal_summary},
};

const CHAT: [u8; 16] = [0x05; 16];
const OTHER: [u8; 16] = [0x06; 16];

pub(crate) fn summary(title: &str, at_ms: i64, sequence: Option<u64>) -> ChatSummary {
    ChatSummary {
        head: sequence.map(|sequence| SummaryHead {
            sequence,
            ciphertext_digest: [u8::try_from(sequence).unwrap(); 32],
        }),
        control_revision: sequence.unwrap_or(0),
        created_at_ms: 1,
        last_activity_ms: at_ms,
        title: title.to_owned(),
        host: SummaryHost::Own,
        model: None,
        state: ChatState::Idle,
        pending_approvals: 0,
        servers: Vec::new(),
        features: 0,
    }
}
fn hub() -> FakeHub {
    FakeHub::new(World::with_directory())
}
fn directory(hub: &FakeHub) -> RunnerDirectory {
    let world = &hub.world;
    RunnerDirectory::new(world.hub.scope(), &world.runner, &world.capabilities).unwrap()
}
fn context(hub: &FakeHub, chat_id: [u8; 16], revision: u64) -> SummaryContext {
    let chat = hub.world.selector.coordinate().unwrap();
    let chat = ChatCoordinate::new(
        chat.namespace().clone(),
        chat.runner(),
        chat_id,
        chat.key_epoch(),
    )
    .unwrap();
    SummaryContext::new(chat, revision).unwrap()
}
fn delivered(header: &crate::flow::RecordHeader) -> DeliveredRecord<'_> {
    DeliveredRecord {
        publication_id: &header.publication_id,
        binding: &header.binding,
        total_bytes: header.total_bytes,
        ciphertext_sha256: &header.ciphertext_sha256,
        cursor: header.cursor,
        origin: crate::reader::DeliveredOrigin {
            account_id: &header.origin_account_id,
            signing_key: &header.origin_signing_key,
            runner_id: header.origin_runner_id.as_deref(),
        },
    }
}
/// Feeds the hub's directory records after the directory's cursor as one page.
fn round(
    hub: &FakeHub,
    directory: &mut RunnerDirectory,
) -> Result<Vec<RecordOutcome>, CloudDeviceError> {
    let keys = hub.world.keys();
    let mut outcomes = Vec::new();
    let after = directory.cursor();
    for (header, data) in hub.directory.iter().filter(|(h, _)| h.cursor > after) {
        directory.record_header(&delivered(header))?;
        directory.record_data(data)?;
        outcomes.push(directory.record_end(&header.publication_id, &keys)?);
    }
    directory.page_end(directory.cursor(), false)?;
    Ok(outcomes)
}
fn revision(directory: &RunnerDirectory, chat: [u8; 16]) -> u64 {
    directory.row(&chat).unwrap().summary().context().revision()
}

#[test]
fn a_round_applies_newer_summaries_across_cursor_holes() {
    let mut hub = hub();
    hub.summary(2, CHAT, 1, &summary("First", 10, None));
    hub.summary(5, OTHER, 1, &summary("Other", 20, None));
    hub.summary(9, CHAT, 2, &summary("First, renamed", 30, Some(1)));
    let mut directory = directory(&hub);
    let outcomes = round(&hub, &mut directory).unwrap();
    assert!(outcomes.iter().all(|o| matches!(o, RecordOutcome::Applied)));
    assert_eq!(directory.cursor(), 9);
    assert_eq!(revision(&directory, CHAT), 2);
    assert_eq!(directory.row(&CHAT).unwrap().cursor(), 9);
    assert_eq!(directory.rows().count(), 2);
    // Delivered again at a later cursor: the same summary changes nothing.
    let (_, sealed) = hub.directory[2].clone();
    hub.directory_record(12, &context(&hub, CHAT, 2), sealed);
    assert!(matches!(
        round(&hub, &mut directory).unwrap()[..],
        [RecordOutcome::Unchanged]
    ));
    assert_eq!(directory.cursor(), 12);
}

#[test]
fn an_older_revision_the_hub_replays_is_skipped_as_a_rollback() {
    let mut hub = hub();
    hub.summary(2, CHAT, 1, &summary("Old", 10, None));
    hub.summary(3, CHAT, 2, &summary("New", 20, Some(1)));
    let mut directory = directory(&hub);
    round(&hub, &mut directory).unwrap();
    let (_, old) = hub.directory[0].clone();
    hub.directory_record(4, &context(&hub, CHAT, 1), old);
    let outcomes = round(&hub, &mut directory).unwrap();
    assert!(matches!(
        outcomes[..],
        [RecordOutcome::Skipped(CloudDeviceError::Rollback)]
    ));
    assert_eq!(revision(&directory, CHAT), 2);
    assert_eq!(
        directory.cursor(),
        4,
        "the skipped record is not read again"
    );
}

#[test]
fn a_summary_not_from_the_pinned_runner_to_this_account_is_skipped() {
    let mut hub = hub();
    let signed = |signer: &RunnerSigningKey, revision| {
        signer
            .attest_summary(context(&hub, CHAT, revision), summary("x", 10, None))
            .unwrap()
    };
    let own = &hub.world.runner_signer;
    let account = hub.world.account_pair.public_key();
    let other_runner = RunnerEncryptionKey::from_seed(&[0x42; 32]);
    let other_signer = RunnerSigningKey::from_seed(&[0x52; 32]);
    let other_account = AccountKeyPair::generate().unwrap().public_key();
    let records = [
        seal_summary(&other_runner, &account, &signed(own, 1)).unwrap(),
        seal_summary(&hub.world.runner_key, &account, &signed(&other_signer, 2)).unwrap(),
        seal_summary(&hub.world.runner_key, &other_account, &signed(own, 3)).unwrap(),
        // Sealed for revision 4 but routed as revision 5.
        seal_summary(&hub.world.runner_key, &account, &signed(own, 4)).unwrap(),
    ];
    for (index, sealed) in records.into_iter().enumerate() {
        let revision = if index == 3 { 5 } else { index as u64 + 1 };
        hub.directory_record(index as u64 + 1, &context(&hub, CHAT, revision), sealed);
    }
    let mut directory = directory(&hub);
    let outcomes = round(&hub, &mut directory).unwrap();
    assert_eq!(outcomes.len(), 4);
    for outcome in outcomes {
        assert!(matches!(
            outcome,
            RecordOutcome::Skipped(CloudDeviceError::Summary(_))
        ));
    }
    assert!(directory.row(&CHAT).is_none());
    assert_eq!(directory.cursor(), 4);
}

#[test]
fn two_different_summaries_at_one_revision_keep_the_first() {
    let mut hub = hub();
    hub.summary(1, CHAT, 3, &summary("One", 10, None));
    hub.summary(2, CHAT, 3, &summary("Two", 10, None));
    let mut directory = directory(&hub);
    let outcomes = round(&hub, &mut directory).unwrap();
    assert!(matches!(
        outcomes[1],
        RecordOutcome::Skipped(CloudDeviceError::SummaryConflict)
    ));
    let held = directory.row(&CHAT).unwrap().summary().summary();
    assert_eq!(held.title, "One");
}

#[test]
fn a_record_routed_elsewhere_or_tampered_ends_the_round_without_moving_the_cursor() {
    let mut hub = hub();
    hub.summary(1, CHAT, 1, &summary("x", 10, None));
    let pristine = hub.directory.clone();
    let mut changes: Vec<fn(&mut FakeHub)> = vec![
        |hub| hub.directory[0].0.origin_signing_key = vec![0x72; 32],
        |hub| hub.directory[0].0.origin_runner_id = None,
        |hub| hub.directory[0].0.origin_account_id = "account-0002".to_owned(),
        |hub| *hub.directory[0].1.last_mut().unwrap() ^= 1,
        |hub| hub.directory[0].0.total_bytes = 100_000,
    ];
    for change in changes.drain(..) {
        hub.directory = pristine.clone();
        change(&mut hub);
        let mut directory = directory(&hub);
        assert!(round(&hub, &mut directory).is_err());
        assert_eq!(directory.cursor(), 0);
        directory.abandon();
        assert!(directory.idle());
    }
    // A binding of another runner generation.
    hub.directory = pristine;
    let chat = hub.world.selector.coordinate().unwrap();
    let elsewhere = ChatCoordinate::new(
        chat.namespace().clone(),
        nocterm_hub_model::cloud::RunnerCoordinate {
            id: chat.runner().id,
            key_epoch: chat.runner().key_epoch + 1,
        },
        CHAT,
        1,
    )
    .unwrap();
    let sealed = hub.directory[0].1.clone();
    hub.directory_record(1, &SummaryContext::new(elsewhere, 1).unwrap(), sealed);
    let mut directory = directory(&hub);
    assert!(matches!(
        round(&hub, &mut directory),
        Err(CloudDeviceError::ReplaySource)
    ));
}

#[test]
fn cursors_must_grow_pages_must_end_at_the_cursor_and_gaps_are_refused() {
    let mut hub = hub();
    hub.summary(4, CHAT, 1, &summary("x", 10, None));
    let mut directory = directory(&hub);
    round(&hub, &mut directory).unwrap();
    assert!(round(&hub, &mut directory).unwrap().is_empty());
    // The hub delivers cursor 4 again.
    assert!(matches!(
        directory.record_header(&delivered(&hub.directory[0].0)),
        Err(CloudDeviceError::ReplayOrder)
    ));
    let mut fresh = self::directory(&hub);
    fresh.page_end(0, false).unwrap();
    assert!(matches!(
        fresh.page_end(0, true),
        Err(CloudDeviceError::ReplayOrder)
    ));
    fresh.abandon();
    assert!(matches!(
        fresh.page_end(3, false),
        Err(CloudDeviceError::ReplayOrder)
    ));
    fresh.abandon();
    assert!(matches!(fresh.gap(), CloudDeviceError::ReplayOrder));
    assert!(!fresh.idle());
}

#[test]
fn a_checkpoint_restores_the_rows_and_cursor_only_for_its_runner_and_account() {
    let mut hub = hub();
    hub.summary(2, CHAT, 1, &summary("First", 10, None));
    hub.summary(7, OTHER, 4, &summary("Other", 20, Some(2)));
    let mut directory = directory(&hub);
    round(&hub, &mut directory).unwrap();
    let world = &hub.world;
    let keys = world.keys();
    let checkpoint = directory.checkpoint(world.hub.scope(), &keys).unwrap();
    let restored = RunnerDirectory::restore(
        world.hub.scope(),
        &world.runner,
        &world.capabilities,
        &keys,
        &checkpoint,
    )
    .unwrap();
    assert_eq!(restored.cursor(), 7);
    assert_eq!(
        restored.rows().collect::<Vec<_>>(),
        directory.rows().collect::<Vec<_>>()
    );
    let other = World::with_directory();
    assert!(
        RunnerDirectory::restore(
            world.hub.scope(),
            &world.runner,
            &world.capabilities,
            &other.keys(),
            &checkpoint
        )
        .is_err()
    );
    let moved = crate::records::TrustedRunner::new(
        nocterm_hub_model::cloud::RunnerCoordinate {
            id: [0x09; 16],
            key_epoch: 3,
        },
        world.runner.pins(),
        "Moved",
    )
    .unwrap();
    assert!(matches!(
        RunnerDirectory::restore(
            world.hub.scope(),
            &moved,
            &world.capabilities,
            &keys,
            &checkpoint
        ),
        Err(CloudDeviceError::CheckpointCrypto(_))
    ));
    let mut altered = checkpoint.into_bytes();
    *altered.last_mut().unwrap() ^= 1;
    assert!(
        RunnerDirectory::restore(
            world.hub.scope(),
            &world.runner,
            &world.capabilities,
            &keys,
            &VerifiedDirectory::from_bytes(altered)
        )
        .is_err()
    );
}

fn witnessed(chat_id: [u8; 16], sequence: Option<u64>, control_revision: u64) -> WitnessedChat {
    WitnessedChat {
        head: ChatHead {
            chat_id,
            chat_key_epoch: 1,
            current_writer: Some(1),
            control_revision,
            deleted: false,
            head: sequence.map(|sequence| HeadRecordAnchor {
                kind: RecordKind::Event,
                position: RecordPosition {
                    writer_epoch: 1,
                    sequence,
                    journal_sequence: sequence,
                    revision: sequence,
                },
                id: [1; 16],
                run: None,
                ciphertext_digest: [u8::try_from(sequence).unwrap(); 32],
            }),
            retained_from: 1,
            snapshot: None,
        },
        at_ms: NOW,
    }
}

#[test]
fn rows_merge_summaries_with_the_catalog_witness() {
    let mut hub = hub();
    let third = [0x07; 16];
    hub.summary(1, CHAT, 1, &summary("Current", 10, Some(2)));
    hub.summary(2, OTHER, 1, &summary("Behind", 30, Some(1)));
    hub.summary(3, third, 1, &summary("Gone", 20, None));
    let mut directory = directory(&hub);
    round(&hub, &mut directory).unwrap();
    let runner = hub.world.runner.runner().id;
    let bare = [0x08; 16];
    let chats = [
        witnessed(CHAT, Some(2), 2),
        witnessed(OTHER, Some(3), 3),
        witnessed(bare, None, 0),
    ];
    let status = |rows: &[ListedChat]| -> Vec<(u8, RowStatus)> {
        rows.iter().map(|r| (r.chat.chat_id[0], r.status)).collect()
    };
    let rows = merge::merge(
        runner,
        Some(&directory),
        Catalog::Answered {
            chats: &chats,
            complete: true,
        },
    );
    assert_eq!(
        status(&rows),
        [
            (0x06, RowStatus::Stale),
            (0x07, RowStatus::Unlisted),
            (0x05, RowStatus::Current),
            (0x08, RowStatus::Unsummarized),
        ],
        "summaries newest first, then witnessed chats without one"
    );
    assert_eq!(rows[0].head_sequence, Some(3), "witnessed fields win");
    assert_eq!(rows[0].summary.as_ref().unwrap().title, "Behind");
    assert_eq!(rows[1].witnessed_at_ms, None);
    let rows = merge::merge(
        runner,
        Some(&directory),
        Catalog::Answered {
            chats: &chats,
            complete: false,
        },
    );
    assert_eq!(rows[1].status, RowStatus::AsOf);
    let pending = merge::merge(runner, Some(&directory), Catalog::Pending);
    assert!(pending.iter().all(|row| row.status == RowStatus::Pending));
    let asleep = merge::merge(runner, Some(&directory), Catalog::Unanswered);
    assert!(asleep.iter().all(|row| row.status == RowStatus::AsOf));
    assert_eq!(asleep.len(), 3);
    // A summary ahead of the witness is current; another digest at its sequence is not.
    let ahead = [witnessed(CHAT, Some(1), 1)];
    let rows = merge::merge(
        runner,
        Some(&directory),
        Catalog::Answered {
            chats: &ahead,
            complete: false,
        },
    );
    assert_eq!(
        rows.iter().find(|r| r.chat.chat_id == CHAT).unwrap().status,
        RowStatus::Current
    );
    let mut forked = witnessed(CHAT, Some(2), 2);
    forked.head.head.as_mut().unwrap().ciphertext_digest = [9; 32];
    let rows = merge::merge(
        runner,
        Some(&directory),
        Catalog::Answered {
            chats: &[forked],
            complete: false,
        },
    );
    assert_eq!(
        rows.iter().find(|r| r.chat.chat_id == CHAT).unwrap().status,
        RowStatus::Stale
    );
}
