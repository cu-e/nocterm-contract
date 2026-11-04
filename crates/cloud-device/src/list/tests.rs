#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::{
    context::ChatRef,
    directory::tests::summary,
    testing::{
        NOW, World,
        hub::{Ended, FakeHub},
    },
};

const OTHER: [u8; 16] = [0x06; 16];

fn runners(updates: &[ChatListUpdate]) -> Vec<&Vec<ListedChat>> {
    updates
        .iter()
        .filter_map(|update| match update {
            ChatListUpdate::Runner { chats, .. } => Some(chats),
            _ => None,
        })
        .collect()
}
fn checkpoints(updates: &[ChatListUpdate]) -> Vec<VerifiedDirectory> {
    updates
        .iter()
        .filter_map(|update| match update {
            ChatListUpdate::Directory { checkpoint, .. } => Some(checkpoint.clone()),
            _ => None,
        })
        .collect()
}
fn statuses(rows: &[ListedChat]) -> Vec<RowStatus> {
    rows.iter().map(|row| row.status).collect()
}

#[test]
fn every_runner_reports_its_witnessed_catalog_or_that_it_did_not_answer() {
    let mut hub = FakeHub::new(World::new());
    let mut flow = ListChats::new(hub.world.session(), hub.world.device.clone());
    let (updates, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Done));
    assert!(matches!(&updates[0], ChatListUpdate::Seats(seats) if seats.is_empty()));
    let ChatListUpdate::Runner {
        chats, complete, ..
    } = &updates[1]
    else {
        panic!("a catalog");
    };
    assert!(complete);
    assert_eq!(chats[0].chat, ChatRef::of(&hub.world.selector));
    assert_eq!(chats[0].head_sequence, None);
    assert_eq!(chats[0].witnessed_at_ms, Some(NOW));
    assert_eq!(chats[0].status, RowStatus::Unsummarized);
    assert!(chats[0].summary.is_none());
    assert!(!hub.effects.contains(&"replay"), "listing never replays");
    assert!(
        !hub.effects.contains(&"directory_replay"),
        "a hub without bit 256 has no directory"
    );

    hub.awake = false;
    let mut flow = ListChats::new(hub.world.session(), hub.world.device.clone());
    let (updates, _) = hub.run(&mut flow, NOW);
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, ChatListUpdate::Unreachable { reason: None, .. }))
    );
    assert!(runners(&updates).is_empty());
}

#[test]
fn directory_rows_show_first_and_the_catalog_then_confirms_them() {
    let mut hub = FakeHub::new(World::with_directory());
    let chat = hub.world.selector.chat_id();
    hub.summary(2, chat, 1, &summary("Fix the build", 20, None));
    hub.summary(6, OTHER, 1, &summary("Retired chat", 10, None));
    let mut flow = ListChats::new(hub.world.session(), hub.world.device.clone());
    let (updates, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Done));
    let rows = runners(&updates);
    let last = rows.last().unwrap();
    assert_eq!(statuses(last), [RowStatus::Current, RowStatus::Unlisted]);
    assert_eq!(last[0].summary.as_ref().unwrap().title, "Fix the build");
    assert_eq!(last[0].witnessed_at_ms, Some(NOW));
    if rows.len() == 2 {
        assert!(rows[0].iter().all(|row| row.status == RowStatus::Pending));
    }
    assert_eq!(checkpoints(&updates).len(), 1);
    assert_eq!(hub.directory_from, [0]);
    assert!(!hub.effects.contains(&"replay"), "rows are never replayed");
}

#[test]
fn a_sleeping_runner_keeps_its_summaries_as_of_their_last_activity() {
    let mut hub = FakeHub::new(World::with_directory());
    hub.awake = false;
    let chat = hub.world.selector.chat_id();
    hub.summary(1, chat, 1, &summary("Asleep", 20, None));
    let mut flow = ListChats::new(hub.world.session(), hub.world.device.clone());
    let (updates, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Done));
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, ChatListUpdate::Unreachable { reason: None, .. }))
    );
    let last = *runners(&updates).last().unwrap();
    assert_eq!(statuses(last), [RowStatus::AsOf]);
    assert_eq!(last[0].witnessed_at_ms, None);
}

#[test]
fn a_listing_resumes_at_the_directory_checkpoint_and_reports_refusals() {
    let mut hub = FakeHub::new(World::with_directory());
    let chat = hub.world.selector.chat_id();
    hub.summary(2, chat, 1, &summary("First", 20, None));
    let mut flow = ListChats::new(hub.world.session(), hub.world.device.clone());
    let (updates, _) = hub.run(&mut flow, NOW);
    let stored = checkpoints(&updates);

    hub.summary(3, chat, 2, &summary("First, renamed", 25, Some(1)));
    // The hub replays the first summary at a later cursor.
    let (header, older) = hub.directory[0].clone();
    let routing =
        nocterm_hub_model::cloud::relay::RelayBinding::from_canonical_bytes(&header.binding)
            .unwrap();
    hub.directory_record(4, routing.summary_context().unwrap(), older);
    hub.summary(5, OTHER, 1, &summary("Second", 30, None));
    let mut flow =
        ListChats::new(hub.world.session(), hub.world.device.clone()).with_directories(&stored);
    let (updates, _) = hub.run(&mut flow, NOW);
    assert_eq!(hub.directory_from, [0, 2], "only what is new is read");
    let last = *runners(&updates).last().unwrap();
    assert_eq!(last.len(), 2);
    assert_eq!(last[0].summary.as_ref().unwrap().title, "Second");
    assert_eq!(last[1].summary.as_ref().unwrap().title, "First, renamed");
    assert!(updates.iter().any(|u| matches!(
        u,
        ChatListUpdate::DirectoryRefused {
            reason: CloudDeviceError::Rollback,
            ..
        }
    )));
}

#[test]
fn a_watching_listing_reads_new_summaries_on_a_hint_and_never_ends() {
    let mut hub = FakeHub::new(World::with_directory());
    let chat = hub.world.selector.chat_id();
    hub.summary(1, chat, 1, &summary("First", 20, None));
    let mut flow = ListChats::new(hub.world.session(), hub.world.device.clone()).watching();
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Idle(None)));
    assert!(hub.effects.contains(&"watch"));

    hub.summary(3, chat, 2, &summary("First, then more", 40, Some(1)));
    hub.hint_directory(&mut flow);
    let (updates, ended) = hub.run(&mut flow, NOW + 1);
    assert!(matches!(ended, Ended::Idle(None)));
    let last = *runners(&updates).last().unwrap();
    assert_eq!(last[0].summary.as_ref().unwrap().title, "First, then more");
    assert_eq!(last[0].status, RowStatus::Current, "newer than the witness");
    assert_eq!(hub.directory_from, [0, 1]);
    assert_eq!(checkpoints(&updates).len(), 1);
    let probes = hub.effects.iter().filter(|e| **e == "probe").count();
    assert_eq!(probes, 1, "the catalog is not probed again");
}
