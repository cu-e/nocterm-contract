#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::testing::{
    NOW, World,
    hub::{Ended, FakeHub},
};

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
    assert_eq!(chats[0].witnessed_at_ms, NOW);
    assert!(!hub.effects.contains(&"replay"), "listing never replays");

    hub.awake = false;
    let mut flow = ListChats::new(hub.world.session(), hub.world.device.clone());
    let (updates, _) = hub.run(&mut flow, NOW);
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, ChatListUpdate::Unreachable { reason: None, .. }))
    );
}
