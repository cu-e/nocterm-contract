#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::{
    flow::{InstanceEntry, InstanceState},
    testing::{
        NOW, World,
        hub::{Ended, FakeHub},
    },
};

fn seat(hub: &mut FakeHub, state: InstanceState) {
    hub.instances.push(InstanceEntry {
        instance_id: "seat-1".to_owned(),
        agent_id: "agent-1".to_owned(),
        pool_id: "pool-1".to_owned(),
        runner_id: Some([0x02; 16]),
        state,
    });
}
fn managed(hub: &FakeHub, chat_id: Option<[u8; 16]>) -> CreateChat {
    CreateChat::new(
        hub.world.session(),
        hub.world.device.clone(),
        ChatHost::Managed {
            agent_id: "agent-1".to_owned(),
        },
        chat_id,
    )
    .unwrap()
}
fn count(hub: &FakeHub, effect: &str) -> usize {
    hub.effects.iter().filter(|e| **e == effect).count()
}

#[test]
fn a_managed_chat_starts_its_seat_stores_its_records_and_waits_for_the_claim() {
    let mut hub = FakeHub::new(World::new());
    seat(&mut hub, InstanceState::Ready);
    hub.awake = false;
    let mut flow = managed(&hub, None);
    let (created, ended) = hub.run(&mut flow, NOW);
    assert!(created.is_empty());
    assert!(matches!(ended, Ended::Idle(Some(at)) if at == NOW + CLAIM_RETRY_MS));
    assert_eq!(hub.effects[..2], ["list_instances", "start_instance"]);
    assert_eq!(count(&hub, "create_collection"), 2, "material and grant");
    assert_eq!(count(&hub, "put_object"), 2);
    assert_eq!(hub.published.len(), 1);
    // Probes every second, republishes the same grant every 15 seconds.
    for second in 1..=15 {
        hub.run(&mut flow, NOW + second * CLAIM_RETRY_MS);
    }
    assert_eq!(hub.published.len(), 2);
    assert_eq!(
        hub.published[0].publication_id(),
        hub.published[1].publication_id()
    );
    assert_eq!(hub.published[0].ciphertext(), hub.published[1].ciphertext());
    hub.awake = true;
    let (created, ended) = hub.run(&mut flow, NOW + 16 * CLAIM_RETRY_MS);
    assert!(matches!(ended, Ended::Done));
    assert_eq!(created[0].chat.chat_id, flow.chat_id());
    assert_eq!(created[0].chat.runner, [0x02; 16]);
    assert_eq!(created[0].instance_id.as_deref(), Some("seat-1"));
}

#[test]
fn a_runner_that_never_claims_the_chat_gives_up_after_a_minute() {
    let mut hub = FakeHub::new(World::new());
    seat(&mut hub, InstanceState::Ready);
    hub.awake = false;
    let mut flow = managed(&hub, None);
    hub.run(&mut flow, NOW);
    let (_, ended) = hub.run(&mut flow, NOW + CLAIM_PATIENCE_MS);
    assert!(matches!(ended, Ended::Failed(CloudDeviceError::NotClaimed)));
}

#[test]
fn a_retry_with_the_same_chat_id_uses_the_stored_records_and_the_same_publication() {
    let mut hub = FakeHub::new(World::new());
    seat(&mut hub, InstanceState::Ready);
    let mut first = managed(&hub, None);
    let (created, _) = hub.run(&mut first, NOW);
    assert_eq!(created.len(), 1);
    let puts = count(&hub, "put_object");
    let mut again = managed(&hub, Some(first.chat_id()));
    let (created, ended) = hub.run(&mut again, NOW + 1);
    assert!(matches!(ended, Ended::Done));
    assert_eq!(created.len(), 1);
    assert_eq!(count(&hub, "put_object"), puts, "nothing sealed twice");
    let last = hub.published.last().unwrap();
    assert_eq!(hub.published[0].publication_id(), last.publication_id());
    assert_eq!(hub.published[0].ciphertext(), last.ciphertext());
}

#[test]
fn a_material_stored_without_its_grant_gets_a_grant_for_the_same_key() {
    let mut hub = FakeHub::new(World::new());
    seat(&mut hub, InstanceState::Ready);
    let mut first = managed(&hub, None);
    hub.run(&mut first, NOW);
    let grants =
        crate::records::account_collection_id(hub.world.selector.scope(), CHAT_GRANT_KIND).unwrap();
    hub.objects.retain(|object| object.collection_id != grants);
    let published = hub.published.len();
    let mut again = managed(&hub, Some(first.chat_id()));
    let (created, _) = hub.run(&mut again, NOW + 1);
    assert_eq!(created.len(), 1);
    assert_eq!(hub.published.len(), published + 1);
    assert_ne!(
        hub.published[0].publication_id(),
        hub.published.last().unwrap().publication_id()
    );
}

#[test]
fn a_seat_without_an_enrolled_runner_or_an_untrusted_runner_is_refused() {
    let mut hub = FakeHub::new(World::new());
    seat(&mut hub, InstanceState::AwaitingEnrolment);
    let mut flow = managed(&hub, None);
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(
        ended,
        Ended::Failed(CloudDeviceError::NotEnrolled)
    ));
    assert!(
        !hub.effects.contains(&"start_instance"),
        "a chat never provisions a seat"
    );
    let mut hub = FakeHub::new(World::new());
    let (_, ended) = hub.run(&mut managed(&hub, None), NOW);
    assert!(matches!(
        ended,
        Ended::Failed(CloudDeviceError::NotEnrolled)
    ));
    assert_eq!(hub.effects, ["list_instances"]);

    let mut hub = FakeHub::new(World::new());
    let mut flow = CreateChat::new(
        hub.world.session(),
        hub.world.device.clone(),
        ChatHost::Own { runner: [9; 16] },
        None,
    )
    .unwrap();
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Failed(CloudDeviceError::NoRunner)));
    assert!(
        hub.effects.contains(&"get_collection_key"),
        "the registry was read again"
    );
}
