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
use nocterm_hub_model::cloud::RunCoordinate;

fn delivery(hub: &FakeHub, wake: Option<&str>) -> Deliver {
    let world = &hub.world;
    let command = UnsignedCommand::prepare(
        &world.selector,
        world.account_public(),
        &world.device,
        super::super::CommandAction::Stop {
            run: RunCoordinate {
                id: [0x21; 16],
                expected_epoch: 1,
            },
        },
        4,
        NOW,
    )
    .unwrap();
    Deliver::new(
        world.session(),
        world.device.clone(),
        world.selector.clone(),
        command,
        wake.map(str::to_owned),
    )
}
fn unknown(hub: &mut FakeHub, times: usize) {
    for _ in 0..times {
        hub.publish.push_back(Input::Failed(EffectFailure::Unknown));
    }
}
fn same_bytes(hub: &FakeHub) -> bool {
    hub.published.windows(2).all(|pair| {
        pair[0].publication_id() == pair[1].publication_id()
            && pair[0].binding().unwrap() == pair[1].binding().unwrap()
            && pair[0].ciphertext() == pair[1].ciphertext()
    })
}

#[test]
fn an_unknown_outcome_retries_identical_bytes_and_asks_the_runner_for_a_receipt() {
    let mut hub = FakeHub::new(World::new());
    unknown(&mut hub, 3);
    let mut flow = delivery(&hub, None);
    let (updates, ended) = hub.run(&mut flow, NOW);
    assert!(updates.is_empty());
    assert!(matches!(ended, Ended::Idle(Some(at)) if at == NOW + 1_000));
    hub.run(&mut flow, NOW + 1_000);
    hub.run(&mut flow, NOW + 3_000);
    assert_eq!(hub.published.len(), 3);
    assert!(!hub.effects.contains(&"probe"));
    // The third unknown outcome asks the runner; it has not seen the command, so the same
    // publication goes out again and is delivered.
    let (updates, ended) = hub.run(&mut flow, NOW + 7_000);
    assert!(hub.effects.contains(&"probe"));
    assert!(matches!(ended, Ended::Done));
    assert_eq!(hub.published.len(), 4);
    assert!(same_bytes(&hub));
    assert_eq!(
        updates,
        [DeliveryUpdate {
            command_id: flow.command_id(),
            state: CommandState::Delivered,
            cursor: Some(4),
        }]
    );
    assert_eq!(
        hub.effects
            .iter()
            .filter(|effect| **effect == "sign")
            .count(),
        2,
        "the command is signed once; the receipt probe once"
    );
}

#[test]
fn a_receipt_that_the_runner_admitted_the_command_settles_it_accepted() {
    let mut hub = FakeHub::new(World::new());
    unknown(&mut hub, 3);
    hub.receipt = ReceiptOutcome::Accepted {
        control_revision: 5,
    };
    let mut flow = delivery(&hub, None);
    for at in [NOW, NOW + 1_000, NOW + 3_000] {
        hub.run(&mut flow, at);
    }
    let (updates, ended) = hub.run(&mut flow, NOW + 7_000);
    assert!(matches!(ended, Ended::Done));
    assert_eq!(updates[0].state, CommandState::Accepted);
    assert_eq!(hub.published.len(), 3, "no publication after the receipt");
}

#[test]
fn a_conflict_or_a_refusal_settles_it_refused() {
    let mut hub = FakeHub::new(World::new());
    unknown(&mut hub, 3);
    hub.receipt = ReceiptOutcome::Conflict;
    let mut flow = delivery(&hub, None);
    for at in [NOW, NOW + 1_000, NOW + 3_000] {
        hub.run(&mut flow, at);
    }
    let (updates, _) = hub.run(&mut flow, NOW + 7_000);
    assert_eq!(updates[0].state, CommandState::Refused);

    let mut hub = FakeHub::new(World::new());
    hub.publish.push_back(Input::Failed(EffectFailure::Refused));
    let mut flow = delivery(&hub, None);
    let (updates, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Done));
    assert_eq!(updates[0].state, CommandState::Refused);
}

#[test]
fn a_command_whose_window_ends_unanswered_is_unreachable() {
    let mut hub = FakeHub::new(World::new());
    unknown(&mut hub, 1);
    let mut flow = delivery(&hub, None);
    hub.run(&mut flow, NOW);
    let (updates, ended) = hub.run(&mut flow, NOW + super::super::CONTROL_LIFETIME_MS);
    assert!(matches!(ended, Ended::Done));
    assert_eq!(updates[0].state, CommandState::Unreachable);
}

#[test]
fn a_managed_seat_is_woken_first_and_a_refusal_to_wake_does_not_stop_delivery() {
    let mut hub = FakeHub::new(World::new());
    hub.instances.push(InstanceEntry {
        instance_id: "i-1".to_owned(),
        agent_id: "agent".to_owned(),
        pool_id: "pool-1".to_owned(),
        runner_id: Some([0x02; 16]),
        state: InstanceState::Suspended,
    });
    let mut flow = delivery(&hub, Some("agent"));
    let (updates, _) = hub.run(&mut flow, NOW);
    assert_eq!(hub.effects[..2], ["list_instances", "start_instance"]);
    assert_eq!(updates[0].state, CommandState::Delivered);
    let mut hub = FakeHub::new(World::new());
    let mut flow = delivery(&hub, Some("unknown agent"));
    let (updates, _) = hub.run(&mut flow, NOW);
    assert_eq!(updates[0].state, CommandState::Delivered);
}

#[test]
fn a_signature_by_another_key_fails_before_anything_is_published() {
    let hub = FakeHub::new(World::new());
    let mut flow = delivery(&hub, None);
    let crate::flow::Step::Effect(id, Effect::Sign(_)) = flow.next(NOW) else {
        panic!("a signature first");
    };
    flow.resolve(id, Input::Signature(vec![7; 64]));
    assert!(matches!(
        flow.next(NOW),
        crate::flow::Step::Failed(CloudDeviceError::Signature(_))
    ));
}
