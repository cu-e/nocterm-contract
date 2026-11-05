#![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
use super::*;
use crate::{
    flow::EffectFailure,
    testing::{
        NOW, World,
        hub::{Ended, FakeHub},
    },
};

fn seat(id: &str, agent: &str, pool: &str, state: InstanceState) -> InstanceEntry {
    InstanceEntry {
        instance_id: id.to_owned(),
        agent_id: agent.to_owned(),
        pool_id: pool.to_owned(),
        runner_id: Some([0x02; 16]),
        state,
    }
}

#[test]
fn the_hosting_seat_is_the_agents_enrolled_one_and_a_ready_seat_comes_first() {
    let seats = [
        seat("other", "agent-2", "pool-2", InstanceState::Ready),
        seat("gone", "agent-1", "pool-0", InstanceState::Deleting),
        seat("asleep", "agent-1", "pool-1", InstanceState::Suspended),
        seat("ready", "agent-1", "pool-3", InstanceState::Ready),
    ];
    assert_eq!(
        hosting_seat(&seats, "agent-1").unwrap().instance_id,
        "ready"
    );
    assert_eq!(
        hosting_seat(&seats[..3], "agent-1").unwrap().instance_id,
        "asleep"
    );
    let mut unenrolled = seat("new", "agent-1", "pool-1", InstanceState::Ready);
    unenrolled.runner_id = None;
    let waiting = seat(
        "wait",
        "agent-1",
        "pool-1",
        InstanceState::AwaitingEnrolment,
    );
    let poolless = seat("odd", "agent-1", "", InstanceState::Ready);
    assert!(hosting_seat(&[unenrolled, waiting, poolless], "agent-1").is_none());
}

#[test]
fn a_wake_starts_exactly_the_pool_of_the_enrolled_seat_for_the_chat() {
    let seats = [seat("s", "agent-1", "pool-7", InstanceState::Suspended)];
    let Effect::StartInstance {
        agent_id,
        pool_id,
        chat_id,
    } = start(&seats, "agent-1", Some([0xab; 16])).unwrap()
    else {
        panic!("a start");
    };
    assert_eq!((agent_id.as_str(), pool_id.as_str()), ("agent-1", "pool-7"));
    assert_eq!(chat_id, Some("ab".repeat(16)));
    assert!(matches!(
        start(&seats, "agent-2", None),
        Err(CloudDeviceError::NotEnrolled)
    ));
}

#[test]
fn wake_seat_outputs_the_started_seat_or_refuses_an_agent_without_one() {
    let mut hub = FakeHub::new(World::new());
    hub.instances
        .push(seat("s", "agent-1", "pool-1", InstanceState::Suspended));
    let (started, ended) = hub.run(&mut WakeSeat::new("agent-1", Some([1; 16])), NOW);
    assert!(matches!(ended, Ended::Done));
    assert_eq!(started[0].instance_id, "s");
    assert_eq!(hub.effects, ["list_instances", "start_instance"]);

    let (_, ended) = hub.run(&mut WakeSeat::new("agent-9", None), NOW);
    assert!(matches!(
        ended,
        Ended::Failed(CloudDeviceError::NotEnrolled)
    ));
    let mut flow = WakeSeat::new("agent-1", None);
    let Step::Effect(id, Effect::ListInstances) = flow.next(NOW) else {
        panic!("the seats first");
    };
    flow.resolve(id, Input::Failed(EffectFailure::Unavailable));
    assert!(matches!(
        flow.next(NOW),
        Step::Failed(CloudDeviceError::Effect(EffectFailure::Unavailable))
    ));
}
