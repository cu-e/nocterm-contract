#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::{
    records::RUNNER_REGISTRY_KIND,
    testing::{
        ACCOUNT, NOW, RAW_HUB, World,
        hub::{Ended, FakeHub},
    },
};
use sha2::{Digest, Sha256};

/// A hub-trust record of `origin` for `raw_hub`, stored as native devices store it.
fn trust(hub: &mut FakeHub, raw_hub: &str, origin: &str) {
    let record = HubTrustRecord::new(
        origin,
        raw_hub,
        ACCOUNT,
        Sha256::digest(hub.world.account_public()).into(),
        hub.world.authority.public_key(),
    )
    .unwrap();
    let id = record.collection_id().unwrap();
    let key = hub.collection(&id, HUB_TRUST_KIND);
    let sealed = key
        .seal_object(
            &id,
            HUB_TRUST_OBJECT,
            HUB_TRUST_KIND,
            &record.encode().unwrap(),
        )
        .unwrap();
    hub.object(&id, HUB_TRUST_OBJECT, HUB_TRUST_KIND, sealed);
}
fn registry(hub: &mut FakeHub) {
    let scope = hub.world.hub.scope().clone();
    let id = RunnerRegistry::collection_id(&scope).unwrap();
    let key = hub.collection(&id, RUNNER_REGISTRY_KIND);
    let rows = RunnerRegistry::new(scope, vec![hub.world.runner.clone()]).unwrap();
    let sealed = key
        .seal_object(
            &id,
            RUNNER_REGISTRY_OBJECT,
            RUNNER_REGISTRY_KIND,
            &rows.encode().unwrap(),
        )
        .unwrap();
    hub.object(&id, RUNNER_REGISTRY_OBJECT, RUNNER_REGISTRY_KIND, sealed);
}
fn discover(hub: &mut FakeHub, origin: Option<&str>) -> Vec<Discovery> {
    let keys = Arc::new(hub.world.keys());
    let mut flow = Discover::new(keys, RAW_HUB, origin.map(str::to_owned));
    let (outcome, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Done), "{ended:?}");
    outcome
}

#[test]
fn the_trust_record_of_this_hub_opens_a_session_with_its_runners() {
    let mut hub = FakeHub::new(World::new());
    trust(&mut hub, RAW_HUB, "hub.example.org:7443");
    trust(&mut hub, "another-hub", "other.example.org:7443");
    registry(&mut hub);
    let outcome = discover(&mut hub, None);
    let [Discovery::Ready(session)] = outcome.as_slice() else {
        panic!("ready");
    };
    assert_eq!(session.hub().record().origin(), "hub.example.org:7443");
    assert_eq!(session.runners(), [hub.world.runner.clone()]);
    assert!(session.capabilities().unary_publish());
}

#[test]
fn several_origins_are_the_persons_choice_and_none_means_not_set_up() {
    let mut hub = FakeHub::new(World::new());
    assert!(matches!(
        discover(&mut hub, None).as_slice(),
        [Discovery::NotSetUp]
    ));
    trust(&mut hub, RAW_HUB, "b.example.org:7443");
    trust(&mut hub, RAW_HUB, "a.example.org:7443");
    let outcome = discover(&mut hub, None);
    let [Discovery::ChooseOrigin(origins)] = outcome.as_slice() else {
        panic!("a choice");
    };
    assert_eq!(origins, &["a.example.org:7443", "b.example.org:7443"]);
    let outcome = discover(&mut hub, Some("b.example.org:7443"));
    let [Discovery::Ready(session)] = outcome.as_slice() else {
        panic!("ready");
    };
    assert!(session.runners().is_empty(), "no runner enrolled yet");
}
