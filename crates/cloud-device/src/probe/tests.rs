#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::{
    records::TrustedRunner,
    testing::{NOW, World},
};
use nocterm_hub_model::cloud::head::{CatalogHeadPage, ChatHead, HeadWitness};
use nocterm_keys::{
    DeviceKey,
    cloud::{RunnerEncryptionKey, open_head_query, seal_head_witness},
};

fn chat_head() -> ChatHead {
    ChatHead {
        chat_id: [0x05; 16],
        chat_key_epoch: 1,
        current_writer: Some(1),
        control_revision: 0,
        deleted: false,
        head: None,
        retained_from: 0,
        snapshot: None,
    }
}

fn sealed(world: &World, target: ProbeTarget) -> SealedHeadProbe {
    let probe = UnsignedHeadProbe::new(
        world.hub.scope(),
        world.account_public(),
        &world.runner,
        &world.device,
        target,
        NOW,
    )
    .unwrap();
    let signature = world.device_key.sign(&probe.signing_bytes().unwrap());
    probe.seal(&world.account_pair, &signature).unwrap()
}

/// The runner's side: open the query and answer it with `value`.
fn answer(
    world: &World,
    probe: &SealedHeadProbe,
    value: HeadValue,
    key: &RunnerEncryptionKey,
) -> Vec<u8> {
    let scope = HeadProbeScope::from_canonical_bytes(probe.scope()).unwrap();
    let query = open_head_query(
        &world.runner_key,
        &scope,
        probe.probe_id(),
        probe.ciphertext(),
        NOW,
    )
    .unwrap();
    let witness = world
        .runner_signer
        .attest_head(HeadWitness {
            query: query.query().clone(),
            observed_at_ms: NOW + 5,
            value,
        })
        .unwrap();
    seal_head_witness(key, &witness).unwrap()
}

#[test]
fn a_chat_probe_signed_by_the_device_opens_the_pinned_runners_witness() {
    let world = World::new();
    let probe = sealed(
        &world,
        ProbeTarget::Chat {
            chat_id: [0x05; 16],
            key_epoch: 1,
        },
    );
    let reply = answer(
        &world,
        &probe,
        HeadValue::Chat(Box::new(chat_head())),
        &world.runner_key,
    );
    let value = probe
        .open_reply(
            &world.account_pair,
            probe.scope(),
            &probe.probe_id(),
            &reply,
            NOW + 10,
        )
        .unwrap();
    assert_eq!(value, HeadValue::Chat(Box::new(chat_head())));
}

#[test]
fn a_catalog_probe_returns_the_witnessed_page() {
    let world = World::new();
    let probe = sealed(&world, ProbeTarget::Catalog(None));
    let page = CatalogHeadPage {
        revision: 2,
        digest: [9; 32],
        total_chats: 1,
        after: None,
        chats: vec![chat_head()],
        has_more: false,
    };
    let reply = answer(
        &world,
        &probe,
        HeadValue::Catalog(Box::new(page.clone())),
        &world.runner_key,
    );
    let value = probe
        .open_reply(
            &world.account_pair,
            probe.scope(),
            &probe.probe_id(),
            &reply,
            NOW + 10,
        )
        .unwrap();
    assert_eq!(value, HeadValue::Catalog(Box::new(page)));
}

#[test]
fn a_signature_by_another_device_key_is_refused_before_sealing() {
    let world = World::new();
    let probe = UnsignedHeadProbe::new(
        world.hub.scope(),
        world.account_public(),
        &world.runner,
        &world.device,
        ProbeTarget::Catalog(None),
        NOW,
    )
    .unwrap();
    let other = DeviceKey::from_seed(&[0x62; 32]).sign(&probe.signing_bytes().unwrap());
    assert!(matches!(
        probe.clone().seal(&world.account_pair, &other),
        Err(CloudDeviceError::Signature(_))
    ));
    assert!(matches!(
        probe.seal(&world.account_pair, &[0; 12]),
        Err(CloudDeviceError::Signature(_))
    ));
}

fn empty_page() -> HeadValue {
    HeadValue::Catalog(Box::new(CatalogHeadPage {
        revision: 1,
        digest: [0; 32],
        total_chats: 0,
        after: None,
        chats: Vec::new(),
        has_more: false,
    }))
}

#[test]
fn a_witness_by_another_runner_or_for_another_probe_is_refused() {
    let world = World::new();
    let probe = sealed(&world, ProbeTarget::Catalog(None));
    // Another runner answers the same question, sealed to the same account.
    let mut stranger = World::new();
    stranger.hub = world.hub.clone();
    stranger.account_pair = world.account_pair;
    stranger.runner_key = RunnerEncryptionKey::from_seed(&[0x42; 32]);
    stranger.runner = TrustedRunner::new(
        world.runner.runner(),
        crate::records::RunnerPins {
            encryption: stranger.runner_key.public_key().to_bytes(),
            ..world.runner.pins()
        },
        "Other",
    )
    .unwrap();
    let theirs = sealed(&stranger, ProbeTarget::Catalog(None));
    let foreign = answer(&stranger, &theirs, empty_page(), &stranger.runner_key);
    assert!(
        probe
            .open_reply(
                &stranger.account_pair,
                probe.scope(),
                &probe.probe_id(),
                &foreign,
                NOW + 10
            )
            .is_err()
    );
    let reply = answer(&stranger, &theirs, empty_page(), &stranger.runner_key);
    assert!(matches!(
        theirs.open_reply(
            &stranger.account_pair,
            theirs.scope(),
            &[0; 16],
            &reply,
            NOW + 10
        ),
        Err(CloudDeviceError::Probe(HeadProbeError::Scope))
    ));
    let other = sealed(&stranger, ProbeTarget::Catalog(None));
    assert!(
        other
            .open_reply(
                &stranger.account_pair,
                other.scope(),
                &other.probe_id(),
                &reply,
                NOW + 10
            )
            .is_err()
    );
}

#[test]
fn a_witness_after_the_probe_window_is_refused() {
    let world = World::new();
    let probe = sealed(&world, ProbeTarget::Catalog(None));
    let reply = answer(&world, &probe, empty_page(), &world.runner_key);
    let late = probe.expires_at_ms();
    assert!(
        probe
            .open_reply(
                &world.account_pair,
                probe.scope(),
                &probe.probe_id(),
                &reply,
                late
            )
            .is_err()
    );
}

#[test]
fn a_probe_never_outlives_the_signed_in_session() {
    let mut world = World::new();
    world.device =
        crate::DeviceIdentity::new("device-0001", world.device_key.public_key(), "a", NOW + 500)
            .unwrap();
    let probe = sealed(&world, ProbeTarget::Catalog(None));
    assert_eq!(probe.expires_at_ms(), NOW + 500);
}

#[test]
fn a_probe_for_another_account_key_is_refused() {
    let world = World::new();
    assert!(matches!(
        UnsignedHeadProbe::new(
            world.hub.scope(),
            [7; 32],
            &world.runner,
            &world.device,
            ProbeTarget::Catalog(None),
            NOW
        ),
        Err(CloudDeviceError::Binding)
    ));
}
