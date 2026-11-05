#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::testing::World;
use nocterm_hub_model::cloud::relay::{RelayBinding, RelayKind};
use nocterm_keys::cloud::open_chat_key_from_account;

#[test]
fn a_new_chat_wraps_its_key_for_the_account_and_grants_the_same_key_to_the_runner() {
    let world = World::new();
    let chat = NewChat::create(
        world.hub.scope(),
        &world.runner,
        [0x09; 16],
        &world.account,
        &world.account_pair,
    )
    .unwrap();
    assert_eq!(chat.selector().key_epoch(), FIRST_KEY_EPOCH);
    let coordinate = chat.selector().coordinate().unwrap();
    let mine = chat.material().open_key(&world.account).unwrap();
    let runners = open_chat_key_from_account(
        &world.runner_key,
        &world.account_pair.public_key(),
        &coordinate,
        chat.grant().ciphertext(),
    )
    .unwrap();
    let probe = nocterm_hub_model::cloud::JournalCoordinate::new(
        coordinate,
        nocterm_hub_model::cloud::JournalClass::Record,
        [1; 16],
        1,
        1,
        1,
    )
    .unwrap();
    let sealed = mine.seal_journal(&probe, b"same key").unwrap();
    assert_eq!(
        &**runners.open_journal(&probe, &sealed).unwrap(),
        b"same key"
    );
}

#[test]
fn a_stored_grant_republishes_as_the_same_publication() {
    let world = World::new();
    let chat = NewChat::create(
        world.hub.scope(),
        &world.runner,
        [0x09; 16],
        &world.account,
        &world.account_pair,
    )
    .unwrap();
    let first = chat.grant_publication(&world.capabilities).unwrap();
    let stored = ChatGrantRecord::decode(&chat.grant().encode()).unwrap();
    let again = grant_publication(chat.selector(), &stored, &world.capabilities).unwrap();
    assert_eq!(first.publication_id(), again.publication_id());
    assert_eq!(first.ciphertext(), again.ciphertext());
    let binding = RelayBinding::from_canonical_bytes(&first.binding().unwrap()).unwrap();
    assert_eq!(binding.kind(), RelayKind::ChatKeyGrant);
    assert_eq!(
        binding.material_coordinate(),
        Some(&chat.selector().coordinate().unwrap())
    );
}

#[test]
fn a_new_chat_for_another_account_key_is_refused() {
    let world = World::new();
    let stranger = nocterm_keys::AccountKeyPair::generate().unwrap();
    assert!(matches!(
        NewChat::create(
            world.hub.scope(),
            &world.runner,
            [1; 16],
            &world.account,
            &stranger
        ),
        Err(CloudDeviceError::Binding)
    ));
}
