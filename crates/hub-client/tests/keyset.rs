#![allow(clippy::unwrap_used)]

//! The keyset flow against a hub that enforces the version check, as a real one does.

mod support;

use nocterm_hub_client::{KeysetError, UnlockMethod};
use nocterm_keys::{CollectionKey, KdfParams, PinnedKeys, UnlockKdf, UnlockKey};
use support::FakeHub;

fn unlock(password: &str) -> (UnlockKey, UnlockKdf) {
    let kdf = UnlockKdf::new(KdfParams::MINIMUM, vec![4; 16]).unwrap();
    (UnlockKey::from_vault_password(password, &kdf).unwrap(), kdf)
}

#[tokio::test]
async fn the_first_device_creates_the_keyset_and_another_opens_it() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    let (key, kdf) = unlock("correct horse battery");

    assert!(client.open_keyset("acc-1", &key).await.unwrap().is_none());
    let created = client.create_keyset("acc-1", &key, &kdf).await.unwrap();
    assert_eq!(created.keyset.version(), 1);

    let opened = client.open_keyset("acc-1", &key).await.unwrap().unwrap();
    assert_eq!(opened.public_key(), created.keyset.public_key());

    // The hub holds the public key and sealed values, nothing that opens by itself.
    let record = hub.seen.keyset().unwrap();
    assert_eq!(record.public_key, created.keyset.public_key().to_bytes());
    assert_eq!(record.kdf, "argon2id;m=65536;t=3;p=4");
    assert_eq!(record.salt, vec![4; 16]);
}

#[tokio::test]
async fn a_second_creation_does_not_overwrite_the_first_keyset() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    let (key, kdf) = unlock("correct horse battery");
    let first = client.create_keyset("acc-1", &key, &kdf).await.unwrap();
    let before = hub.seen.keyset().unwrap();

    let second = client.create_keyset("acc-1", &key, &kdf).await;

    assert!(matches!(second, Err(KeysetError::AlreadyExists)));
    assert_eq!(hub.seen.keyset().unwrap(), before);
    let opened = client.open_keyset("acc-1", &key).await.unwrap().unwrap();
    assert_eq!(opened.public_key(), first.keyset.public_key());
}

#[tokio::test]
async fn a_wrong_unlock_key_does_not_open_the_keyset() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    let (key, kdf) = unlock("correct horse battery");
    client.create_keyset("acc-1", &key, &kdf).await.unwrap();

    let (other, _) = unlock("another password");
    let result = client.open_keyset("acc-1", &other).await;

    assert!(matches!(result, Err(KeysetError::WrongUnlockKey)));
}

#[tokio::test]
async fn the_recovery_key_restores_access_under_a_new_password() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    let (old, kdf) = unlock("correct horse battery");
    let created = client.create_keyset("acc-1", &old, &kdf).await.unwrap();
    let (fresh, fresh_kdf) = unlock("a brand new password");

    let recovered = client
        .recover_keyset("acc-1", &created.recovery, &fresh, &fresh_kdf)
        .await
        .unwrap();

    assert_eq!(recovered.public_key(), created.keyset.public_key());
    assert_eq!(recovered.version(), 2);
    assert!(client.open_keyset("acc-1", &fresh).await.unwrap().is_some());
    assert!(matches!(
        client.open_keyset("acc-1", &old).await,
        Err(KeysetError::WrongUnlockKey)
    ));
}

#[tokio::test]
async fn a_grant_is_sealed_by_the_granter_to_the_recipient_for_one_collection() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    let (key, kdf) = unlock("correct horse battery");
    let alice = client
        .create_keyset("alice", &key, &kdf)
        .await
        .unwrap()
        .keyset;
    let bob = nocterm_keys::AccountKeyPair::generate().unwrap();
    let mut pins = PinnedKeys::new();
    let bob_key = pins.pin("bob", bob.public_key()).unwrap();
    let collection_key = CollectionKey::generate().unwrap();

    client
        .grant(&alice, "col-1", &collection_key, &bob_key)
        .await
        .unwrap();

    let grants = hub.seen.grants();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].collection_id, "col-1");
    assert_eq!(grants[0].account_id, "bob");
    let sealed = &grants[0].sealed_key;
    let from = alice.public_key();
    let opened = CollectionKey::open_from(&bob, &from, "col-1", "bob", sealed).unwrap();
    let name = collection_key.seal_name("col-1", "Servers").unwrap();
    assert_eq!(opened.open_name("col-1", &name).unwrap(), "Servers");
    assert!(CollectionKey::open_from(&bob, &from, "col-2", "bob", sealed).is_err());
    // Another key than the granter's does not open it, and nor does the granter's own account.
    let stranger = nocterm_keys::AccountKeyPair::generate().unwrap();
    assert!(
        CollectionKey::open_from(&bob, &stranger.public_key(), "col-1", "bob", sealed).is_err()
    );
    let alice_key = pins.pin("alice", from).unwrap();
    assert!(
        alice
            .open_granted_collection_key("col-1", sealed, &alice_key)
            .is_err()
    );
}

#[tokio::test]
async fn the_stored_keyset_tells_the_client_which_password_to_ask_for() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    assert_eq!(client.unlock_method().await.unwrap(), None);

    let secrets =
        nocterm_keys::LoginSecrets::derive("correct horse battery", "hub", "alice").unwrap();
    client
        .create_keyset("acc-1", secrets.unlock(), secrets.kdf())
        .await
        .unwrap();

    assert_eq!(
        client.unlock_method().await.unwrap(),
        Some(UnlockMethod::LoginPassword)
    );
    // Signing in through SSO afterwards, the client derives a vault key: refused as the wrong
    // source, not reported as a wrong password.
    let (vault, _) = unlock("correct horse battery");
    assert!(matches!(
        client.open_keyset("acc-1", &vault).await,
        Err(KeysetError::WrongUnlockSource { .. })
    ));
    assert!(
        client
            .open_keyset("acc-1", secrets.unlock())
            .await
            .unwrap()
            .is_some()
    );
}
