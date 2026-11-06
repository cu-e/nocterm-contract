#![allow(clippy::unwrap_used)]

//! The keyset flow against a hub that enforces the version check, as a real one does.

mod support;

use nocterm_hub_client::KeysetError;
use nocterm_keys::{CollectionKey, KdfParams, UnlockKdf, UnlockKey};
use support::FakeHub;

/// Both keysets hold the same account key: what one seals, the other opens.
fn assert_same_account(a: &nocterm_hub_client::Keyset, b: &nocterm_hub_client::Keyset) {
    let wrapped = a
        .seal_collection_key(&CollectionKey::generate().unwrap(), "col-1")
        .unwrap();
    b.open_collection_key("col-1", &wrapped).unwrap();
}

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
    assert_same_account(&opened, &created.keyset);

    // The hub holds sealed values, nothing that opens by itself.
    let record = hub.seen.keyset().unwrap();
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
    assert_same_account(&opened, &first.keyset);
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

    assert_same_account(&recovered, &created.keyset);
    assert_eq!(recovered.version(), 2);
    assert!(client.open_keyset("acc-1", &fresh).await.unwrap().is_some());
    assert!(matches!(
        client.open_keyset("acc-1", &old).await,
        Err(KeysetError::WrongUnlockKey)
    ));
}
