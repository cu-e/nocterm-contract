use nocterm_keys::{AccountKey, LoginSecrets, UnlockKdf, UnlockKey};

use super::*;

#[test]
fn a_vault_password_unlocks_only_with_the_recorded_derivation() {
    let kdf = UnlockKdf::random().unwrap();
    let unlock = UnlockKey::from_vault_password("vault password!", &kdf).unwrap();
    let account_id = "acc-2";
    let sealed = AccountKey::generate()
        .unwrap()
        .seal(&unlock, account_id)
        .unwrap();
    let open = |password: &str, description: &str| {
        WebAccount::open_vault(password, description, kdf.salt(), account_id, &sealed)
    };
    assert!(open("vault password!", &kdf.description()).is_ok());
    assert!(open("another password", &kdf.description()).is_err());
    assert!(open("vault password!", "argon2id;m=8;t=1;p=1").is_err());
}

#[test]
fn a_keyset_created_in_the_browser_unlocks_like_a_native_one() {
    let (hub, user, account_id) = ("hub", "ann", "acc-3");
    let created = new_login_keyset("correct horse battery", hub, user, account_id).unwrap();
    assert_eq!(created.unlock_kind(), 1);
    assert_eq!(created.kdf(), "argon2id;m=65536;t=3;p=4");
    WebAccount::open(
        "correct horse battery",
        hub,
        user,
        account_id,
        &created.wrapped_account_key(),
    )
    .unwrap();
    let recovery = nocterm_keys::RecoveryKey::parse(&created.recovery_key()).unwrap();
    recovery
        .unwrap(account_id, &created.recovery_wrapped_account_key())
        .unwrap();
}

#[test]
fn a_vault_keyset_records_its_derivation_and_refuses_short_passwords() {
    let created = new_vault_keyset("vault password!", "acc-4").unwrap();
    assert_eq!(created.unlock_kind(), 2);
    WebAccount::open_vault(
        "vault password!",
        &created.kdf(),
        &created.salt(),
        "acc-4",
        &created.wrapped_account_key(),
    )
    .unwrap();
    assert!(matches!(
        new_vault_keyset("short", "acc-4"),
        Err(WebError::Login(LoginError::PasswordTooShort { .. }))
    ));
}

#[test]
fn login_auth_is_the_native_clients_value() {
    let secrets = LoginSecrets::derive("correct horse battery", "hub-0001", "alice").unwrap();
    assert_eq!(secrets.auth().len(), 64);
    assert_eq!(
        LoginSecrets::derive("correct horse battery", "hub-0001", " alice ")
            .unwrap()
            .auth(),
        secrets.auth()
    );
}
