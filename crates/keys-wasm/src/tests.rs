use super::*;

#[test]
fn scopes_and_identifiers_are_parsed_strictly() {
    assert_eq!(scope("account", None).unwrap(), AgentScope::Account);
    assert!(scope("org", None).is_err());
    assert!(scope("account", Some(uuid::Uuid::nil().to_string())).is_err());
    assert!(scope("galaxy", None).is_err());
    assert!(uuid("nope", "agent id").is_err());
}

#[test]
fn an_unlocked_account_seals_a_definition_the_pool_opens() {
    use nocterm_keys::agents::open_definition;
    let (hub, user, account_id) = ("hub", "ann", "acc-1");
    let secrets = LoginSecrets::derive("correct horse battery", hub, user).unwrap();
    let account = AccountKey::generate().unwrap();
    let pair = AccountKeyPair::generate().unwrap();
    let sealed_account = account.seal(secrets.unlock(), account_id).unwrap();
    let sealed_pair = pair.seal(&account, account_id).unwrap();
    let web = WebAccount::open(
        "correct horse battery",
        hub,
        user,
        account_id,
        &sealed_account,
        &sealed_pair,
        &pair.public_key().to_bytes(),
    )
    .unwrap();
    assert!(
        WebAccount::open(
            "wrong password!!",
            hub,
            user,
            account_id,
            &sealed_account,
            &sealed_pair,
            &pair.public_key().to_bytes()
        )
        .is_err()
    );

    let pool_pair = AccountKeyPair::generate().unwrap();
    let (agent, pool) = (AgentId::new(), PoolId::new());
    let json = r#"{"name":"A","instructions":"","provider":{"kind":"k","endpoint":"","models":["m"],"api_key":null},"secrets":[],"allowed_hosts":[],"ssh_targets":[]}"#;
    let sealed = web
        .seal(
            json,
            &agent.to_string(),
            "account",
            None,
            &pool.to_string(),
            2,
            &pool_pair.public_key().to_bytes(),
        )
        .unwrap();
    let context = DefinitionContext {
        agent,
        scope: AgentScope::Account,
        pool,
        version: 2,
    };
    let opened = open_definition(&pool_pair, &pair.public_key(), &context, &sealed).unwrap();
    assert_eq!(opened.name, "A");
}

#[test]
fn a_version_two_definition_from_json_opens_with_its_policy() {
    use nocterm_keys::agents::{
        AgentDefinition, DEFINITION_FORMAT_VERSION_V2, ToolApproval, open_definition_any,
        sealed_definition_version,
    };
    let pair = AccountKeyPair::generate().unwrap();
    let web = WebAccount {
        account_id: "acc-1".to_owned(),
        account: AccountKey::generate().unwrap(),
        pair,
    };
    let pool_pair = AccountKeyPair::generate().unwrap();
    let (agent, pool) = (AgentId::new(), PoolId::new());
    let json = r#"{"name":"A","instructions":"","provider":{"kind":"k","endpoint":"","models":["m"],"api_key":null},"secrets":[],"allowed_hosts":[],"ssh_targets":[],
        "tools":{"allowed":{"only":["read_file"]},"approval":"always"},
        "limits":{"max_turns":20,"max_output_tokens":null,"max_spend_micros_per_run":null,"max_spend_micros_per_chat":1000000},
        "pricing":[{"model":"m","input_micros_per_mtok":1,"output_micros_per_mtok":2,"cached_input_micros_per_mtok":null,"revision":"r1"}]}"#;
    let sealed = web
        .seal_v2(
            json,
            &agent.to_string(),
            "account",
            None,
            &pool.to_string(),
            4,
            &pool_pair.public_key().to_bytes(),
        )
        .unwrap();
    assert_eq!(
        sealed_definition_version(&sealed),
        Some(DEFINITION_FORMAT_VERSION_V2)
    );
    let context =
        definition_context(&agent.to_string(), "account", None, &pool.to_string(), 4).unwrap();
    let AgentDefinition::V2(opened) =
        open_definition_any(&pool_pair, &web.pair.public_key(), &context, &sealed).unwrap()
    else {
        panic!("expected a version 2 definition");
    };
    assert_eq!(opened.tools.approval, ToolApproval::Always);
    assert_eq!(opened.limits.max_turns, Some(20));
    assert_eq!(opened.price("m").unwrap().revision, "r1");
    let invalid = json.replace("\"max_turns\":20", "\"max_turns\":0");
    assert!(matches!(
        web.seal_v2(
            &invalid,
            &agent.to_string(),
            "account",
            None,
            &pool.to_string(),
            4,
            &pool_pair.public_key().to_bytes(),
        ),
        Err(WebError::Seal(_))
    ));
}

#[test]
fn pool_keys_are_first_use_pinned_or_changed() {
    let (enc, sign) = ([1u8; 32], [2u8; 32]);
    let pin = Some((&enc[..], &sign[..]));
    assert_eq!(pool_trust(None, &enc, &sign).unwrap(), "first_use");
    assert_eq!(pool_trust(pin, &enc, &sign).unwrap(), "pinned");
    assert_eq!(pool_trust(pin, &enc, &[9; 32]).unwrap(), "changed");
    assert!(pool_trust(None, &enc[..31], &sign).is_err());
    assert!(pin_pair(Some(enc.to_vec()), None).is_err());
    assert!(pin_pair(None, None).unwrap().is_none());
}

#[test]
fn a_vault_password_unlocks_only_with_the_recorded_derivation() {
    let kdf = UnlockKdf::random().unwrap();
    let unlock = UnlockKey::from_vault_password("vault password!", &kdf).unwrap();
    let (account_id, account) = ("acc-2", AccountKey::generate().unwrap());
    let pair = AccountKeyPair::generate().unwrap();
    let sealed_account = account.seal(&unlock, account_id).unwrap();
    let sealed_pair = pair.seal(&account, account_id).unwrap();
    let public = pair.public_key().to_bytes();
    let open = |password: &str, description: &str| {
        WebAccount::open_vault(
            password,
            description,
            kdf.salt(),
            account_id,
            &sealed_account,
            &sealed_pair,
            &public,
        )
    };

    let web = open("vault password!", &kdf.description()).unwrap();
    assert_eq!(web.pair.public_key().to_bytes(), public);
    assert!(open("another password", &kdf.description()).is_err());
    assert!(open("vault password!", "argon2id;m=8;t=1;p=1").is_err());
}

#[test]
fn a_keyset_created_in_the_browser_unlocks_like_a_native_one() {
    let (hub, user, account_id) = ("hub", "ann", "acc-3");
    let created = new_login_keyset("correct horse battery", hub, user, account_id).unwrap();
    assert_eq!(created.unlock_kind(), 1);
    assert_eq!(created.kdf(), "argon2id;m=65536;t=3;p=4");
    let web = WebAccount::open(
        "correct horse battery",
        hub,
        user,
        account_id,
        &created.wrapped_account_key(),
        &created.sealed_private_key(),
        &created.public_key(),
    )
    .unwrap();
    assert_eq!(web.public_key(), created.public_key());
    let recovery = nocterm_keys::RecoveryKey::parse(&created.recovery_key()).unwrap();
    recovery
        .unwrap(account_id, &created.recovery_wrapped_account_key())
        .unwrap();
    assert_eq!(created.into_account().public_key(), web.public_key());
}

#[test]
fn a_vault_keyset_records_its_derivation_and_refuses_short_passwords() {
    let created = new_vault_keyset("vault password!", "acc-4").unwrap();
    assert_eq!(created.unlock_kind(), 2);
    let web = WebAccount::open_vault(
        "vault password!",
        &created.kdf(),
        &created.salt(),
        "acc-4",
        &created.wrapped_account_key(),
        &created.sealed_private_key(),
        &created.public_key(),
    )
    .unwrap();
    assert_eq!(web.public_key(), created.public_key());
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
