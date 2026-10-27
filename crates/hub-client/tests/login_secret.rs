#![allow(clippy::expect_used)]

//! The password never reaches the hub: sign-in sends the value derived from it.

mod support;

use nocterm_hub_client::ClientError;
use nocterm_hub_proto::v1;
use nocterm_keys::{LoginError, LoginSecrets};
use support::{FakeHub, HUB_ID, device};

const PASSWORD: &str = "correct horse battery";

#[tokio::test]
async fn password_login_sends_the_derived_value_and_returns_the_secrets() {
    let hub = FakeHub::start(false).await;
    let client = hub.client().await;

    let signed_in = client
        .password_login("  alice ", PASSWORD, &device())
        .await
        .unwrap();

    let expected = LoginSecrets::derive(PASSWORD, HUB_ID, "alice").unwrap();
    let sent = hub.seen.password_logins();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].username, "alice");
    assert_eq!(sent[0].password, expected.auth());
    assert_ne!(sent[0].password, PASSWORD);
    assert_eq!(signed_in.secrets.auth(), expected.auth());
    assert_eq!(signed_in.session.account_id, "acc-1");
    assert!(client.session().is_some());
}

#[tokio::test]
async fn bootstrap_and_invites_replace_the_typed_password_too() {
    let hub = FakeHub::start(false).await;
    let client = hub.client().await;

    client
        .bootstrap(
            v1::BootstrapRequest {
                setup_token: "setup".into(),
                username: "owner".into(),
                password: PASSWORD.into(),
                display_name: "Owner".into(),
                org_name: "Org".into(),
            },
            &device(),
        )
        .await
        .unwrap();
    client
        .redeem_invite(
            v1::RedeemInviteRequest {
                invite_code: "invite".into(),
                username: "bob".into(),
                password: PASSWORD.into(),
                display_name: "Bob".into(),
            },
            &device(),
        )
        .await
        .unwrap();

    let owner = LoginSecrets::derive(PASSWORD, HUB_ID, "owner").unwrap();
    let bob = LoginSecrets::derive(PASSWORD, HUB_ID, "bob").unwrap();
    assert_eq!(hub.seen.bootstraps()[0].password, owner.auth());
    assert_eq!(hub.seen.invites()[0].password, bob.auth());
    assert_ne!(owner.auth(), bob.auth());
}

#[tokio::test]
async fn a_password_that_cannot_be_derived_is_refused_before_any_request() {
    let hub = FakeHub::start(false).await;
    let client = hub.client().await;

    let short = client.password_login("alice", "short", &device()).await;
    assert!(matches!(
        short,
        Err(ClientError::Login(LoginError::PasswordTooShort { .. }))
    ));
    let nameless = client.password_login("  ", PASSWORD, &device()).await;
    assert!(matches!(
        nameless,
        Err(ClientError::Login(LoginError::EmptyUsername))
    ));
    assert!(hub.seen.password_logins().is_empty());
}
