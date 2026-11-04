//! The device key signs only what the Cloud device core asks for.
#![allow(clippy::expect_used, reason = "test fixtures fail loudly")]

mod support;

use nocterm_cloud_device::{
    AccountScope, DeviceIdentity,
    command::{CommandAction, UnsignedCommand},
    records::{ChatSelector, RunnerPins},
};
use nocterm_hub_client::ClientError;
use nocterm_hub_model::cloud::{RunCoordinate, RunnerCoordinate};
use nocterm_keys::{AccountKeyPair, DeviceKey};
use support::FakeHub;

fn stop(device: &DeviceIdentity) -> UnsignedCommand {
    let pair = AccountKeyPair::generate().expect("pair");
    let public = pair.public_key().to_bytes();
    let scope = AccountScope::derive("hub-1", [0x21; 32], "acc-1", public).expect("scope");
    let selector = ChatSelector::new(
        scope,
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 1,
        },
        [5; 16],
        1,
        RunnerPins {
            encryption: AccountKeyPair::generate()
                .expect("runner")
                .public_key()
                .to_bytes(),
            signing: [0x51; 32],
            proof: [0x71; 32],
        },
    )
    .expect("selector");
    let run = RunCoordinate {
        id: [0x21; 16],
        expected_epoch: 1,
    };
    UnsignedCommand::prepare(
        &selector,
        public,
        device,
        CommandAction::Stop { run },
        0,
        nocterm_hub_client::now_ms(),
    )
    .expect("command")
}

#[tokio::test]
async fn the_device_key_signs_a_cloud_value_that_names_it_and_refuses_any_other() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    let device = client.cloud_device().expect("identity");
    assert_eq!(device.device_id(), "dev-1");
    let command = stop(&device);
    let request = command.sign_request().expect("request");
    let signature = client.sign_cloud(&request).expect("signature");
    assert!(
        nocterm_keys::verify_signature(&device.signing_key(), request.bytes(), &signature).is_ok()
    );

    let other = DeviceIdentity::new(
        "dev-2",
        DeviceKey::generate().expect("key").public_key(),
        "access",
        i64::MAX,
    )
    .expect("other");
    let foreign = stop(&other).sign_request().expect("request");
    assert!(matches!(
        client.sign_cloud(&foreign),
        Err(ClientError::CloudSigner)
    ));
}

#[tokio::test]
async fn a_device_that_is_not_signed_in_has_no_cloud_identity() {
    let hub = FakeHub::start(false).await;
    assert!(matches!(
        hub.client().await.cloud_device(),
        Err(ClientError::NotSignedIn)
    ));
}
