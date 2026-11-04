#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::testing::{ACCOUNT, NONCE, NOW, RAW_HUB, World, capability_proof};
use nocterm_hub_model::cloud::capabilities::CapabilityError;
use nocterm_keys::DeviceKey;

#[test]
fn only_records_for_the_signed_in_hub_account_and_key_match() {
    let world = World::new();
    let key = world.account_public();
    let mine = world.hub.record().clone();
    let other_hub = HubTrustRecord::new(
        "other:7443",
        "raw-hub-0002",
        ACCOUNT,
        mine.account_key_digest(),
        [1; 32],
    )
    .unwrap();
    let other_origin = HubTrustRecord::new(
        "10.0.0.1:7443",
        RAW_HUB,
        ACCOUNT,
        mine.account_key_digest(),
        [2; 32],
    )
    .unwrap();
    let records = [mine.clone(), other_hub.clone(), other_origin.clone()];
    let matches = matching_hub_trust(&records, RAW_HUB, ACCOUNT, &key);
    assert_eq!(matches, vec![&mine, &other_origin]);
    assert!(matches!(
        TrustedHub::new(other_hub, RAW_HUB, ACCOUNT, &key),
        Err(CloudDeviceError::Binding)
    ));
}

#[test]
fn a_capability_proof_by_another_authority_is_refused() {
    let world = World::new();
    let impostor = DeviceKey::from_seed(&[0x22; 32]);
    let (claim, signature) = capability_proof(&impostor, 0, NONCE, NOW);
    assert!(matches!(
        world
            .hub
            .verify_capabilities(&claim, &signature, &NONCE, NOW),
        Err(CloudDeviceError::Capability(CapabilityError::Identity))
    ));
}

#[test]
fn a_capability_proof_for_another_nonce_or_after_expiry_is_refused() {
    let world = World::new();
    let (claim, signature) = capability_proof(&world.authority, 0, NONCE, NOW);
    assert!(matches!(
        world
            .hub
            .verify_capabilities(&claim, &signature, &[0; 16], NOW),
        Err(CloudDeviceError::Capability(CapabilityError::Nonce))
    ));
    assert!(matches!(
        world
            .hub
            .verify_capabilities(&claim, &signature, &NONCE, NOW + 60_000),
        Err(CloudDeviceError::Capability(CapabilityError::Expired))
    ));
    let mut forged = signature.clone();
    forged[0] ^= 1;
    assert!(matches!(
        world.hub.verify_capabilities(&claim, &forged, &NONCE, NOW),
        Err(CloudDeviceError::Capability(CapabilityError::Signature(_)))
    ));
}

#[test]
fn reading_needs_fresh_heads_and_commands_need_unary_publish() {
    let world = World::new();
    assert!(world.capabilities.require_commands().is_ok());
    let (claim, signature) = capability_proof(&world.authority, 0, NONCE, NOW);
    let bare = world
        .hub
        .verify_capabilities(&claim, &signature, &NONCE, NOW)
        .unwrap();
    assert!(matches!(
        bare.require_reading(),
        Err(CloudDeviceError::Unsupported)
    ));
    let (claim, signature) =
        capability_proof(&world.authority, CLOUD_FEATURE_FRESH_HEAD, NONCE, NOW);
    let reading = world
        .hub
        .verify_capabilities(&claim, &signature, &NONCE, NOW)
        .unwrap();
    assert!(reading.require_reading().is_ok());
    assert!(matches!(
        reading.require_commands(),
        Err(CloudDeviceError::Unsupported)
    ));
}
