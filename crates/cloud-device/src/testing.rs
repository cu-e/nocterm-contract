//! One account, device, hub and runner with real keys, shared by the module tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
pub(crate) mod hub;

use crate::{
    DeviceIdentity,
    context::{AccountKeys, CloudSession},
    records::{ChatSelector, HubTrustRecord, RunnerPins, TrustedRunner},
    trust::{HubCapabilities, TrustedHub},
};
use nocterm_hub_model::cloud::{
    CloudTextId, RunnerCoordinate,
    capabilities::{
        CLOUD_FEATURE_CHAT_KEY_MATERIAL, CLOUD_FEATURE_FRESH_HEAD, CLOUD_FEATURE_UNARY_PUBLISH,
        CapabilitiesClaim, CapabilityLimits, CapabilityWindow,
    },
};
use nocterm_keys::{
    AccountKey, AccountKeyPair, DeviceKey,
    cloud::{RunnerEncryptionKey, RunnerSigningKey},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const NOW: i64 = 1_800_000_000_000;
pub(crate) const RAW_HUB: &str = "raw-hub-0001";
pub(crate) const ACCOUNT: &str = "account-0001";
pub(crate) const NONCE: [u8; 16] = [0x4e; 16];
pub(crate) const ALL_FEATURES: u64 =
    CLOUD_FEATURE_FRESH_HEAD | CLOUD_FEATURE_UNARY_PUBLISH | CLOUD_FEATURE_CHAT_KEY_MATERIAL;

pub(crate) struct World {
    pub(crate) account_pair: AccountKeyPair,
    pub(crate) account: AccountKey,
    pub(crate) authority: DeviceKey,
    pub(crate) device_key: DeviceKey,
    pub(crate) device: DeviceIdentity,
    pub(crate) runner_key: RunnerEncryptionKey,
    pub(crate) runner_signer: RunnerSigningKey,
    pub(crate) runner: TrustedRunner,
    pub(crate) hub: TrustedHub,
    pub(crate) capabilities: HubCapabilities,
    pub(crate) selector: ChatSelector,
}
impl World {
    pub(crate) fn new() -> Self {
        Self::with_features(ALL_FEATURES)
    }
    pub(crate) fn with_features(features: u64) -> Self {
        let account_pair = AccountKeyPair::generate().unwrap();
        let account_public = account_pair.public_key().to_bytes();
        let authority = DeviceKey::from_seed(&[0x21; 32]);
        let record = HubTrustRecord::new(
            "hub.example.org:7443",
            RAW_HUB,
            ACCOUNT,
            Sha256::digest(account_public).into(),
            authority.public_key(),
        )
        .unwrap();
        let hub = TrustedHub::new(record, RAW_HUB, ACCOUNT, &account_public).unwrap();
        let (claim, signature) = capability_proof(&authority, features, NONCE, NOW);
        let capabilities = hub
            .verify_capabilities(&claim, &signature, &NONCE, NOW)
            .unwrap();
        let device_key = DeviceKey::from_seed(&[0x61; 32]);
        let device = DeviceIdentity::new(
            "device-0001",
            device_key.public_key(),
            "access",
            NOW + 3_600_000,
        )
        .unwrap();
        let runner_key = RunnerEncryptionKey::from_seed(&[0x41; 32]);
        let runner_signer = RunnerSigningKey::from_seed(&[0x51; 32]);
        let runner = TrustedRunner::new(
            RunnerCoordinate {
                id: [0x02; 16],
                key_epoch: 3,
            },
            RunnerPins {
                encryption: runner_key.public_key().to_bytes(),
                signing: runner_signer.public_key(),
                proof: [0x71; 32],
            },
            "Runner",
        )
        .unwrap();
        let selector = ChatSelector::new(
            hub.scope().clone(),
            runner.runner(),
            [0x05; 16],
            1,
            runner.pins(),
        )
        .unwrap();
        Self {
            account_pair,
            account: AccountKey::generate().unwrap(),
            authority,
            device_key,
            device,
            runner_key,
            runner_signer,
            runner,
            hub,
            capabilities,
            selector,
        }
    }
    pub(crate) fn account_public(&self) -> [u8; 32] {
        self.account_pair.public_key().to_bytes()
    }
    pub(crate) fn keys(&self) -> AccountKeys {
        AccountKeys::new(ACCOUNT, self.account.clone(), self.account_pair.clone())
    }
    pub(crate) fn session(&self) -> Arc<CloudSession> {
        Arc::new(
            CloudSession::new(
                Arc::new(self.keys()),
                self.hub.clone(),
                self.capabilities,
                vec![self.runner.clone()],
            )
            .unwrap(),
        )
    }
}

/// A `CloudCapabilities` answer signed by `authority`.
pub(crate) fn capability_proof(
    authority: &DeviceKey,
    features: u64,
    nonce: [u8; 16],
    now: i64,
) -> (Vec<u8>, Vec<u8>) {
    let claim = CapabilitiesClaim::new(
        CloudTextId::new(RAW_HUB).unwrap(),
        authority.public_key(),
        CapabilityLimits {
            features: CapabilityLimits::v1().features | features,
            ..CapabilityLimits::v1()
        },
        nonce,
        CapabilityWindow {
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
        },
    )
    .unwrap();
    let bytes = claim.canonical_bytes().unwrap();
    let signature = authority.sign(&bytes);
    (bytes, signature.to_vec())
}
