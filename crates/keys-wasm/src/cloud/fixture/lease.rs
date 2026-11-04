//! What a provider lease of the recorded session needs (ADR 0126 of the native client): the
//! runner's signed boot as `RunnerStatus` returns it, and an own agent's key in the account's
//! `agent_provider_keys` collection.
use nocterm_cloud_device::records::{
    ChatSelector, PROVIDER_KEYS_KIND, ProviderKeyRecord, provider_key_object,
};
use nocterm_hub_model::cloud::provider::{BootDescriptor, BootWindow};
use nocterm_keys::cloud::{RunnerBootKey, RunnerSigningKey};
use serde_json::{Value, json};

use super::{NOW, RUNNER_SIGNING_SEED, Recorder, runner};
use crate::WebAccount;

/// The own agent whose key the account holds.
pub(in crate::cloud) const OWN_AGENT: &str = "ag-own";
pub(in crate::cloud) const OWN_PROVIDER: &str = "openai";
pub(in crate::cloud) const OWN_MODEL: &str = "gpt-5.1";
/// The collection of kind `agent_provider_keys`.
const KEYS_COLLECTION: &str = "own-agent-keys";

/// Stores the own agent's key and returns the runner's signed boot (current for 29 minutes,
/// so a renewal at half the lease term still finds it current).
pub(super) fn store(
    recorder: &mut Recorder,
    account: &WebAccount,
    selector: &ChatSelector,
) -> Value {
    let key = recorder.collection(account, KEYS_COLLECTION, PROVIDER_KEYS_KIND);
    let record = ProviderKeyRecord::new(OWN_PROVIDER, OWN_MODEL, b"sk-test-not-a-key").unwrap();
    let object = provider_key_object(OWN_AGENT);
    let sealed = key
        .seal_object(
            KEYS_COLLECTION,
            &object,
            PROVIDER_KEYS_KIND,
            &record.encode().unwrap(),
        )
        .unwrap();
    recorder.object(KEYS_COLLECTION, &object, PROVIDER_KEYS_KIND, sealed);
    let boot = RunnerBootKey::generate().unwrap();
    let descriptor = BootDescriptor::new(
        selector.scope().namespace(),
        runner().runner(),
        [0xb0; 16],
        boot.public_key().to_bytes(),
        BootWindow {
            issued_at_ms: NOW - 1_000,
            expires_at_ms: NOW + 29 * 60 * 1000,
        },
    )
    .unwrap();
    let signed = RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED)
        .attest_boot(descriptor)
        .unwrap();
    json!({
        "agentId": OWN_AGENT,
        "provider": OWN_PROVIDER,
        "model": OWN_MODEL,
        "runnerStatus": hex::encode(signed.canonical_bytes().unwrap()),
    })
}
