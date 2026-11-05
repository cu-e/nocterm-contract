//! The page's executor over the recorded session file alone, as the panel's tests replay it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use std::sync::OnceLock;

use nocterm_cloud_device::nonces::Nonces;
use serde_json::Value;

use super::{Answer, Hub, NONCE_SEED, NOW_MS, RAW_HUB, Rows, drive, hex_of, store_answer};
use crate::{
    WebAccount,
    cloud::{
        CloudDevice,
        types::{EffectInput, FlowOutput, FlowStep, WireCollection, WireEffect, WireObject},
    },
};

pub(in crate::cloud) fn account() -> &'static WebAccount {
    static ACCOUNT: OnceLock<WebAccount> = OnceLock::new();
    ACCOUNT.get_or_init(super::account)
}
/// A connected device, as the recorded order begins.
pub(in crate::cloud) fn connected(hub: &mut Replayer) -> (CloudDevice, Vec<FlowOutput>) {
    let device = CloudDevice::made(account(), super::device_input()).unwrap();
    let mut connect = device.discover(RAW_HUB, None, Nonces::seeded(NONCE_SEED));
    let (outputs, last, _) = drive(&mut connect, hub, NOW_MS);
    assert!(matches!(last, FlowStep::Done), "{last:?}");
    (device, outputs)
}
pub(in crate::cloud) fn recorded() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../fixtures/cloud-device-v1/web-session.json"
    ))
    .unwrap()
}

/// A Store collection row of the session file, with its wrapped key.
fn collection(c: &Value) -> (WireCollection, Vec<u8>) {
    let wire = WireCollection {
        collection_id: c["collectionId"].as_str().unwrap().to_owned(),
        kind: c["kind"].as_str().unwrap().to_owned(),
        personal: c["personal"].as_bool().unwrap(),
        deleted: c["deleted"].as_bool().unwrap(),
    };
    (wire, hex_of(c, "wrappedKey"))
}
/// A Store object row of the session file.
fn object(o: &Value) -> WireObject {
    WireObject {
        collection_id: o["collectionId"].as_str().unwrap().to_owned(),
        object_id: o["objectId"].as_str().unwrap().to_owned(),
        kind: o["kind"].as_str().unwrap().to_owned(),
        version: o["version"].as_u64().unwrap(),
        deleted: o["deleted"].as_bool().unwrap(),
        ciphertext: hex_of(o, "ciphertext"),
    }
}

/// The page's executor over the recorded session only, as the panel's tests replay it.
pub(in crate::cloud) struct Replayer {
    pub(in crate::cloud) session: Value,
    pub(in crate::cloud) rows: Rows,
    /// The runner answers probes (false: a sleeping seat).
    pub(in crate::cloud) awake: bool,
    /// Answers to `publish`, in order, before the default receipt.
    pub(in crate::cloud) publish: Vec<EffectInput>,
    pub(in crate::cloud) published: Vec<WireEffect>,
}
impl Replayer {
    pub(in crate::cloud) fn new() -> Self {
        let session = recorded();
        let array = |part: &Value| part.as_array().unwrap().clone();
        let rows = Rows {
            collections: array(&session["collections"])
                .iter()
                .map(collection)
                .collect(),
            objects: array(&session["objects"]).iter().map(object).collect(),
            records: array(&session["chat"]["records"]),
            directory: array(&session["directory"]["records"]),
            runner_status: hex_of(&session["own"], "runnerStatus"),
        };
        Self {
            session,
            rows,
            awake: true,
            publish: Vec::new(),
            published: Vec::new(),
        }
    }
    pub(in crate::cloud) fn with_fragmented_publish() -> Self {
        let mut hub = Self::new();
        hub.session["capabilities"] = hub.session["fragmentedCapabilities"].clone();
        hub
    }
    /// With the account's `agent_ssh_trust` collection, and the later text record and the
    /// chat's SSH records in the stream (what a new open reads to announce the runner's
    /// certificate request).
    pub(in crate::cloud) fn with_ssh() -> Self {
        let mut hub = Self::new();
        let ssh = hub.session["ssh"].clone();
        hub.rows.collections.push(collection(&ssh["collection"]));
        hub.rows
            .objects
            .extend(ssh["objects"].as_array().unwrap().iter().map(object));
        for part in [&hub.session["chat"]["later"], &ssh["records"]] {
            hub.rows
                .records
                .extend(part.as_array().unwrap().iter().cloned());
        }
        hub
    }
    pub(in crate::cloud) fn chat_id(&self) -> String {
        self.session["chat"]["chatId"].as_str().unwrap().to_owned()
    }
}
impl Hub for Replayer {
    fn answer(&mut self, effect: &WireEffect) -> Answer {
        let failed = |failure: &str| {
            Answer::Input(EffectInput::Failed {
                failure: failure.to_owned(),
            })
        };
        match effect {
            WireEffect::Capabilities { nonce } => {
                let answer = &self.session["capabilities"][hex::encode(nonce)];
                Answer::Input(EffectInput::Capabilities {
                    claim: hex_of(answer, "claim"),
                    signature: hex_of(answer, "signature"),
                })
            }
            WireEffect::Probe { probe_id, .. } => {
                let reply = &self.session["probeReplies"][hex::encode(probe_id)];
                if !self.awake || reply.is_null() {
                    return failed("unavailable");
                }
                Answer::Input(EffectInput::ProbeReply {
                    scope: hex_of(reply, "scope"),
                    probe_id: probe_id.clone(),
                    ciphertext: hex_of(reply, "ciphertext"),
                })
            }
            WireEffect::Publish { .. } => {
                self.published.push(effect.clone());
                if self.publish.is_empty() {
                    store_answer(&self.rows, effect)
                } else {
                    Answer::Input(self.publish.remove(0))
                }
            }
            effect => store_answer(&self.rows, effect),
        }
    }
}
