//! A recorded browser session over the device flows, of the account the panel's own fixtures
//! unlock (`acc-1`, login password `correct horse battery` of `alice` on `hub-1`).
//! `fixtures/cloud-device-v1/web-session.json` holds the output (its README lists the parts);
//! the panel replays it against the real wasm module: `connectSeeded(rawHub, null, nonceSeed)`,
//! then `listChats({watch: true})`, then `openChat(chat.chatId)`, then `openChat(chat.chatId,
//! checkpoint)`, then `listChats({directories: [the first listing's directory checkpoint],
//! watch: true})`, then (with the SSH rows of `ssh.rs` and the later and SSH records in the
//! stream) `openChat(chat.chatId)` and `answerSsh`, in this order, so every probe id is one with
//! a recorded reply. The hub has the chat directory (bit 256); a provider lease needs no
//! recorded reply. Regenerate with `cargo test -p nocterm-keys-wasm write_web_session_fixture --
//! --ignored` (fresh random keys each time: copy the file into the panel afterwards).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use nocterm_cloud_device::records::{
    CHAT_MATERIAL_KIND, ChatMaterialRecord, ChatSelector, HUB_TRUST_KIND, HUB_TRUST_OBJECT,
    HubTrustRecord, RUNNER_REGISTRY_KIND, RUNNER_REGISTRY_OBJECT, RunnerPins, RunnerRegistry,
    TrustedRunner, account_collection_id,
};
use nocterm_hub_model::cloud::{
    CloudTextId, RunCoordinate, RunnerCoordinate,
    capabilities::{
        CLOUD_FEATURE_CHAT_DIRECTORY, CLOUD_FEATURE_CHAT_KEY_MATERIAL, CLOUD_FEATURE_FRESH_HEAD,
        CLOUD_FEATURE_UNARY_PUBLISH, CapabilitiesClaim, CapabilityLimits, CapabilityWindow,
    },
    head::{
        CatalogHeadPage, ChatHead, HeadProbeScope, HeadRecordAnchor, HeadTarget, HeadValue,
        HeadWitness, ReceiptOutcome,
    },
};
use nocterm_keys::{
    CollectionKey, DeviceKey,
    cloud::{ChatKey, RunnerEncryptionKey, RunnerSigningKey, open_head_query, seal_head_witness},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    CloudDevice, CloudResult, WebChat, WebFlow,
    types::{
        DeviceInput, EffectInput, FlowOutput, FlowStep, ListOptions, StreamFrame, WireCollection,
        WireEffect, WireObject,
    },
};
use crate::WebAccount;

mod chat;
mod directory;
pub(super) mod lease;
pub(super) mod replay;
mod ssh;

pub(super) const NOW: i64 = 1_800_000_000_000;
pub(super) const NOW_MS: f64 = 1_800_000_000_000.0;
pub(super) const RAW_HUB: &str = "hub-1";
pub(super) const ACCOUNT: &str = "acc-1";
pub(super) const DEVICE_ID: &str = "device-web";
pub(super) const ACCESS_TOKEN: &str = "access-token";
pub(super) const SESSION_ENDS: i64 = NOW + 3_600_000;
pub(super) const DEVICE_SEED: [u8; 32] = [0x61; 32];
pub(super) const NONCE_SEED: [u8; 32] = [0x5e; 32];
pub(super) const AUTHORITY_SEED: [u8; 32] = [0x21; 32];
pub(super) const RUNNER_ENCRYPTION_SEED: [u8; 32] = [0x41; 32];
pub(super) const RUNNER_SIGNING_SEED: [u8; 32] = [0x51; 32];
pub(super) const RUNNER_PROOF: [u8; 32] = [0x71; 32];
pub(super) const RUNNER_ID: [u8; 16] = [0x02; 16];
pub(super) const CHAT_ID: [u8; 16] = [0x05; 16];
/// The run of the public event vectors (`fixtures/cloud-events-v1`).
pub(super) const RUN: RunCoordinate = RunCoordinate {
    id: [0x21; 16],
    expected_epoch: 2,
};
pub(super) const PROMPT: &str = "Which services listen on the build host?";
pub(super) const ANSWER: &str =
    "I'll list the listening sockets:\n\n```sh\nss -tlnp\n```\n\nThis needs your approval.";
pub(super) const LATER: &str = "Waiting for your answer.";

/// The `LOGIN_KEYSET` of the panel's `keyset-fixtures.ts`.
const WRAPPED_ACCOUNT_KEY: &str = "010131b0c155b255a2b91b9b977e254520dd4557bbf759a4a7b90a98d26142f229802093d52190a71dd80795fa0d7b93d5b9e10719ffbf382d7a489f371f48a7dc1545949026c5dd1278";
const SEALED_PRIVATE_KEY: &str = "010566cca7d3cd3dc833416c7edb3cfbef66156c91afaffdbbf0911390f218bdea13a3b106de958fe1ebb0ed53693b7b5e279cbf937497575f4711fb4e17ba4176bb31fa67c76b833d1b";
const PUBLIC_KEY: &str = "c13c5522ce9483ee79f3fe4302ad0439aeab7e5b1ea17869c10ff51b984a1c44";

pub(super) fn hex_of(value: &Value, name: &str) -> Vec<u8> {
    hex::decode(value[name].as_str().unwrap_or_else(|| panic!("{name}"))).unwrap()
}

pub(super) fn account() -> WebAccount {
    WebAccount::open(
        "correct horse battery",
        RAW_HUB,
        "alice",
        ACCOUNT,
        &hex::decode(WRAPPED_ACCOUNT_KEY).unwrap(),
        &hex::decode(SEALED_PRIVATE_KEY).unwrap(),
        &hex::decode(PUBLIC_KEY).unwrap(),
    )
    .unwrap()
}
pub(super) fn device_input() -> DeviceInput {
    DeviceInput {
        device_id: DEVICE_ID.to_owned(),
        signing_key: DeviceKey::from_seed(&DEVICE_SEED).public_key().to_vec(),
        access_token: ACCESS_TOKEN.to_owned(),
        #[allow(clippy::cast_precision_loss, reason = "a fixture time")]
        session_expires_at_ms: SESSION_ENDS as f64,
    }
}
pub(super) fn runner() -> TrustedRunner {
    TrustedRunner::new(
        RunnerCoordinate {
            id: RUNNER_ID,
            key_epoch: 3,
        },
        RunnerPins {
            encryption: RunnerEncryptionKey::from_seed(&RUNNER_ENCRYPTION_SEED)
                .public_key()
                .to_bytes(),
            signing: RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED).public_key(),
            proof: RUNNER_PROOF,
        },
        "Build runner",
    )
    .unwrap()
}

/// What an executor does with one effect.
pub(super) enum Answer {
    Input(EffectInput),
    Frames(Vec<StreamFrame>),
    /// A watch: held open.
    Hold,
}
/// A page-side executor in a test.
pub(super) trait Hub {
    fn answer(&mut self, effect: &WireEffect) -> Answer;
}
/// A flow as the page drives it.
pub(super) trait Driven {
    fn step(&mut self, now_ms: f64) -> CloudResult<FlowStep>;
    fn answer(&mut self, id: u32, input: EffectInput);
    fn push(&mut self, id: u32, frame: StreamFrame);
}
impl Driven for WebFlow {
    fn step(&mut self, now_ms: f64) -> CloudResult<FlowStep> {
        WebFlow::step(self, now_ms)
    }
    fn answer(&mut self, id: u32, input: EffectInput) {
        self.resolve_input(id, input).unwrap();
    }
    fn push(&mut self, id: u32, frame: StreamFrame) {
        self.frame_input(id, frame);
    }
}
impl Driven for WebChat {
    fn step(&mut self, now_ms: f64) -> CloudResult<FlowStep> {
        WebChat::step(self, now_ms)
    }
    fn answer(&mut self, id: u32, input: EffectInput) {
        self.resolve_input(id, input).unwrap();
    }
    fn push(&mut self, id: u32, frame: StreamFrame) {
        self.frame_input(id, frame);
    }
}
/// Runs `flow` until it waits or ends; returns its outputs, the last step and held watch ids.
pub(super) fn drive(
    flow: &mut impl Driven,
    hub: &mut impl Hub,
    now_ms: f64,
) -> (Vec<FlowOutput>, FlowStep, Vec<u32>) {
    let mut outputs = Vec::new();
    let mut watches = Vec::new();
    loop {
        match flow.step(now_ms).unwrap() {
            FlowStep::Effect { id, effect } => match hub.answer(&effect) {
                Answer::Input(input) => flow.answer(id, input),
                Answer::Frames(frames) => frames.into_iter().for_each(|f| flow.push(id, f)),
                Answer::Hold => watches.push(id),
            },
            FlowStep::Output { output } => outputs.push(output),
            last => return (outputs, last, watches),
        }
    }
}

/// What a page's executor answers from recorded rows alone: the Store rows, the chat stream,
/// the runner's directory and its signed boot status.
#[derive(Default)]
pub(super) struct Rows {
    pub(super) collections: Vec<(WireCollection, Vec<u8>)>,
    pub(super) objects: Vec<WireObject>,
    pub(super) records: Vec<Value>,
    pub(super) directory: Vec<Value>,
    pub(super) runner_status: Vec<u8>,
}

/// The live hub of the generator: Store rows, the runner's real keys and the chat stream.
pub(super) struct Recorder {
    pub(super) rows: Rows,
    pub(super) head: Option<HeadRecordAnchor>,
    pub(super) capabilities: Map<String, Value>,
    pub(super) replies: Map<String, Value>,
    /// What the device published, in order (the runner opens its SSH commands).
    pub(super) published: Vec<WireEffect>,
}
impl Recorder {
    fn collection(&mut self, account: &WebAccount, id: &str, kind: &str) -> CollectionKey {
        let key = CollectionKey::generate().unwrap();
        let wrapped = key.seal_for(&account.account, id).unwrap();
        self.rows.collections.push((
            WireCollection {
                collection_id: id.to_owned(),
                kind: kind.to_owned(),
                personal: true,
                deleted: false,
            },
            wrapped,
        ));
        key
    }
    fn object(&mut self, collection: &str, object: &str, kind: &str, ciphertext: Vec<u8>) {
        self.rows.objects.push(WireObject {
            collection_id: collection.to_owned(),
            object_id: object.to_owned(),
            kind: kind.to_owned(),
            version: 1,
            deleted: false,
            ciphertext,
        });
    }
    fn chat_head(&self) -> ChatHead {
        ChatHead {
            chat_id: CHAT_ID,
            chat_key_epoch: 1,
            current_writer: Some(1),
            control_revision: self.head.as_ref().map_or(0, |a| a.position.sequence),
            deleted: false,
            head: self.head.clone(),
            retained_from: 1,
            snapshot: None,
        }
    }
    fn probe(&mut self, scope: &[u8], probe_id: &[u8], ciphertext: &[u8]) -> EffectInput {
        let runner = RunnerEncryptionKey::from_seed(&RUNNER_ENCRYPTION_SEED);
        let parsed = HeadProbeScope::from_canonical_bytes(scope).unwrap();
        let id: [u8; 16] = probe_id.try_into().unwrap();
        let query = open_head_query(&runner, &parsed, id, ciphertext, NOW).unwrap();
        let query = query.query().clone();
        let value = match &query.target {
            HeadTarget::Catalog { after } => HeadValue::Catalog(Box::new(CatalogHeadPage {
                revision: 7,
                digest: [0x77; 32],
                total_chats: 1,
                after: after.clone(),
                chats: vec![self.chat_head()],
                has_more: false,
            })),
            HeadTarget::Chat { .. } => HeadValue::Chat(Box::new(self.chat_head())),
            HeadTarget::CommandReceipt { .. } => {
                HeadValue::CommandReceipt(ReceiptOutcome::NotFound)
            }
        };
        let witness = RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED)
            .attest_head(HeadWitness {
                query,
                observed_at_ms: NOW + 5,
                value,
            })
            .unwrap();
        let sealed = seal_head_witness(&runner, &witness).unwrap();
        self.replies.insert(
            hex::encode(probe_id),
            json!({ "scope": hex::encode(scope), "ciphertext": hex::encode(&sealed) }),
        );
        EffectInput::ProbeReply {
            scope: scope.to_vec(),
            probe_id: probe_id.to_vec(),
            ciphertext: sealed,
        }
    }
}
impl Hub for Recorder {
    fn answer(&mut self, effect: &WireEffect) -> Answer {
        match effect {
            WireEffect::Capabilities { nonce } => {
                let (claim, signature) = capability_proof(nonce.as_slice().try_into().unwrap());
                self.capabilities.insert(
                    hex::encode(nonce),
                    json!({ "claim": hex::encode(&claim), "signature": hex::encode(&signature) }),
                );
                Answer::Input(EffectInput::Capabilities { claim, signature })
            }
            WireEffect::Probe {
                scope,
                probe_id,
                ciphertext,
                ..
            } => Answer::Input(self.probe(scope, probe_id, ciphertext)),
            WireEffect::Publish { .. } => {
                self.published.push(effect.clone());
                store_answer(&self.rows, effect)
            }
            effect => store_answer(&self.rows, effect),
        }
    }
}

/// Every answer a page derives from recorded rows alone (all but capabilities and probes).
pub(super) fn store_answer(rows: &Rows, effect: &WireEffect) -> Answer {
    let Rows {
        collections,
        objects,
        records,
        directory,
        runner_status,
    } = rows;
    let failed = |failure: &str| {
        Answer::Input(EffectInput::Failed {
            failure: failure.to_owned(),
        })
    };
    match effect {
        WireEffect::Sign { bytes, .. } => Answer::Input(EffectInput::Signature {
            signature: DeviceKey::from_seed(&DEVICE_SEED).sign(bytes).to_vec(),
        }),
        WireEffect::ListCollections { collection_kind } => {
            Answer::Input(EffectInput::Collections {
                collections: collections
                    .iter()
                    .filter(|(c, _)| &c.kind == collection_kind)
                    .map(|(c, _)| c.clone())
                    .collect(),
            })
        }
        WireEffect::GetCollectionKey { collection_id } => collections
            .iter()
            .find(|(c, _)| &c.collection_id == collection_id)
            .map_or_else(
                || failed("not_found"),
                |(_, wrapped)| {
                    Answer::Input(EffectInput::CollectionKey {
                        wrapped_key: wrapped.clone(),
                        granted_by: None,
                    })
                },
            ),
        WireEffect::GetObject {
            collection_id,
            object_id,
        } => objects
            .iter()
            .find(|o| &o.collection_id == collection_id && &o.object_id == object_id)
            .map_or_else(
                || failed("not_found"),
                |o| Answer::Input(EffectInput::Object { object: o.clone() }),
            ),
        WireEffect::Replay {
            selector,
            after_cursor,
            ..
        } => Answer::Frames(replay(
            if selector.directory {
                directory
            } else {
                records
            },
            *after_cursor,
        )),
        WireEffect::Watch { .. } => Answer::Hold,
        WireEffect::Publish { publication, .. } => Answer::Input(EffectInput::Receipt {
            publication_id: publication.publication_id.clone(),
            cursor: 1,
            ciphertext_sha256: publication.ciphertext_sha256.clone(),
        }),
        WireEffect::ListInstances => Answer::Input(EffectInput::Instances {
            instances: Vec::new(),
        }),
        WireEffect::RunnerStatus { .. } if !runner_status.is_empty() => {
            Answer::Input(EffectInput::RunnerStatus {
                signed_status: runner_status.clone(),
            })
        }
        _ => failed("refused"),
    }
}

/// One replay page of recorded records after `after`.
pub(super) fn replay(records: &[Value], after: u64) -> Vec<StreamFrame> {
    let mut frames = Vec::new();
    let mut through = after;
    for record in records
        .iter()
        .filter(|r| r["cursor"].as_u64().unwrap() > after)
    {
        let id = hex_of(record, "publicationId");
        frames.push(StreamFrame::Header {
            publication_id: id.clone(),
            binding: hex_of(record, "binding"),
            total_bytes: u32::try_from(record["totalBytes"].as_u64().unwrap()).unwrap(),
            ciphertext_sha256: hex_of(record, "ciphertextSha256"),
            cursor: record["cursor"].as_u64().unwrap(),
            origin_account_id: ACCOUNT.to_owned(),
            origin_signing_key: RUNNER_PROOF.to_vec(),
            origin_runner_id: Some(RUNNER_ID.to_vec()),
        });
        frames.push(StreamFrame::Data {
            bytes: hex_of(record, "data"),
        });
        frames.push(StreamFrame::End { publication_id: id });
        through = record["cursor"].as_u64().unwrap();
    }
    frames.push(StreamFrame::PageEnd {
        through_cursor: through,
        has_more: false,
    });
    frames
}

fn capability_proof(nonce: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
    capability_proof_with_features(nonce, 0)
}
fn capability_proof_with_features(nonce: [u8; 16], extra: u64) -> (Vec<u8>, Vec<u8>) {
    let authority = DeviceKey::from_seed(&AUTHORITY_SEED);
    let claim = CapabilitiesClaim::new(
        CloudTextId::new(RAW_HUB).unwrap(),
        authority.public_key(),
        CapabilityLimits {
            features: CapabilityLimits::v1().features
                | CLOUD_FEATURE_FRESH_HEAD
                | CLOUD_FEATURE_UNARY_PUBLISH
                | CLOUD_FEATURE_CHAT_KEY_MATERIAL
                | CLOUD_FEATURE_CHAT_DIRECTORY
                | extra,
            ..CapabilityLimits::v1()
        },
        nonce,
        CapabilityWindow {
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
        },
    )
    .unwrap();
    let bytes = claim.canonical_bytes().unwrap();
    let signature = authority.sign(&bytes).to_vec();
    (bytes, signature)
}

/// The account's Store rows: two hub-trust records (one for another hub), the registry and
/// the chat's wrapped key.
fn store(recorder: &mut Recorder, account: &WebAccount, chat_key: &ChatKey) -> ChatSelector {
    let public = account.pair.public_key().to_bytes();
    let mut trust = None;
    for (raw_hub, origin) in [
        (RAW_HUB, "hub.example.org:7443"),
        ("hub-2", "other.example.org:7443"),
    ] {
        let record = HubTrustRecord::new(
            origin,
            raw_hub,
            ACCOUNT,
            Sha256::digest(public).into(),
            DeviceKey::from_seed(&AUTHORITY_SEED).public_key(),
        )
        .unwrap();
        let id = record.collection_id().unwrap();
        let key = recorder.collection(account, &id, HUB_TRUST_KIND);
        let sealed = key
            .seal_object(
                &id,
                HUB_TRUST_OBJECT,
                HUB_TRUST_KIND,
                &record.encode().unwrap(),
            )
            .unwrap();
        recorder.object(&id, HUB_TRUST_OBJECT, HUB_TRUST_KIND, sealed);
        trust.get_or_insert(record);
    }
    let scope = trust.unwrap().scope().unwrap();
    let registry_id = RunnerRegistry::collection_id(&scope).unwrap();
    let key = recorder.collection(account, &registry_id, RUNNER_REGISTRY_KIND);
    let rows = RunnerRegistry::new(scope.clone(), vec![runner()]).unwrap();
    let sealed = key
        .seal_object(
            &registry_id,
            RUNNER_REGISTRY_OBJECT,
            RUNNER_REGISTRY_KIND,
            &rows.encode().unwrap(),
        )
        .unwrap();
    recorder.object(
        &registry_id,
        RUNNER_REGISTRY_OBJECT,
        RUNNER_REGISTRY_KIND,
        sealed,
    );
    let selector = ChatSelector::new(
        scope.clone(),
        runner().runner(),
        CHAT_ID,
        1,
        runner().pins(),
    )
    .unwrap();
    let material_id = account_collection_id(&scope, CHAT_MATERIAL_KIND).unwrap();
    let key = recorder.collection(account, &material_id, CHAT_MATERIAL_KIND);
    let material = ChatMaterialRecord::wrap(selector.clone(), chat_key, &account.account).unwrap();
    recorder.object(
        &material_id,
        &selector.object_id().unwrap(),
        CHAT_MATERIAL_KIND,
        material.seal(&key).unwrap(),
    );
    selector
}

fn rows_json(recorder: &Recorder) -> (Vec<Value>, Vec<Value>) {
    let collections = recorder
        .rows
        .collections
        .iter()
        .map(|(c, wrapped)| {
            json!({
                "collectionId": c.collection_id, "kind": c.kind, "personal": c.personal,
                "deleted": c.deleted, "wrappedKey": hex::encode(wrapped),
            })
        })
        .collect();
    let objects = recorder
        .rows
        .objects
        .iter()
        .map(|o| {
            json!({
                "collectionId": o.collection_id, "objectId": o.object_id, "kind": o.kind,
                "version": o.version, "deleted": o.deleted,
                "ciphertext": hex::encode(&o.ciphertext),
            })
        })
        .collect();
    (collections, objects)
}

/// The directory checkpoint a listing reported.
fn directory_checkpoint(outputs: Vec<FlowOutput>) -> Vec<u8> {
    outputs
        .into_iter()
        .find_map(|output| match output {
            FlowOutput::Directory { bytes, .. } => Some(bytes),
            _ => None,
        })
        .unwrap()
}

/// Runs the documented order against the live recorder, then a lease (it draws no recorded
/// nonce, but must reach its first lease with these rows); returns the device and its first
/// open of the chat.
fn run_order(
    account: &WebAccount,
    recorder: &mut Recorder,
    chat_id: &str,
) -> (CloudDevice, WebChat) {
    let device = CloudDevice::made(account, device_input()).unwrap();
    let mut connect = device.discover(
        RAW_HUB,
        None,
        nocterm_cloud_device::nonces::Nonces::seeded(NONCE_SEED),
    );
    drive(&mut connect, recorder, NOW_MS);
    let watching = ListOptions {
        directories: None,
        watch: Some(true),
    };
    let (listed, ..) = drive(
        &mut device.listing_with(watching).unwrap(),
        recorder,
        NOW_MS,
    );
    let directory = directory_checkpoint(listed);
    let mut chat = device.opened(chat_id, None).unwrap();
    let (outputs, ..) = drive(&mut chat, recorder, NOW_MS);
    let checkpoint = outputs
        .into_iter()
        .find_map(|output| match output {
            FlowOutput::Checkpoint { bytes } => Some(bytes),
            _ => None,
        })
        .unwrap();
    drive(
        &mut device.opened(chat_id, Some(checkpoint)).unwrap(),
        recorder,
        NOW_MS,
    );
    let relist = ListOptions {
        directories: Some(vec![serde_bytes::ByteBuf::from(directory)]),
        watch: Some(true),
    };
    drive(&mut device.listing_with(relist).unwrap(), recorder, NOW_MS);
    let (leased, ..) = drive(
        &mut device.leasing(&chat, lease::OWN_AGENT).unwrap(),
        recorder,
        NOW_MS,
    );
    assert!(
        leased
            .iter()
            .any(|output| matches!(output, FlowOutput::Lease { .. })),
        "{leased:?}"
    );
    (device, chat)
}

/// The session file: the recorded rows and answers of `run_order`.
fn generate() -> Value {
    let account = account();
    let chat_key = ChatKey::generate().unwrap();
    let mut recorder = Recorder {
        rows: Rows::default(),
        head: None,
        capabilities: Map::new(),
        replies: Map::new(),
        published: Vec::new(),
    };
    let selector = store(&mut recorder, &account, &chat_key);
    ssh::store(&mut recorder, &account);
    let own = lease::store(&mut recorder, &account, &selector);
    recorder.rows.runner_status = hex_of(&own, "runnerStatus");
    let sealed = chat::records(&selector, &chat_key);
    let (visible, later) = sealed.split_at(6);
    let (summary, later_summary) = directory::records(
        &selector,
        &account,
        &visible[5].1,
        &later[0].1,
        NOW - 600_000 + 7_000,
    );
    recorder.rows.records = visible.iter().map(|(r, _)| r.clone()).collect();
    recorder.rows.directory = vec![summary];
    recorder.head = Some(visible[5].1.clone());
    let chat_id = nocterm_cloud_device::context::ChatRef::of(&selector).to_string();
    let (device, mut chat) = run_order(&account, &mut recorder, &chat_id);
    // The SSH part follows once the later text record is in the stream.
    let visible_records = recorder.rows.records.clone();
    recorder
        .rows
        .records
        .extend(later.iter().map(|(r, _)| r.clone()));
    let mut ssh = ssh::record(
        &mut recorder,
        &account,
        &device,
        &mut chat,
        &selector,
        &chat_key,
    );
    recorder.rows.records = visible_records;
    let (collections, objects) = rows_json(&recorder);
    // The trust collection is the `ssh` part's: an account without it has no CA.
    let trust = |row: &Value| row["kind"] == nocterm_cloud_device::records::SSH_TRUST_KIND;
    let (trust_collections, collections): (Vec<_>, Vec<_>) =
        collections.into_iter().partition(trust);
    let (trust_objects, objects): (Vec<_>, Vec<_>) = objects.into_iter().partition(trust);
    ssh["collection"] = trust_collections.into_iter().next().unwrap();
    ssh["objects"] = Value::Array(trust_objects);
    json!({
        "comment": "Generated by crates/keys-wasm/src/cloud/fixture/mod.rs; public test values only.",
        "order": "connectSeeded(rawHub, null, nonceSeed); listChats({watch: true}); openChat(chat.chatId); openChat(chat.chatId, checkpoint of the first); listChats({directories: [directory of the first listing], watch: true}); with ssh.collection, ssh.objects and chat.later + ssh.records in the stream: openChat(chat.chatId), then answerSsh(ssh.request.requestId)",
        "now": NOW,
        "rawHub": RAW_HUB,
        "accountId": ACCOUNT,
        "nonceSeed": hex::encode(NONCE_SEED),
        "device": {
            "deviceId": DEVICE_ID,
            "seed": hex::encode(DEVICE_SEED),
            "publicKey": hex::encode(DeviceKey::from_seed(&DEVICE_SEED).public_key()),
            "accessToken": ACCESS_TOKEN,
            "sessionExpiresAtMs": SESSION_ENDS,
        },
        "runner": {
            "runnerId": hex::encode(RUNNER_ID),
            "keyEpoch": 3,
            "label": "Build runner",
            "proofKey": hex::encode(RUNNER_PROOF),
        },
        "collections": collections,
        "objects": objects,
        "capabilities": recorder.capabilities,
        "fragmentedCapabilities": fragmented_capabilities(&recorder.capabilities),
        "probeReplies": recorder.replies,
        "chat": {
            "chatId": chat_id,
            "run": hex::encode(RUN.id),
            "prompt": PROMPT,
            "answer": ANSWER,
            "records": recorder.rows.records,
            "later": later.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>(),
        },
        "directory": {
            "agentId": directory::AGENT_ID,
            "records": recorder.rows.directory,
            "later": [later_summary],
        },
        "own": own,
        "ssh": ssh,
    })
}

fn fragmented_capabilities(original: &Map<String, Value>) -> Map<String, Value> {
    original
        .keys()
        .map(|nonce| {
            let (claim, signature) = capability_proof_with_features(
                hex::decode(nonce).unwrap().try_into().unwrap(),
                nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_FRAGMENTED_PUBLISH,
            );
            (
                nonce.clone(),
                json!({"claim": hex::encode(claim), "signature": hex::encode(signature)}),
            )
        })
        .collect()
}

#[test]
#[ignore = "adds the additive signed fragmented-publication capability proofs"]
fn write_fragmented_capability_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/cloud-device-v1/web-session.json"
    );
    let mut session = replay::recorded();
    session["fragmentedCapabilities"] = Value::Object(fragmented_capabilities(
        session["capabilities"].as_object().unwrap(),
    ));
    std::fs::write(path, serde_json::to_string_pretty(&session).unwrap() + "\n").unwrap();
}

#[test]
#[ignore = "writes the fixture; run explicitly after a format change"]
fn write_web_session_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/cloud-device-v1/web-session.json"
    );
    let text = serde_json::to_string_pretty(&generate()).unwrap();
    std::fs::write(path, text + "\n").unwrap();
}
