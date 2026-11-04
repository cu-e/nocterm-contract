//! A recorded browser session over the device flows, of the account the panel's own fixtures
//! unlock (`acc-1`, login password `correct horse battery` of `alice` on `hub-1`).
//! `fixtures/cloud-device-v1/web-session.json` holds the output; the panel replays it against
//! the real wasm module (a `testing` build): `connectSeeded(rawHub, null, nonceSeed)`, then
//! `listChats()`, then `openChat(chat.chatId)`, then `openChat(chat.chatId, checkpoint)`, in this
//! order, so every probe id is one with a recorded reply. Regenerate with
//! `cargo test -p nocterm-keys-wasm write_web_session_fixture -- --ignored` (fresh random keys
//! each time: copy the file into the panel afterwards).
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
    CloudTextId, CommandIssuer, CommandKind, RecordContext, RecordKind, RecordPosition,
    RunCoordinate, RunnerCoordinate,
    capabilities::{
        CLOUD_FEATURE_CHAT_KEY_MATERIAL, CLOUD_FEATURE_FRESH_HEAD, CLOUD_FEATURE_UNARY_PUBLISH,
        CapabilitiesClaim, CapabilityLimits, CapabilityWindow,
    },
    events::{
        AcceptedCommand, AcceptedPrompt, CloudEvent, CloudEventPayload, CloudRunStatus,
        CloudTextChannel, CloudUsage,
    },
    head::{
        CatalogHeadPage, ChatHead, HeadProbeScope, HeadRecordAnchor, HeadTarget, HeadValue,
        HeadWitness, ReceiptOutcome,
    },
    payload::{ModelSelection, PromptPart},
    relay::RelayBinding,
};
use nocterm_keys::{
    CollectionKey, DeviceKey,
    cloud::{
        ChatKey, RunnerEncryptionKey, RunnerSigningKey, open_head_query, seal_event,
        seal_head_witness,
    },
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{
    CloudDevice, CloudResult, WebChat, WebFlow,
    types::{
        DeviceInput, EffectInput, FlowOutput, FlowStep, StreamFrame, WireCollection, WireEffect,
        WireObject,
    },
};
use crate::WebAccount;

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
        self.frame(id, frame);
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

/// The live hub of the generator: Store rows, the runner's real keys and the chat stream.
pub(super) struct Recorder {
    pub(super) collections: Vec<(WireCollection, Vec<u8>)>,
    pub(super) objects: Vec<WireObject>,
    pub(super) records: Vec<Value>,
    pub(super) head: Option<HeadRecordAnchor>,
    pub(super) capabilities: Map<String, Value>,
    pub(super) replies: Map<String, Value>,
}
impl Recorder {
    fn collection(&mut self, account: &WebAccount, id: &str, kind: &str) -> CollectionKey {
        let key = CollectionKey::generate().unwrap();
        let wrapped = key.seal_for(&account.account, id).unwrap();
        self.collections.push((
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
        self.objects.push(WireObject {
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
            effect => store_answer(&self.collections, &self.objects, &self.records, effect),
        }
    }
}

/// Every answer a page derives from recorded rows alone (all but capabilities and probes).
pub(super) fn store_answer(
    collections: &[(WireCollection, Vec<u8>)],
    objects: &[WireObject],
    records: &[Value],
    effect: &WireEffect,
) -> Answer {
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
                        granted_by: String::new(),
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
        WireEffect::Replay { after_cursor, .. } => Answer::Frames(replay(records, *after_cursor)),
        WireEffect::Watch { .. } => Answer::Hold,
        WireEffect::Publish { publication, .. } => Answer::Input(EffectInput::Receipt {
            publication_id: publication.publication_id.clone(),
            cursor: 1,
            ciphertext_sha256: publication.ciphertext_sha256.clone(),
        }),
        WireEffect::ListInstances => Answer::Input(EffectInput::Instances {
            instances: Vec::new(),
        }),
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
    let authority = DeviceKey::from_seed(&AUTHORITY_SEED);
    let claim = CapabilitiesClaim::new(
        CloudTextId::new(RAW_HUB).unwrap(),
        authority.public_key(),
        CapabilityLimits {
            features: CapabilityLimits::v1().features
                | CLOUD_FEATURE_FRESH_HEAD
                | CLOUD_FEATURE_UNARY_PUBLISH
                | CLOUD_FEATURE_CHAT_KEY_MATERIAL,
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

/// The chat's events: the device's prompt, the run starting, the assistant's text, a tool call
/// waiting for approval (the public `approval` vector), usage, the waiting status, and one later
/// line of text that arrives by Watch.
fn events(at: u64) -> Vec<Vec<u8>> {
    let issuer = CommandIssuer {
        device_id: CloudTextId::new(DEVICE_ID).unwrap(),
        signing_key: DeviceKey::from_seed(&DEVICE_SEED).public_key(),
        access_token_digest: Sha256::digest(ACCESS_TOKEN.as_bytes()).into(),
    };
    let model = ModelSelection {
        provider: CloudTextId::new("managed").unwrap(),
        model: CloudTextId::new("gpt-5-mini").unwrap(),
        pricing_policy: CloudTextId::new("managed-v1").unwrap(),
    };
    let event = |revision: u64, payload: CloudEventPayload<'static>| {
        CloudEvent {
            control_revision: revision,
            timestamp_ms: at + revision * 1_000,
            payload,
        }
        .canonical_bytes()
        .unwrap()
    };
    let approval_bytes =
        hex::decode(include_str!("../../../../fixtures/cloud-events-v1/approval.hex").trim())
            .unwrap();
    let mut approval = CloudEvent::from_canonical_bytes(&approval_bytes).unwrap();
    approval.control_revision = 4;
    approval.timestamp_ms = at + 4_000;
    let text = |revision, step, text| {
        event(
            revision,
            CloudEventPayload::Text {
                run: RUN,
                step: Some([step; 16]),
                channel: CloudTextChannel::Assistant,
                text,
            },
        )
    };
    let prompt = CloudEventPayload::PromptAccepted {
        command: AcceptedCommand {
            id: [0x11; 16],
            kind: CommandKind::SubmitPrompt,
            signed_message_digest: [0x12; 32],
            issuer,
            expected_control_revision: 0,
        },
        run: RUN,
        prompt: Box::new(AcceptedPrompt {
            content: vec![PromptPart::Text(PROMPT)],
            model,
            target: None,
            existing_session: None,
        }),
    };
    let usage = CloudUsage {
        input_tokens: Some(812),
        output_tokens: Some(64),
        total_tokens: Some(876),
        cached_input_tokens: None,
        thought_tokens: None,
        cost_micros: Some(1_250),
    };
    let status = |status| CloudEventPayload::Status { run: RUN, status };
    vec![
        event(1, prompt),
        event(2, status(CloudRunStatus::Running)),
        text(3, 0x31, ANSWER),
        approval.canonical_bytes().unwrap(),
        event(5, CloudEventPayload::Usage { run: RUN, usage }),
        event(6, status(CloudRunStatus::WaitingApproval)),
        text(7, 0x32, LATER),
    ]
}

/// The sealed records as the runner publishes them.
fn records(selector: &ChatSelector, key: &ChatKey) -> Vec<(Value, HeadRecordAnchor)> {
    let signer = RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED);
    let bodies = events(u64::try_from(NOW - 600_000).unwrap());
    bodies
        .iter()
        .enumerate()
        .map(|(index, body)| {
            let sequence = u64::try_from(index + 1).unwrap();
            let tag = u8::try_from(sequence).unwrap();
            let position = RecordPosition {
                writer_epoch: 1,
                sequence,
                journal_sequence: sequence,
                revision: sequence,
            };
            let context = RecordContext::new(
                selector.coordinate().unwrap(),
                position,
                [tag; 16],
                Some(RUN),
            )
            .unwrap();
            let sealed = seal_event(key, &signer, context.clone(), body).unwrap();
            let digest: [u8; 32] = Sha256::digest(&sealed).into();
            let anchor = HeadRecordAnchor {
                kind: RecordKind::Event,
                position: context.position(),
                id: context.id(),
                run: context.run(),
                ciphertext_digest: digest,
            };
            let record = json!({
                "publicationId": hex::encode([0xa0 + tag; 16]),
                "binding": hex::encode(RelayBinding::event(context).canonical_bytes().unwrap()),
                "totalBytes": sealed.len(),
                "ciphertextSha256": hex::encode(digest),
                "cursor": sequence,
                "originAccountId": ACCOUNT,
                "originSigningKey": hex::encode(RUNNER_PROOF),
                "originRunnerId": hex::encode(RUNNER_ID),
                "data": hex::encode(&sealed),
            });
            (record, anchor)
        })
        .collect()
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

/// Runs the documented order against the live recorder and returns the session file.
fn generate() -> Value {
    let account = account();
    let chat_key = ChatKey::generate().unwrap();
    let mut recorder = Recorder {
        collections: Vec::new(),
        objects: Vec::new(),
        records: Vec::new(),
        head: None,
        capabilities: Map::new(),
        replies: Map::new(),
    };
    let selector = store(&mut recorder, &account, &chat_key);
    let sealed = records(&selector, &chat_key);
    let (visible, later) = sealed.split_at(6);
    recorder.records = visible.iter().map(|(r, _)| r.clone()).collect();
    recorder.head = Some(visible[5].1.clone());
    let device = CloudDevice::made(&account, device_input()).unwrap();
    let mut connect = device.discover(
        RAW_HUB,
        None,
        nocterm_cloud_device::nonces::Nonces::seeded(NONCE_SEED),
    );
    drive(&mut connect, &mut recorder, NOW_MS);
    drive(&mut device.listing().unwrap(), &mut recorder, NOW_MS);
    let chat_id = nocterm_cloud_device::context::ChatRef::of(&selector).to_string();
    let mut chat = device.opened(&chat_id, None).unwrap();
    let (outputs, ..) = drive(&mut chat, &mut recorder, NOW_MS);
    let checkpoint = outputs
        .into_iter()
        .find_map(|output| match output {
            FlowOutput::Checkpoint { bytes } => Some(bytes),
            _ => None,
        })
        .unwrap();
    drive(
        &mut device.opened(&chat_id, Some(checkpoint)).unwrap(),
        &mut recorder,
        NOW_MS,
    );
    let (collections, objects) = rows_json(&recorder);
    json!({
        "comment": "Generated by crates/keys-wasm/src/cloud/fixture.rs; public test values only.",
        "order": "connectSeeded(rawHub, null, nonceSeed); listChats(); openChat(chat.chatId); openChat(chat.chatId, checkpoint of the first)",
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
        "probeReplies": recorder.replies,
        "chat": {
            "chatId": chat_id,
            "run": hex::encode(RUN.id),
            "prompt": PROMPT,
            "answer": ANSWER,
            "records": recorder.records,
            "later": later.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>(),
        },
    })
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
