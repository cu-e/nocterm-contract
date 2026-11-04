//! A recorded browser session of the account the panel's own fixtures unlock (`acc-1`, login
//! password `correct horse battery` of `alice` on `hub-1`): hub trust, the capability proof, the
//! trusted runner registry, a catalog and a chat witness to probes with fixed nonces, the chat's
//! wrapped key and its sealed records. `fixtures/cloud-device-v1/web-session.json` holds the
//! output; the panel tests the real wasm module against the same file. Regenerate with
//! `cargo test -p nocterm-keys-wasm write_web_session_fixture -- --ignored` (fresh random keys
//! each time: copy the file into the panel afterwards).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use nocterm_cloud_device::records::{
    ChatMaterialRecord, ChatSelector, HUB_TRUST_KIND, HUB_TRUST_OBJECT, HubTrustRecord,
    RUNNER_REGISTRY_KIND, RUNNER_REGISTRY_OBJECT, RunnerPins, RunnerRegistry, TrustedRunner,
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
    head::{CatalogHeadPage, ChatHead, HeadProbeScope, HeadRecordAnchor, HeadValue, HeadWitness},
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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{WebCloud, WebDevice, WebProbe, WebStoredObject};
use crate::{WebAccount, WebCollectionKey};

pub(super) const NOW: i64 = 1_800_000_000_000;
/// [`NOW`] as the page passes it.
pub(super) const NOW_MS: f64 = 1_800_000_000_000.0;
pub(super) const RAW_HUB: &str = "hub-1";
pub(super) const ACCOUNT: &str = "acc-1";
pub(super) const DEVICE_ID: &str = "device-web";
pub(super) const ACCESS_TOKEN: &str = "access-token";
pub(super) const SESSION_ENDS: i64 = NOW + 3_600_000;
pub(super) const DEVICE_SEED: [u8; 32] = [0x61; 32];
pub(super) const AUTHORITY_SEED: [u8; 32] = [0x21; 32];
pub(super) const RUNNER_ENCRYPTION_SEED: [u8; 32] = [0x41; 32];
pub(super) const RUNNER_SIGNING_SEED: [u8; 32] = [0x51; 32];
pub(super) const RUNNER_PROOF: [u8; 32] = [0x71; 32];
pub(super) const RUNNER_ID: [u8; 16] = [0x02; 16];
pub(super) const CHAT_ID: [u8; 16] = [0x05; 16];
pub(super) const CAPABILITY_NONCE: [u8; 16] = [0x4e; 16];
pub(super) const CATALOG_NONCES: ([u8; 16], [u8; 32]) = ([0xc1; 16], [0xc2; 32]);
pub(super) const CHAT_NONCES: ([u8; 16], [u8; 32]) = ([0xd1; 16], [0xd2; 32]);
/// The run of the public event vectors (`fixtures/cloud-events-v1`).
pub(super) const RUN: RunCoordinate = RunCoordinate {
    id: [0x21; 16],
    expected_epoch: 2,
};
pub(super) const PROMPT: &str = "Which services listen on the build host?";
pub(super) const ANSWER: &str =
    "I'll list the listening sockets:\n\n```sh\nss -tlnp\n```\n\nThis needs your approval.";

/// The `LOGIN_KEYSET` of the panel's `keyset-fixtures.ts`.
const WRAPPED_ACCOUNT_KEY: &str = "010131b0c155b255a2b91b9b977e254520dd4557bbf759a4a7b90a98d26142f229802093d52190a71dd80795fa0d7b93d5b9e10719ffbf382d7a489f371f48a7dc1545949026c5dd1278";
const SEALED_PRIVATE_KEY: &str = "010566cca7d3cd3dc833416c7edb3cfbef66156c91afaffdbbf0911390f218bdea13a3b106de958fe1ebb0ed53693b7b5e279cbf937497575f4711fb4e17ba4176bb31fa67c76b833d1b";
const PUBLIC_KEY: &str = "c13c5522ce9483ee79f3fe4302ad0439aeab7e5b1ea17869c10ff51b984a1c44";

pub(super) fn bytes(value: &Value, name: &str) -> Vec<u8> {
    hex::decode(value[name].as_str().unwrap_or_else(|| panic!("{name}"))).unwrap()
}

/// The checked-in session.
pub(super) fn recorded() -> Value {
    serde_json::from_str(include_str!(
        "../../../../fixtures/cloud-device-v1/web-session.json"
    ))
    .unwrap()
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

pub(super) fn device() -> WebDevice {
    WebDevice::identified(
        DEVICE_ID,
        &DeviceKey::from_seed(&DEVICE_SEED).public_key(),
        ACCESS_TOKEN,
        1_800_003_600_000.0,
    )
    .unwrap()
}

pub(super) fn stored(collection: &str, object: &Value) -> WebStoredObject {
    WebStoredObject::new(
        collection.to_owned(),
        object["objectId"].as_str().unwrap().to_owned(),
        object["kind"].as_str().unwrap().to_owned(),
        object["version"].as_u64().unwrap(),
        false,
        bytes(object, "ciphertext"),
    )
}

fn runner() -> TrustedRunner {
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

/// A collection of the account: its key wrapped for the account key.
fn collection(account: &WebAccount, id: &str) -> (CollectionKey, Value) {
    let key = CollectionKey::generate().unwrap();
    let wrapped = key.seal_for(&account.account, id).unwrap();
    (
        key,
        json!({ "collectionId": id, "wrappedKey": hex::encode(wrapped) }),
    )
}

fn hub_trust(account: &WebAccount, raw_hub: &str, origin: &str) -> Value {
    let record = HubTrustRecord::new(
        origin,
        raw_hub,
        ACCOUNT,
        Sha256::digest(account.pair.public_key().to_bytes()).into(),
        DeviceKey::from_seed(&AUTHORITY_SEED).public_key(),
    )
    .unwrap();
    let id = record.collection_id().unwrap();
    let (key, mut value) = collection(account, &id);
    let sealed = key
        .seal_object(
            &id,
            HUB_TRUST_OBJECT,
            HUB_TRUST_KIND,
            &record.encode().unwrap(),
        )
        .unwrap();
    value["object"] = json!({
        "objectId": HUB_TRUST_OBJECT, "kind": HUB_TRUST_KIND, "version": 1,
        "ciphertext": hex::encode(sealed),
    });
    value
}

fn capabilities() -> Value {
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
        CAPABILITY_NONCE,
        CapabilityWindow {
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
        },
    )
    .unwrap();
    let bytes = claim.canonical_bytes().unwrap();
    json!({
        "nonce": hex::encode(CAPABILITY_NONCE),
        "claim": hex::encode(&bytes),
        "signature": hex::encode(authority.sign(&bytes)),
    })
}

/// The chat's events: the device's prompt, the run starting, the assistant's text and a tool
/// call waiting for approval (the public `approval` vector).
fn events(at: u64) -> Vec<Vec<u8>> {
    let device = DeviceKey::from_seed(&DEVICE_SEED);
    let issuer = CommandIssuer {
        device_id: CloudTextId::new(DEVICE_ID).unwrap(),
        signing_key: device.public_key(),
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
    vec![
        event(
            1,
            CloudEventPayload::PromptAccepted {
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
            },
        ),
        event(
            2,
            CloudEventPayload::Status {
                run: RUN,
                status: CloudRunStatus::Running,
            },
        ),
        event(
            3,
            CloudEventPayload::Text {
                run: RUN,
                step: Some([0x31; 16]),
                channel: CloudTextChannel::Assistant,
                text: ANSWER,
            },
        ),
        approval.canonical_bytes().unwrap(),
        event(
            5,
            CloudEventPayload::Usage {
                run: RUN,
                usage: CloudUsage {
                    input_tokens: Some(812),
                    output_tokens: Some(64),
                    total_tokens: Some(876),
                    cached_input_tokens: None,
                    thought_tokens: None,
                    cost_micros: Some(1_250),
                },
            },
        ),
        event(
            6,
            CloudEventPayload::Status {
                run: RUN,
                status: CloudRunStatus::WaitingApproval,
            },
        ),
    ]
}

/// Seals the events as the runner publishes them; returns the delivered records and the head.
fn records(selector: &ChatSelector, key: &ChatKey) -> (Vec<Value>, ChatHead) {
    let signer = RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED);
    let mut delivered = Vec::new();
    let mut last = None;
    let bodies = events(u64::try_from(NOW - 600_000).unwrap());
    for (index, body) in bodies.iter().enumerate() {
        let sequence = u64::try_from(index + 1).unwrap();
        let tag = u8::try_from(sequence).unwrap();
        let context = RecordContext::new(
            selector.coordinate().unwrap(),
            RecordPosition {
                writer_epoch: 1,
                sequence,
                journal_sequence: sequence,
                revision: sequence,
            },
            [tag; 16],
            Some(RUN),
        )
        .unwrap();
        let sealed = seal_event(key, &signer, context.clone(), body).unwrap();
        let digest: [u8; 32] = Sha256::digest(&sealed).into();
        last = Some(HeadRecordAnchor {
            kind: RecordKind::Event,
            position: context.position(),
            id: context.id(),
            run: context.run(),
            ciphertext_digest: digest,
        });
        delivered.push(json!({
            "publicationId": hex::encode([0xa0 + tag; 16]),
            "binding": hex::encode(RelayBinding::event(context).canonical_bytes().unwrap()),
            "totalBytes": sealed.len(),
            "ciphertextSha256": hex::encode(digest),
            "cursor": sequence,
            "data": hex::encode(&sealed),
        }));
    }
    let head = ChatHead {
        chat_id: CHAT_ID,
        chat_key_epoch: 1,
        current_writer: Some(1),
        control_revision: 6,
        deleted: false,
        head: last,
        retained_from: 1,
        snapshot: None,
    };
    (delivered, head)
}

/// Probes with fixed nonces and the runner's sealed answer to each.
fn witnessed(
    cloud: &WebCloud,
    account: &WebAccount,
    target: &str,
    nonces: ([u8; 16], [u8; 32]),
    value: HeadValue,
) -> Value {
    let mut probe: WebProbe = cloud
        .probe(account, &device(), &RUNNER_ID, target, NOW_MS, Some(nonces))
        .unwrap();
    let signature = DeviceKey::from_seed(&DEVICE_SEED).sign(&probe.bytes().unwrap());
    probe.sealed_with(account, &signature).unwrap();
    let sealed = probe.sealed().unwrap();
    let runner = RunnerEncryptionKey::from_seed(&RUNNER_ENCRYPTION_SEED);
    let scope = HeadProbeScope::from_canonical_bytes(sealed.scope()).unwrap();
    let query =
        open_head_query(&runner, &scope, sealed.probe_id(), sealed.ciphertext(), NOW).unwrap();
    let witness = RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED)
        .attest_head(HeadWitness {
            query: query.query().clone(),
            observed_at_ms: NOW + 5,
            value,
        })
        .unwrap();
    json!({
        "target": target,
        "probeId": hex::encode(nonces.0),
        "challenge": hex::encode(nonces.1),
        "scope": hex::encode(sealed.scope()),
        "reply": hex::encode(seal_head_witness(&runner, &witness).unwrap()),
    })
}

/// The hub accepted under the record made for `RAW_HUB`.
fn accepted(account: &WebAccount, trust: &Value, caps: &Value) -> WebCloud {
    let id = trust["collectionId"].as_str().unwrap();
    let trust_key = WebCollectionKey {
        collection_id: id.to_owned(),
        key: CollectionKey::open(&account.account, id, &bytes(trust, "wrappedKey")).unwrap(),
    };
    let record = trust_key
        .hub_trust(account, RAW_HUB, &stored(id, &trust["object"]))
        .unwrap();
    WebCloud::accepted(
        account,
        &record,
        RAW_HUB,
        (
            &bytes(caps, "claim"),
            &bytes(caps, "signature"),
            &CAPABILITY_NONCE,
        ),
        NOW_MS,
    )
    .unwrap()
}

/// The registry with the one trusted runner, opened into `cloud`.
fn registry(account: &WebAccount, cloud: &mut WebCloud) -> Value {
    let scope = cloud.hub().scope().clone();
    let registry_id = RunnerRegistry::collection_id(&scope).unwrap();
    let (registry_key, mut registry) = collection(account, &registry_id);
    let rows = RunnerRegistry::new(scope, vec![runner()]).unwrap();
    registry["object"] = json!({
        "objectId": RUNNER_REGISTRY_OBJECT, "kind": RUNNER_REGISTRY_KIND, "version": 1,
        "ciphertext": hex::encode(registry_key.seal_object(
            &registry_id, RUNNER_REGISTRY_OBJECT, RUNNER_REGISTRY_KIND, &rows.encode().unwrap(),
        ).unwrap()),
    });
    cloud
        .registry_from(
            &WebCollectionKey {
                collection_id: registry_id.clone(),
                key: registry_key,
            },
            &stored(&registry_id, &registry["object"]),
        )
        .unwrap();
    registry
}

/// The chat key wrapped for the account in the material collection.
fn material(account: &WebAccount, selector: &ChatSelector, chat_key: &ChatKey) -> Value {
    let material = ChatMaterialRecord::wrap(selector.clone(), chat_key, &account.account).unwrap();
    let material_id = ChatMaterialRecord::collection_id(selector.scope()).unwrap();
    let (material_key, mut materials) = collection(account, &material_id);
    materials["object"] = json!({
        "objectId": selector.object_id().unwrap(),
        "kind": nocterm_cloud_device::records::CHAT_MATERIAL_KIND,
        "version": 1,
        "ciphertext": hex::encode(material.seal(&material_key).unwrap()),
    });
    materials
}

/// The catalog and the chat probe, each answered with `head`.
fn probes(cloud: &WebCloud, account: &WebAccount, head: ChatHead) -> (Value, Value) {
    let catalog = HeadValue::Catalog(Box::new(CatalogHeadPage {
        revision: 7,
        digest: [0x77; 32],
        total_chats: 1,
        after: None,
        chats: vec![head.clone()],
        has_more: false,
    }));
    let target = format!(
        r#"{{"chat":{{"chatId":"{}","keyEpoch":1}}}}"#,
        hex::encode(CHAT_ID)
    );
    (
        witnessed(
            cloud,
            account,
            r#"{"catalog":null}"#,
            CATALOG_NONCES,
            catalog,
        ),
        witnessed(
            cloud,
            account,
            &target,
            CHAT_NONCES,
            HeadValue::Chat(Box::new(head)),
        ),
    )
}

fn generate() -> Value {
    let account = account();
    let trust = hub_trust(&account, RAW_HUB, "hub.example.org:7443");
    let caps = capabilities();
    let mut cloud = accepted(&account, &trust, &caps);
    let registry = registry(&account, &mut cloud);
    let scope = cloud.hub().scope().clone();
    let selector = ChatSelector::new(
        scope.clone(),
        runner().runner(),
        CHAT_ID,
        1,
        runner().pins(),
    )
    .unwrap();
    let chat_key = ChatKey::generate().unwrap();
    let grant_id = nocterm_cloud_device::records::ChatGrantRecord::collection_id(&scope).unwrap();
    let (delivered, head) = records(&selector, &chat_key);
    let (catalog, chat) = probes(&cloud, &account, head);
    json!({
        "comment": "Generated by crates/keys-wasm/src/cloud/fixture.rs; public test values only.",
        "now": NOW,
        "rawHub": RAW_HUB,
        "accountId": ACCOUNT,
        "device": {
            "deviceId": DEVICE_ID,
            "seed": hex::encode(DEVICE_SEED),
            "publicKey": hex::encode(DeviceKey::from_seed(&DEVICE_SEED).public_key()),
            "accessToken": ACCESS_TOKEN,
            "sessionExpiresAtMs": SESSION_ENDS,
        },
        "hubTrust": trust,
        "otherHubTrust": hub_trust(&account, "hub-2", "other.example.org:7443"),
        "capabilities": caps,
        "registry": registry,
        "runner": {
            "runnerId": hex::encode(RUNNER_ID),
            "keyEpoch": 3,
            "label": "Build runner",
            "proofKey": hex::encode(RUNNER_PROOF),
        },
        "material": material(&account, &selector, &chat_key),
        "grants": collection(&account, &grant_id).1,
        "chat": {
            "chatId": hex::encode(CHAT_ID),
            "keyEpoch": 1,
            "run": hex::encode(RUN.id),
            "prompt": PROMPT,
            "answer": ANSWER,
            "records": delivered,
        },
        "catalogProbe": catalog,
        "chatProbe": chat,
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
