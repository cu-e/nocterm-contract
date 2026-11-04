#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use std::sync::OnceLock;

use nocterm_cloud_device::replay::{DeliveredOrigin, DeliveredRecord};
use nocterm_hub_model::cloud::{CommandKind, payload::CloudCommandPayload, relay::RelayBinding};
use nocterm_keys::{
    CollectionKey, DeviceKey, PublicKey,
    cloud::{RunnerEncryptionKey, open_command},
};
use serde_json::Value;

use super::fixture::{
    self, ACCOUNT, CAPABILITY_NONCE, CATALOG_NONCES, CHAT_NONCES, DEVICE_SEED, NOW_MS, RAW_HUB,
    RUNNER_ENCRYPTION_SEED, RUNNER_ID, bytes, recorded, stored,
};
use super::{
    WebCloud, WebCloudError, WebHubTrust,
    chat::{WebChat, WebCommand},
};
use crate::{WebAccount, WebCollectionKey};

fn account() -> &'static WebAccount {
    static ACCOUNT: OnceLock<WebAccount> = OnceLock::new();
    ACCOUNT.get_or_init(fixture::account)
}

fn key(value: &Value) -> WebCollectionKey {
    account()
        .own_collection(
            value["collectionId"].as_str().unwrap(),
            &bytes(value, "wrappedKey"),
        )
        .unwrap()
}

fn trust(value: &Value, raw_hub: &str) -> Result<WebHubTrust, WebCloudError> {
    key(value).hub_trust(
        account(),
        raw_hub,
        &stored(value["collectionId"].as_str().unwrap(), &value["object"]),
    )
}

/// The accepted hub with its registry open, as the panel holds it after discovery.
fn cloud(session: &Value) -> WebCloud {
    let caps = &session["capabilities"];
    let mut cloud = WebCloud::accepted(
        account(),
        &trust(&session["hubTrust"], RAW_HUB).unwrap(),
        RAW_HUB,
        (
            &bytes(caps, "claim"),
            &bytes(caps, "signature"),
            &CAPABILITY_NONCE,
        ),
        NOW_MS,
    )
    .unwrap();
    let registry = &session["registry"];
    cloud
        .registry_from(
            &key(registry),
            &stored(
                registry["collectionId"].as_str().unwrap(),
                &registry["object"],
            ),
        )
        .unwrap();
    cloud
}

/// Probes `name` (`catalogProbe` or `chatProbe`) with its recorded nonces and opens the reply.
fn probe(cloud: &mut WebCloud, session: &Value, name: &str, nonces: ([u8; 16], [u8; 32])) -> Value {
    let recorded = &session[name];
    let mut probe = cloud
        .probe(
            account(),
            &fixture::device(),
            &RUNNER_ID,
            recorded["target"].as_str().unwrap(),
            NOW_MS,
            Some(nonces),
        )
        .unwrap();
    let signature = DeviceKey::from_seed(&DEVICE_SEED).sign(&probe.bytes().unwrap());
    probe.sealed_with(account(), &signature).unwrap();
    let scope = probe.sealed().unwrap().scope().to_vec();
    let id = probe.sealed().unwrap().probe_id();
    let reply = cloud
        .reply(
            account(),
            &probe,
            (&scope, &id, &bytes(recorded, "reply")),
            NOW_MS + 10.0,
        )
        .unwrap();
    serde_json::from_str(&reply).unwrap()
}

fn chat(cloud: &WebCloud, session: &Value) -> WebChat {
    let material = &session["material"];
    cloud
        .chat(
            account(),
            &key(material),
            (&RUNNER_ID, session["chat"]["chatId"].as_str().unwrap(), 1),
            &stored(
                material["collectionId"].as_str().unwrap(),
                &material["object"],
            ),
        )
        .unwrap()
}

fn deliver(chat: &mut WebChat, record: &Value, proof: &[u8]) -> Result<(), WebCloudError> {
    let id = bytes(record, "publicationId");
    chat.header(&DeliveredRecord {
        publication_id: &id,
        binding: &bytes(record, "binding"),
        total_bytes: u32::try_from(record["totalBytes"].as_u64().unwrap()).unwrap(),
        ciphertext_sha256: &bytes(record, "ciphertextSha256"),
        cursor: record["cursor"].as_u64().unwrap(),
        origin: DeliveredOrigin {
            account_id: ACCOUNT,
            signing_key: proof,
            runner_id: Some(&RUNNER_ID),
        },
    })?;
    chat.data(&bytes(record, "data"))?;
    chat.end(account(), &id)
}

/// A chat whose whole recorded history was replayed against the chat probe's head.
fn replayed(session: &Value) -> (WebCloud, WebChat) {
    let mut cloud = cloud(session);
    probe(&mut cloud, session, "chatProbe", CHAT_NONCES);
    let mut chat = chat(&cloud, session);
    assert_eq!(chat.begin(&cloud).unwrap(), 0);
    let records = session["chat"]["records"].as_array().unwrap();
    let proof = bytes(&session["runner"], "proofKey");
    for record in records {
        deliver(&mut chat, record, &proof).unwrap();
    }
    assert!(chat.page(records.len() as u64, false).unwrap());
    (cloud, chat)
}

fn code(error: &WebCloudError) -> String {
    let text = error.to_string();
    text[1..text.find(']').unwrap()].to_owned()
}

#[test]
fn a_hub_trust_record_matches_only_the_hub_and_account_it_names() {
    let session = recorded();
    let here = trust(&session["hubTrust"], RAW_HUB).unwrap();
    assert!(here.matches());
    assert_eq!(here.origin(), "hub.example.org:7443");
    assert!(!trust(&session["otherHubTrust"], RAW_HUB).unwrap().matches());
    assert!(!trust(&session["hubTrust"], "hub-2").unwrap().matches());
    // An object listed under another collection is not that collection's record.
    let moved = key(&session["hubTrust"]).hub_trust(
        account(),
        RAW_HUB,
        &stored("another-collection", &session["hubTrust"]["object"]),
    );
    assert_eq!(code(&moved.unwrap_err()), "binding");
}

#[test]
fn the_capability_proof_must_answer_this_nonce_under_the_pinned_authority() {
    let session = recorded();
    let caps = &session["capabilities"];
    let record = trust(&session["hubTrust"], RAW_HUB).unwrap();
    let answer = |nonce: &[u8], raw_hub: &str| {
        WebCloud::accepted(
            account(),
            &record,
            raw_hub,
            (&bytes(caps, "claim"), &bytes(caps, "signature"), nonce),
            NOW_MS,
        )
    };
    let cloud = answer(&CAPABILITY_NONCE, RAW_HUB).unwrap();
    assert!(cloud.can_read() && cloud.can_command() && cloud.can_create());
    assert_eq!(code(&answer(&[0; 16], RAW_HUB).unwrap_err()), "capability");
    assert_eq!(
        code(&answer(&CAPABILITY_NONCE, "hub-2").unwrap_err()),
        "binding"
    );
    let other = trust(&session["otherHubTrust"], "hub-2").unwrap();
    let elsewhere = WebCloud::accepted(
        account(),
        &other,
        "hub-2",
        (
            &bytes(caps, "claim"),
            &bytes(caps, "signature"),
            &CAPABILITY_NONCE,
        ),
        NOW_MS,
    );
    assert_eq!(code(&elsewhere.unwrap_err()), "capability");
}

#[test]
fn the_registry_lists_the_trusted_runners_and_probes_only_them() {
    let session = recorded();
    let mut cloud = cloud(&session);
    let registry = &session["registry"];
    let listed: Value = serde_json::from_str(
        &cloud
            .registry_from(
                &key(registry),
                &stored(
                    registry["collectionId"].as_str().unwrap(),
                    &registry["object"],
                ),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(listed[0]["runnerId"], session["runner"]["runnerId"]);
    assert_eq!(listed[0]["keyEpoch"], 3);
    assert_eq!(listed[0]["label"], "Build runner");
    let unknown = cloud.probe(
        account(),
        &fixture::device(),
        &[9; 16],
        r#"{"catalog":null}"#,
        NOW_MS,
        None,
    );
    assert_eq!(code(&unknown.unwrap_err()), "no_runner");
    // The registry lives in its derived collection only.
    let elsewhere = cloud.registry_from(
        &key(&session["material"]),
        &stored("x", &registry["object"]),
    );
    assert_eq!(code(&elsewhere.unwrap_err()), "binding");
}

#[test]
fn a_catalog_probe_opens_the_pinned_runners_witness() {
    let session = recorded();
    let mut cloud = cloud(&session);
    let page = probe(&mut cloud, &session, "catalogProbe", CATALOG_NONCES);
    assert_eq!(page["kind"], "catalog");
    assert_eq!(page["chats"][0]["chatId"], session["chat"]["chatId"]);
    assert_eq!(page["chats"][0]["headSequence"], 6);
    assert_eq!(page["hasMore"], false);
    assert!(cloud.head(RUNNER_ID, fixture::CHAT_ID, 1).is_some());
}

#[test]
fn a_probe_signed_by_another_key_is_refused_before_sealing() {
    let session = recorded();
    let cloud = cloud(&session);
    let mut probe = cloud
        .probe(
            account(),
            &fixture::device(),
            &RUNNER_ID,
            r#"{"catalog":null}"#,
            NOW_MS,
            None,
        )
        .unwrap();
    let forged = DeviceKey::from_seed(&[7; 32]).sign(&probe.bytes().unwrap());
    assert_eq!(
        code(&probe.sealed_with(account(), &forged).unwrap_err()),
        "signature"
    );
    assert_eq!(code(&probe.sealed().unwrap_err()), "used");
}

#[test]
fn a_replay_against_the_witnessed_head_builds_the_transcript() {
    let session = recorded();
    let (_, chat) = replayed(&session);
    let transcript = chat.transcript_json();
    let rows = transcript["rows"].as_array().unwrap();
    assert_eq!(rows[0]["role"], "user");
    assert_eq!(rows[0]["text"], session["chat"]["prompt"]);
    assert_eq!(rows[1]["role"], "assistant");
    assert_eq!(rows[1]["text"], session["chat"]["answer"]);
    assert_eq!(rows[2]["tool"]["status"], "awaiting_approval");
    assert_eq!(transcript["runs"][0]["status"], "waiting_approval");
    assert_eq!(transcript["runs"][0]["issuerDevice"], fixture::DEVICE_ID);
    assert_eq!(transcript["runs"][0]["usage"]["costMicros"], 1_250);
    assert_eq!(transcript["activeRun"], session["chat"]["run"]);
    assert_eq!(transcript["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(transcript["controlRevision"], 6);
}

#[test]
fn a_replay_that_ends_before_the_head_is_withheld_and_keeps_the_last_transcript() {
    let session = recorded();
    let mut cloud = cloud(&session);
    let mut chat = chat(&cloud, &session);
    assert_eq!(code(&chat.begin(&cloud).unwrap_err()), "no_head");
    probe(&mut cloud, &session, "chatProbe", CHAT_NONCES);
    chat.begin(&cloud).unwrap();
    let proof = bytes(&session["runner"], "proofKey");
    deliver(&mut chat, &session["chat"]["records"][0], &proof).unwrap();
    assert_eq!(code(&chat.page(1, false).unwrap_err()), "withheld");
    assert!(
        chat.transcript_json()["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // The failed replay is over; a new one starts from the beginning.
    assert_eq!(code(&chat.data(&[1]).unwrap_err()), "used");
}

#[test]
fn a_record_from_another_publisher_is_refused() {
    let session = recorded();
    let mut cloud = cloud(&session);
    probe(&mut cloud, &session, "chatProbe", CHAT_NONCES);
    let mut chat = chat(&cloud, &session);
    chat.begin(&cloud).unwrap();
    let error = deliver(&mut chat, &session["chat"]["records"][0], &[0x55; 32]).unwrap_err();
    assert_eq!(code(&error), "replay_source");
}

/// Prepares `action`, signs it with the device key and seals it; returns the route's command.
fn sealed(cloud: &WebCloud, chat: &WebChat, action: &str) -> (CommandKind, Vec<u8>) {
    let mut command: WebCommand = chat
        .command(account(), &fixture::device(), action, NOW_MS)
        .unwrap();
    let signature = DeviceKey::from_seed(&DEVICE_SEED).sign(&command.bytes().unwrap());
    let publication = command.sealed(account(), cloud, &signature).unwrap();
    let binding = RelayBinding::from_canonical_bytes(&publication.binding().unwrap()).unwrap();
    let route = binding.command_route().unwrap().clone();
    let opened = open_command(
        &RunnerEncryptionKey::from_seed(&RUNNER_ENCRYPTION_SEED),
        &account().pair.public_key(),
        &route,
        publication.publication().ciphertext(),
    )
    .unwrap();
    let command = opened.command().unwrap();
    assert_eq!(command.header().context().expected_chat_revision, 6);
    assert_eq!(
        command.header().issuer().device_id.as_str(),
        fixture::DEVICE_ID
    );
    (command.header().context().kind, command.payload().to_vec())
}

#[test]
fn commands_open_for_the_pinned_runner_once_the_device_signature_verifies() {
    let session = recorded();
    let (cloud, chat) = replayed(&session);
    let run = session["chat"]["run"].as_str().unwrap();
    let (kind, payload) = sealed(
        &cloud,
        &chat,
        r#"{"kind":"prompt","text":"and the disks?"}"#,
    );
    assert_eq!(kind, CommandKind::SubmitPrompt);
    let CloudCommandPayload::SubmitPrompt(prompt) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::SubmitPrompt, &payload).unwrap()
    else {
        panic!("a prompt");
    };
    assert_eq!(
        prompt.model.model.as_str(),
        "gpt-5-mini",
        "the latest run's model"
    );
    let stop = format!(r#"{{"kind":"stop","run":"{run}"}}"#);
    assert_eq!(sealed(&cloud, &chat, &stop).0, CommandKind::Stop);
    let allow = format!(r#"{{"kind":"allow","run":"{run}"}}"#);
    assert_eq!(sealed(&cloud, &chat, &allow).0, CommandKind::IssueGrant);
    let intent = chat.transcript_json()["approvals"][0]["intent"].clone();
    let answer = format!(r#"{{"kind":"answer","intent":{intent},"choice":"deny"}}"#);
    assert_eq!(
        sealed(&cloud, &chat, &answer).0,
        CommandKind::ResolveApproval
    );
}

#[test]
fn commands_without_their_subject_or_signature_are_refused() {
    let session = recorded();
    let (cloud, chat) = replayed(&session);
    let device = fixture::device();
    let refuse = |action: &str| {
        code(
            &chat
                .command(account(), &device, action, NOW_MS)
                .unwrap_err(),
        )
    };
    let missing = format!(
        r#"{{"kind":"answer","intent":"{}","choice":"approve"}}"#,
        "ab".repeat(16)
    );
    assert_eq!(refuse(&missing), "no_approval");
    assert_eq!(
        refuse(&format!(r#"{{"kind":"stop","run":"{}"}}"#, "cd".repeat(16))),
        "no_run"
    );
    assert_eq!(refuse(r#"{"kind":"dance"}"#), "argument");
    let long = format!(r#"{{"kind":"prompt","text":"{}"}}"#, "x".repeat(20_000));
    let mut command = chat.command(account(), &device, &long, NOW_MS).unwrap();
    let signature = DeviceKey::from_seed(&DEVICE_SEED).sign(&command.bytes().unwrap());
    let too_long = command.sealed(account(), &cloud, &signature).unwrap_err();
    assert!(matches!(code(&too_long).as_str(), "capacity" | "refused"));
    let fresh = chat.command(
        account(),
        &device,
        r#"{"kind":"prompt","text":"hi"}"#,
        NOW_MS,
    );
    let mut fresh = fresh.unwrap();
    let forged = DeviceKey::from_seed(&[8; 32]).sign(&fresh.bytes().unwrap());
    assert_eq!(
        code(&fresh.sealed(account(), &cloud, &forged).unwrap_err()),
        "signature"
    );

    let empty = self::chat(&cloud, &session);
    let none = empty.command(
        account(),
        &device,
        r#"{"kind":"prompt","text":"hi"}"#,
        NOW_MS,
    );
    assert_eq!(code(&none.unwrap_err()), "no_model");
    let managed = r#"{"kind":"prompt","text":"hi","model":{"provider":"managed","model":"m"}}"#;
    assert!(empty.command(account(), &device, managed, NOW_MS).is_ok());
}

#[test]
fn a_new_chat_seals_its_material_and_grant_for_the_trusted_runner() {
    let session = recorded();
    let cloud = cloud(&session);
    let chat_id = hex::encode(nocterm_cloud_device::create::new_chat_id().unwrap());
    let mut created = cloud.created(account(), &RUNNER_ID, &chat_id).unwrap();
    assert_eq!(
        hex::encode(created.chat().unwrap().selector().chat_id()),
        chat_id
    );
    assert_eq!(
        code(&cloud.created(account(), &RUNNER_ID, "beef").unwrap_err()),
        "argument"
    );
    let material_key = key(&session["material"]);
    let sealed = created
        .chat()
        .unwrap()
        .material()
        .seal(&material_key.key)
        .unwrap();
    let object = super::WebStoredObject::new(
        material_key.collection_id.clone(),
        created.chat().unwrap().selector().object_id().unwrap(),
        nocterm_cloud_device::records::CHAT_MATERIAL_KIND.to_owned(),
        1,
        false,
        sealed,
    );
    assert!(
        cloud
            .chat(account(), &material_key, (&RUNNER_ID, &chat_id, 1), &object)
            .is_ok()
    );
    let grant_key = key(&session["grants"]);
    let chat = created.chat().unwrap();
    assert!(chat.grant().seal(&grant_key.key, chat.selector()).is_ok());
    let first = created.publication(&cloud).unwrap();
    let again = created.publication(&cloud).unwrap();
    assert_eq!(first.publication_id(), again.publication_id());
    assert_eq!(first.accept_before_ms(), None);
    assert!(created.take_chat().is_ok());
    assert_eq!(code(&created.publication(&cloud).unwrap_err()), "used");
    assert_eq!(
        code(&cloud.created(account(), &[3; 16], &chat_id).unwrap_err()),
        "no_runner"
    );
}

#[test]
fn a_collection_made_in_the_browser_opens_under_the_account_key() {
    let mut made = account()
        .new_collection("col-cloud", "cloud-chat-grant")
        .unwrap();
    let opened = account()
        .own_collection("col-cloud", &made.wrapped_key())
        .unwrap();
    let mine = made.take_key().unwrap();
    let probe = mine.key.seal_object("col-cloud", "o", "k", b"x").unwrap();
    assert_eq!(
        &*opened
            .key
            .open_object("col-cloud", "o", "k", &probe)
            .unwrap(),
        b"x"
    );
    assert_eq!(
        CollectionKey::open(&account().account, "col-cloud", &made.wrapped_key())
            .unwrap()
            .open_name("col-cloud", &made.sealed_name())
            .unwrap(),
        "cloud-chat-grant"
    );
    let _ = PublicKey::from_bytes(&account().public_key()).unwrap();
}
