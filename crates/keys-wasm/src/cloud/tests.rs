#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use std::sync::OnceLock;

use nocterm_cloud_device::nonces::Nonces;
use nocterm_hub_model::cloud::{CommandKind, payload::CloudCommandPayload, relay::RelayBinding};
use nocterm_keys::{
    PublicKey,
    cloud::{RunnerEncryptionKey, open_command},
};
use serde_json::Value;

use super::fixture::{
    self, Answer, Hub, NONCE_SEED, NOW_MS, RAW_HUB, RUNNER_ENCRYPTION_SEED, Rows, drive, hex_of,
    store_answer,
};
use super::types::{
    ChatActionInput, EffectInput, FlowOutput, FlowStep, ModelInput, WireCollection, WireEffect,
    WireObject,
};
use super::{CloudDevice, WebChat};
use crate::WebAccount;

fn account() -> &'static WebAccount {
    static ACCOUNT: OnceLock<WebAccount> = OnceLock::new();
    ACCOUNT.get_or_init(fixture::account)
}
fn recorded() -> Value {
    serde_json::from_str(include_str!(
        "../../../../fixtures/cloud-device-v1/web-session.json"
    ))
    .unwrap()
}

/// The page's executor over the recorded session only, as the panel's tests replay it.
struct Replayer {
    session: Value,
    rows: Rows,
    /// The runner answers probes (false: a sleeping seat).
    awake: bool,
    /// Answers to `publish`, in order, before the default receipt.
    publish: Vec<EffectInput>,
    published: Vec<WireEffect>,
}
impl Replayer {
    fn new() -> Self {
        let session = recorded();
        let collections = session["collections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let wire = WireCollection {
                    collection_id: c["collectionId"].as_str().unwrap().to_owned(),
                    kind: c["kind"].as_str().unwrap().to_owned(),
                    personal: c["personal"].as_bool().unwrap(),
                    deleted: c["deleted"].as_bool().unwrap(),
                };
                (wire, hex_of(c, "wrappedKey"))
            })
            .collect();
        let objects = session["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| WireObject {
                collection_id: o["collectionId"].as_str().unwrap().to_owned(),
                object_id: o["objectId"].as_str().unwrap().to_owned(),
                kind: o["kind"].as_str().unwrap().to_owned(),
                version: o["version"].as_u64().unwrap(),
                deleted: o["deleted"].as_bool().unwrap(),
                ciphertext: hex_of(o, "ciphertext"),
            })
            .collect();
        let rows = Rows {
            collections,
            objects,
            records: session["chat"]["records"].as_array().unwrap().clone(),
            directory: session["directory"]["records"].as_array().unwrap().clone(),
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
    fn chat_id(&self) -> String {
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

/// A connected device, as the recorded order begins.
fn connected(hub: &mut Replayer) -> (CloudDevice, Vec<FlowOutput>) {
    let device = CloudDevice::made(account(), fixture::device_input()).unwrap();
    let mut connect = device.discover(RAW_HUB, None, Nonces::seeded(NONCE_SEED));
    let (outputs, last, _) = drive(&mut connect, hub, NOW_MS);
    assert!(matches!(last, FlowStep::Done), "{last:?}");
    (device, outputs)
}
/// Connected, listed and the chat opened, as recorded.
fn opened(hub: &mut Replayer) -> (CloudDevice, WebChat, Vec<FlowOutput>, Vec<u32>) {
    let (device, _) = connected(hub);
    drive(&mut device.listing().unwrap(), hub, NOW_MS);
    let mut chat = device.opened(&hub.chat_id(), None).unwrap();
    let (outputs, _, watches) = drive(&mut chat, hub, NOW_MS);
    (device, chat, outputs, watches)
}
fn freshness(outputs: &[FlowOutput]) -> Vec<String> {
    outputs
        .iter()
        .filter_map(|output| match output {
            FlowOutput::Freshness { freshness } => Some(
                serde_json::to_value(freshness).unwrap()["state"]
                    .as_str()?
                    .to_owned(),
            ),
            _ => None,
        })
        .collect()
}

#[test]
fn connecting_finds_this_hubs_trust_and_its_runner() {
    let mut hub = Replayer::new();
    let (device, outputs) = connected(&mut hub);
    let [
        FlowOutput::Ready {
            origin,
            can_command,
            can_create,
            runners,
        },
    ] = outputs.as_slice()
    else {
        panic!("ready: {outputs:?}");
    };
    assert_eq!(origin, "hub.example.org:7443");
    assert!(*can_command && *can_create);
    assert_eq!(runners[0].label, "Build runner");
    assert!(device.ready());
    assert_eq!(device.runners(), *runners);
}

#[test]
fn flows_before_connecting_are_refused_with_a_code() {
    let device = CloudDevice::made(account(), fixture::device_input()).unwrap();
    let error = device.listing().unwrap_err();
    assert_eq!(error.code(), "not_ready");
    assert!(error.to_string().starts_with("[not_ready]"));
}

#[test]
fn listing_reports_the_runners_witnessed_catalog_without_a_replay() {
    let mut hub = Replayer::new();
    let (device, _) = connected(&mut hub);
    let (outputs, last, _) = drive(&mut device.listing().unwrap(), &mut hub, NOW_MS);
    assert!(matches!(last, FlowStep::Done));
    let chats = outputs
        .iter()
        .find_map(|output| match output {
            FlowOutput::RunnerChats { chats, .. } => Some(chats),
            _ => None,
        })
        .unwrap();
    assert_eq!(chats[0].chat_id, hub.chat_id());
    assert_eq!(chats[0].head_sequence, Some(6));
}

#[test]
fn an_open_chat_is_current_with_the_recorded_transcript_and_a_checkpoint() {
    let mut hub = Replayer::new();
    let (_, chat, outputs, _) = opened(&mut hub);
    assert_eq!(freshness(&outputs), ["current"]);
    let delta = chat.transcript();
    assert_eq!(delta.rows[0].role, "user");
    assert_eq!(delta.rows[0].text, fixture::PROMPT);
    assert_eq!(delta.rows[1].text, fixture::ANSWER);
    assert_eq!(
        delta.rows[2].tool.as_ref().unwrap().status,
        "awaiting_approval"
    );
    let runs = delta.runs.unwrap();
    assert_eq!(runs[0].status, "waiting_approval");
    assert_eq!(runs[0].usage.cost_micros, Some(1_250));
    assert_eq!(delta.approvals.unwrap().len(), 1);
    assert_eq!(delta.control_revision, 6);
    assert!(
        outputs
            .iter()
            .any(|o| matches!(o, FlowOutput::Checkpoint { .. }))
    );
}

#[test]
fn a_watch_hint_brings_only_the_later_record_and_a_reopen_resumes_at_the_checkpoint() {
    let mut hub = Replayer::new();
    let (device, mut chat, outputs, watches) = opened(&mut hub);
    let checkpoint = outputs
        .into_iter()
        .find_map(|output| match output {
            FlowOutput::Checkpoint { bytes } => Some(bytes),
            _ => None,
        })
        .unwrap();
    let later = hub.session["chat"]["later"].as_array().unwrap().clone();
    hub.rows.records.extend(later);
    chat.frame_input(
        watches[0],
        super::types::StreamFrame::Hint { head_cursor: 7 },
    );
    let (outputs, ..) = drive(&mut chat, &mut hub, NOW_MS + 1.0);
    let FlowOutput::Transcript { delta } = &outputs[0] else {
        panic!("a delta: {outputs:?}");
    };
    assert!(!delta.reset);
    assert_eq!(delta.rows.last().unwrap().text, fixture::LATER);
    assert!(freshness(&outputs).is_empty(), "still current");

    let mut resumed = device.opened(&hub.chat_id(), Some(checkpoint)).unwrap();
    assert_eq!(
        resumed.transcript().rows.len(),
        3,
        "shown before any effect"
    );
    let (outputs, ..) = drive(&mut resumed, &mut hub, NOW_MS + 2.0);
    assert_eq!(resumed.transcript().rows.len(), 4);
    assert!(!freshness(&outputs).is_empty());
}

#[test]
fn a_sleeping_seat_shows_the_stored_history_unconfirmed() {
    let mut hub = Replayer::new();
    let (device, _) = connected(&mut hub);
    hub.awake = false;
    let mut chat = device.opened(&hub.chat_id(), None).unwrap();
    let (outputs, ..) = drive(&mut chat, &mut hub, NOW_MS);
    assert_eq!(freshness(&outputs), ["unconfirmed"]);
    assert_eq!(chat.transcript().rows.len(), 3);
}

/// The command the pinned runner opens from a publish effect.
fn opened_command(effect: &WireEffect) -> (CommandKind, u64, Vec<u8>) {
    let WireEffect::Publish { publication, data } = effect else {
        panic!("a publication");
    };
    let binding = RelayBinding::from_canonical_bytes(&publication.binding).unwrap();
    let opened = open_command(
        &RunnerEncryptionKey::from_seed(&RUNNER_ENCRYPTION_SEED),
        &PublicKey::from_bytes(&account().public_key()).unwrap(),
        binding.command_route().unwrap(),
        data,
    )
    .unwrap();
    let command = opened.command().unwrap();
    let context = command.header().context();
    (
        context.kind,
        context.expected_chat_revision,
        command.payload().to_vec(),
    )
}

#[test]
fn a_prompt_retries_identical_bytes_and_carries_the_latest_runs_model() {
    let mut hub = Replayer::new();
    let (_, mut chat, ..) = opened(&mut hub);
    hub.publish.push(EffectInput::Failed {
        failure: "unknown".to_owned(),
    });
    let action = ChatActionInput::Prompt {
        text: "and the disks?".to_owned(),
        model: None,
    };
    let mut delivery = chat.delivery(action, None, NOW_MS).unwrap();
    assert_eq!(chat.transcript().pending.unwrap()[0].state, "sending");
    let (outputs, last, _) = drive(&mut delivery, &mut hub, NOW_MS);
    assert!(outputs.is_empty());
    assert!(matches!(last, FlowStep::Idle { until_ms: Some(_) }));
    let (outputs, last, _) = drive(&mut delivery, &mut hub, NOW_MS + 1_000.0);
    assert!(matches!(last, FlowStep::Done));
    let FlowOutput::Delivery { state, .. } = &outputs[0] else {
        panic!("a delivery");
    };
    assert_eq!(state, "delivered");
    assert_eq!(hub.published[0], hub.published[1], "identical bytes");
    assert_eq!(chat.transcript().pending.unwrap()[0].state, "delivered");
    let (kind, revision, payload) = opened_command(&hub.published[0]);
    assert_eq!((kind, revision), (CommandKind::SubmitPrompt, 6));
    let CloudCommandPayload::SubmitPrompt(prompt) =
        CloudCommandPayload::from_canonical_bytes(kind, &payload).unwrap()
    else {
        panic!("a prompt");
    };
    assert_eq!(prompt.model.model.as_str(), "gpt-5-mini");
}

#[test]
fn stop_allow_and_answer_name_the_verified_run_and_approval() {
    let mut hub = Replayer::new();
    let (_, mut chat, ..) = opened(&mut hub);
    let run = hub.session["chat"]["run"].as_str().unwrap().to_owned();
    let intent = chat.transcript().approvals.unwrap()[0].intent.clone();
    for (action, kind) in [
        (ChatActionInput::Stop { run: None }, CommandKind::Stop),
        (
            ChatActionInput::Allow { run: run.clone() },
            CommandKind::IssueGrant,
        ),
        (
            ChatActionInput::Answer {
                intent: intent.clone(),
                approve: false,
            },
            CommandKind::ResolveApproval,
        ),
    ] {
        let mut delivery = chat.delivery(action, None, NOW_MS).unwrap();
        drive(&mut delivery, &mut hub, NOW_MS);
        assert_eq!(opened_command(hub.published.last().unwrap()).0, kind);
    }
    let missing = ChatActionInput::Answer {
        intent: "ab".repeat(16),
        approve: true,
    };
    assert_eq!(
        chat.delivery(missing, None, NOW_MS).unwrap_err().code(),
        "no_approval"
    );
    let stop = ChatActionInput::Stop {
        run: Some("cd".repeat(16)),
    };
    assert_eq!(
        chat.delivery(stop, None, NOW_MS).unwrap_err().code(),
        "no_run"
    );
    let bad = ChatActionInput::Allow {
        run: "beef".to_owned(),
    };
    assert_eq!(
        chat.delivery(bad, None, NOW_MS).unwrap_err().code(),
        "argument"
    );
}

#[test]
fn a_prompt_without_a_model_or_too_long_for_one_frame_is_refused() {
    let mut hub = Replayer::new();
    let (device, _) = connected(&mut hub);
    hub.awake = false;
    hub.rows.records.clear();
    let mut empty = device.opened(&hub.chat_id(), None).unwrap();
    drive(&mut empty, &mut hub, NOW_MS);
    let prompt = |model: Option<ModelInput>| ChatActionInput::Prompt {
        text: "hi".to_owned(),
        model,
    };
    assert_eq!(
        empty
            .delivery(prompt(None), None, NOW_MS)
            .unwrap_err()
            .code(),
        "no_model"
    );
    let managed = ModelInput {
        provider: "managed".to_owned(),
        model: "m".to_owned(),
    };
    assert!(
        empty
            .delivery(prompt(Some(managed.clone())), None, NOW_MS)
            .is_ok()
    );
    let long = ChatActionInput::Prompt {
        text: "x".repeat(20_000),
        model: Some(managed),
    };
    let mut delivery = empty.delivery(long, None, NOW_MS).unwrap();
    let (_, last, _) = drive(&mut delivery, &mut hub, NOW_MS);
    let FlowStep::Failed { error } = last else {
        panic!("refused");
    };
    assert!(
        matches!(error.code.as_str(), "capacity" | "refused"),
        "{error:?}"
    );
}

#[test]
fn an_effect_answer_of_an_unknown_failure_kind_is_an_argument_error() {
    let mut hub = Replayer::new();
    let (device, _) = connected(&mut hub);
    let mut flow = device.listing().unwrap();
    let FlowStep::Effect { id, .. } = flow.step(NOW_MS).unwrap() else {
        panic!("an effect");
    };
    let error = flow
        .resolve_input(
            id,
            EffectInput::Failed {
                failure: "exploded".to_owned(),
            },
        )
        .unwrap_err();
    assert_eq!(error.code(), "argument");
}

#[test]
fn listed_rows_cross_with_their_summary_status_and_directory_checkpoints() {
    use nocterm_cloud_device::{
        context::ChatRef,
        directory::{ListedChat, RowStatus, VerifiedDirectory},
        list::ChatListUpdate,
        records::{RunnerPins, TrustedRunner},
    };
    use nocterm_hub_model::cloud::{
        CloudTextId, RunnerCoordinate,
        summary::{BoundServer, ChatState, ChatSummary, ServerState, SummaryHost},
    };
    let runner = TrustedRunner::new(
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        RunnerPins {
            encryption: [1; 32],
            signing: [2; 32],
            proof: [3; 32],
        },
        "Runner",
    )
    .unwrap();
    let summary = ChatSummary {
        head: None,
        control_revision: 4,
        created_at_ms: 10,
        last_activity_ms: 20,
        title: "Fix the build".to_owned(),
        host: SummaryHost::Managed {
            agent_id: CloudTextId::new("agent-1").unwrap(),
        },
        model: None,
        state: ChatState::WaitingApproval,
        pending_approvals: 1,
        servers: vec![BoundServer {
            host: CloudTextId::new("db").unwrap(),
            port: 22,
            user: CloudTextId::new("deploy").unwrap(),
            state: ServerState::NeedsCaUpdate,
            valid_before_ms: None,
        }],
        features: 1,
    };
    let row = ListedChat {
        chat: ChatRef {
            runner: [2; 16],
            chat_id: [5; 16],
            key_epoch: 1,
        },
        summary: Some(summary),
        status: RowStatus::AsOf,
        control_revision: 4,
        head_sequence: None,
        deleted: false,
        witnessed_at_ms: None,
    };
    let output = super::listing::listed(ChatListUpdate::Runner {
        runner: runner.clone(),
        chats: vec![row],
        complete: false,
    });
    let json = serde_json::to_value(&output).unwrap();
    let chat = &json["chats"][0];
    assert_eq!(json["kind"], "runnerChats");
    assert_eq!(chat["status"], "asOf");
    assert!(chat.get("witnessedAtMs").is_none());
    assert_eq!(chat["summary"]["title"], "Fix the build");
    assert_eq!(chat["summary"]["host"], "managed");
    assert_eq!(chat["summary"]["agentId"], "agent-1");
    assert_eq!(chat["summary"]["state"], "waitingApproval");
    assert_eq!(chat["summary"]["servers"][0]["state"], "needsCaUpdate");
    let output = super::listing::listed(ChatListUpdate::Directory {
        runner: [2; 16],
        checkpoint: VerifiedDirectory::from_bytes(vec![9, 9]),
    });
    let FlowOutput::Directory { runner_id, bytes } = output else {
        panic!("a directory checkpoint");
    };
    assert_eq!(runner_id, hex::encode([2; 16]));
    assert_eq!(bytes, [9, 9]);
    let options: super::types::ListOptions =
        serde_json::from_value(serde_json::json!({ "watch": true })).unwrap();
    assert!(options.watch == Some(true) && options.directories.is_none());
}

/// Every field the declarations mark optional (`field?: T`) also accepts an explicit absent
/// value: the page passes `{grantedBy: undefined}`, which reaches serde as a unit value, as
/// `null` does here.
#[test]
fn optional_input_fields_accept_an_explicit_absent_value() {
    use super::types::{ListOptions, StreamFrame};
    use serde_json::json;
    let key: EffectInput = serde_json::from_value(
        json!({ "kind": "collectionKey", "wrappedKey": [1, 2], "grantedBy": null }),
    )
    .unwrap();
    assert!(matches!(
        key,
        EffectInput::CollectionKey {
            granted_by: None,
            ..
        }
    ));
    let options: ListOptions =
        serde_json::from_value(json!({ "directories": null, "watch": null })).unwrap();
    assert!(options.directories.is_none() && options.watch.is_none());
    let prompt: ChatActionInput =
        serde_json::from_value(json!({ "kind": "prompt", "text": "hi", "model": null })).unwrap();
    assert!(matches!(
        prompt,
        ChatActionInput::Prompt { model: None, .. }
    ));
    let stop: ChatActionInput =
        serde_json::from_value(json!({ "kind": "stop", "run": null })).unwrap();
    assert!(matches!(stop, ChatActionInput::Stop { run: None }));
    let header: StreamFrame = serde_json::from_value(json!({
        "kind": "header", "publicationId": [1], "binding": [2], "totalBytes": 1,
        "ciphertextSha256": [3], "cursor": 4, "originAccountId": "a",
        "originSigningKey": [5], "originRunnerId": null,
    }))
    .unwrap();
    assert!(matches!(
        header,
        StreamFrame::Header {
            origin_runner_id: None,
            ..
        }
    ));
    let seat: EffectInput = serde_json::from_value(json!({
        "kind": "instance",
        "instance": { "instanceId": "i", "agentId": "a", "poolId": "p", "runnerId": null, "state": "ready" },
    }))
    .unwrap();
    assert!(matches!(
        seat,
        EffectInput::Instance { instance } if instance.runner_id.is_none()
    ));
}

/// The listing outputs' last rows of the recorded runner.
fn last_rows(outputs: &[FlowOutput]) -> Vec<super::types::WireChat> {
    outputs
        .iter()
        .rev()
        .find_map(|output| match output {
            FlowOutput::RunnerChats { chats, .. } => Some(chats.clone()),
            _ => None,
        })
        .unwrap()
}
fn watching(directories: Option<Vec<Vec<u8>>>) -> super::types::ListOptions {
    super::types::ListOptions {
        directories: directories.map(|d| d.into_iter().map(serde_bytes::ByteBuf::from).collect()),
        watch: Some(true),
    }
}

#[test]
fn a_listing_shows_the_runners_summary_confirmed_by_its_witness_and_a_directory_checkpoint() {
    let mut hub = Replayer::new();
    let (device, _) = connected(&mut hub);
    let mut list = device.listing_with(watching(None)).unwrap();
    let (outputs, _, watches) = drive(&mut list, &mut hub, NOW_MS);
    let row = &last_rows(&outputs)[0];
    assert_eq!(row.status, "current");
    let summary = row.summary.as_ref().unwrap();
    assert_eq!(summary.title, fixture::PROMPT);
    assert_eq!(
        (summary.host.as_str(), summary.agent_id.as_deref()),
        ("managed", Some("ag-1"))
    );
    assert_eq!(summary.model.as_deref(), Some("gpt-5-mini"));
    assert_eq!(
        (summary.state.as_str(), summary.pending_approvals),
        ("waitingApproval", 1)
    );
    assert!(
        outputs
            .iter()
            .any(|o| matches!(o, FlowOutput::Directory { .. }))
    );
    assert_eq!(watches.len(), 1, "the directory is watched");
}

#[test]
fn a_directory_hint_brings_the_later_summary_and_a_relisting_resumes_at_its_checkpoint() {
    let mut hub = Replayer::new();
    let (device, _) = connected(&mut hub);
    let mut list = device.listing_with(watching(None)).unwrap();
    let (outputs, _, watches) = drive(&mut list, &mut hub, NOW_MS);
    let first = last_rows(&outputs)[0].summary.clone().unwrap();
    let checkpoint = outputs
        .into_iter()
        .find_map(|o| match o {
            FlowOutput::Directory { bytes, .. } => Some(bytes),
            _ => None,
        })
        .unwrap();
    let later = hub.session["directory"]["later"]
        .as_array()
        .unwrap()
        .clone();
    hub.rows.directory.extend(later);
    list.frame_input(
        watches[0],
        super::types::StreamFrame::Hint { head_cursor: 2 },
    );
    let (outputs, ..) = drive(&mut list, &mut hub, NOW_MS);
    let row = &last_rows(&outputs)[0];
    let later = row.summary.as_ref().unwrap();
    assert!(later.last_activity_ms > first.last_activity_ms);
    assert_eq!(row.status, "current", "newer than the witness");

    // A new listing from the first checkpoint reads only what followed it.
    hub.rows.directory.remove(0);
    let mut relist = device
        .listing_with(watching(Some(vec![checkpoint])))
        .unwrap();
    let (outputs, ..) = drive(&mut relist, &mut hub, NOW_MS);
    let row = &last_rows(&outputs)[0];
    assert!(
        (row.summary.as_ref().unwrap().last_activity_ms - later.last_activity_ms).abs() < 1.0,
        "the later summary, from the checkpoint on"
    );
}

#[test]
fn a_lease_names_the_keys_provider_and_model_and_an_expired_boot_is_its_own_code() {
    let mut hub = Replayer::new();
    let (device, chat, ..) = opened(&mut hub);
    let mut lease = device.leasing(&chat, fixture::lease::OWN_AGENT).unwrap();
    let (outputs, ..) = drive(&mut lease, &mut hub, NOW_MS);
    let Some(FlowOutput::Lease {
        provider,
        model,
        renew_at_ms,
        ..
    }) = outputs.first()
    else {
        panic!("a lease: {outputs:?}");
    };
    assert_eq!(
        (provider.as_str(), model.as_str()),
        (fixture::lease::OWN_PROVIDER, fixture::lease::OWN_MODEL)
    );
    assert!(
        (*renew_at_ms - (NOW_MS + 5.0 * 60_000.0)).abs() < 1.0,
        "half the term"
    );
    let (kind, ..) = opened_command(hub.published.last().unwrap());
    assert_eq!(kind, CommandKind::IssueGrant);

    let mut late = device.leasing(&chat, fixture::lease::OWN_AGENT).unwrap();
    let (_, last, _) = drive(&mut late, &mut hub, NOW_MS + 30.0 * 60_000.0);
    let FlowStep::Failed { error } = last else {
        panic!("refused: {last:?}");
    };
    assert_eq!(error.code, "boot_expired");
}

#[test]
fn ssh_commands_need_a_verified_request_a_binding_or_the_accounts_ca() {
    use super::types::{BindOptions, SshServerInput, WireSsh};
    let mut hub = Replayer::new();
    let (_, mut chat, _, _) = opened(&mut hub);
    assert_eq!(chat.ssh(), WireSsh::default());
    let code = |result: super::CloudResult<super::WebFlow>| result.unwrap_err().code();
    assert_eq!(
        code(chat.answering(&"44".repeat(16), NOW_MS)),
        "ssh_unknown_request"
    );
    assert_eq!(code(chat.unbinding(None, NOW_MS)), "ssh_not_bound");
    let server = |server_id: &str, port| {
        vec![SshServerInput {
            server_id: server_id.to_owned(),
            port,
        }]
    };
    let bind = |chat: &mut WebChat, servers, options| chat.binding(servers, options, NOW_MS);
    assert_eq!(
        code(bind(&mut chat, server("zz", 22), BindOptions::default())),
        "argument"
    );
    assert_eq!(
        code(bind(
            &mut chat,
            server(&"ab".repeat(16), 0),
            BindOptions::default()
        )),
        "ssh_servers"
    );
    let month = BindOptions {
        window_ms: Some(31.0 * 86_400_000.0),
        wake: None,
    };
    assert_eq!(
        code(bind(&mut chat, server(&"ab".repeat(16), 22), month)),
        "ssh_window"
    );
    // The recorded account has no `agent_ssh_trust` collection, so it has no CA to bind with.
    let mut flow = bind(
        &mut chat,
        server(&"ab".repeat(16), 22),
        BindOptions::default(),
    )
    .unwrap();
    let (_, last, _) = drive(&mut flow, &mut hub, NOW_MS);
    assert!(
        matches!(&last, FlowStep::Failed { error } if error.code == "ssh_no_ca"),
        "{last:?}"
    );
    assert!(hub.published.is_empty());
}
