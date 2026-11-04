//! What flows report to the page, as structured display values (tsify), and the actions the
//! page asks of an open chat.
use nocterm_cloud_device::{
    reader::Freshness,
    records::TrustedRunner,
    transcript::{
        ApprovalRequest, CommandState, PendingCommand, PendingKind, Role, RunState, SessionCall,
        SessionStatus, ToolCall, ToolOutcome, ToolStatus, TranscriptDelta, TranscriptRow,
    },
};
use nocterm_hub_model::cloud::{
    RunCoordinate,
    events::{CloudRunStatus, CloudUsage},
    payload::SessionFailure,
};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;

use super::{
    listing::WireChat,
    ssh::WireSsh,
    types::{WireError, WireInstance},
};

/// A trusted runner.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct RunnerInfo {
    pub runner_id: String,
    pub key_epoch: u64,
    pub label: String,
}
impl From<&TrustedRunner> for RunnerInfo {
    fn from(runner: &TrustedRunner) -> Self {
        Self {
            runner_id: hex::encode(runner.runner().id),
            key_epoch: runner.runner().key_epoch,
            label: runner.label().to_owned(),
        }
    }
}

/// `state`: `opening` (`lastWitnessedAtMs` of a restored checkpoint: no round has finished yet,
/// show the stored history without calling the seat asleep), `current` (`witnessedAtMs`),
/// `unconfirmed` (`lastWitnessedAtMs` when ever
/// witnessed: show "Seat asleep — stored history, may be incomplete" and offer Wake) or
/// `withheld` (`witnessedAtMs`: the hub withholds newer history).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum WireFreshness {
    #[serde(rename_all = "camelCase")]
    Opening {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        last_witnessed_at_ms: Option<f64>,
    },
    #[serde(rename_all = "camelCase")]
    Current { witnessed_at_ms: f64 },
    #[serde(rename_all = "camelCase")]
    Unconfirmed {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        last_witnessed_at_ms: Option<f64>,
    },
    #[serde(rename_all = "camelCase")]
    Withheld { witnessed_at_ms: f64 },
}
#[allow(
    clippy::cast_precision_loss,
    reason = "a time in milliseconds fits 2^53"
)]
pub(super) fn ms(value: i64) -> f64 {
    value as f64
}
impl From<Freshness> for WireFreshness {
    fn from(freshness: Freshness) -> Self {
        match freshness {
            Freshness::Opening {
                last_witnessed_at_ms,
            } => Self::Opening {
                last_witnessed_at_ms: last_witnessed_at_ms.map(ms),
            },
            Freshness::Current { witnessed_at_ms } => Self::Current {
                witnessed_at_ms: ms(witnessed_at_ms),
            },
            Freshness::Unconfirmed {
                last_witnessed_at_ms,
            } => Self::Unconfirmed {
                last_witnessed_at_ms: last_witnessed_at_ms.map(ms),
            },
            Freshness::Withheld { witnessed_at_ms } => Self::Withheld {
                witnessed_at_ms: ms(witnessed_at_ms),
            },
        }
    }
}

/// What a flow reports.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FlowOutput {
    /// `connect`: no hub-trust record names this hub: set Cloud up on a native device.
    NotSetUp,
    /// `connect`: several native origins; call `connect` again with one.
    ChooseOrigin {
        origins: Vec<String>,
    },
    /// `connect`: the hub cannot serve Cloud chats.
    Unsupported,
    /// `connect`: the device is ready for the other flows.
    #[serde(rename_all = "camelCase")]
    Ready {
        origin: String,
        can_command: bool,
        can_create: bool,
        runners: Vec<RunnerInfo>,
    },
    /// `listChats`: the account's seats.
    Seats {
        seats: Vec<WireInstance>,
    },
    /// `listChats`: all rows of one runner, replacing its earlier rows (see `WireChat.status`).
    RunnerChats {
        runner: RunnerInfo,
        chats: Vec<WireChat>,
        complete: bool,
    },
    /// `listChats`: one runner did not answer (`error` absent) or was refused.
    Unreachable {
        runner: RunnerInfo,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        error: Option<WireError>,
    },
    /// `listChats`: store `bytes` as the directory checkpoint of runner `runnerId`, in place of
    /// the previous one, and pass it to the next `listChats`.
    #[serde(rename_all = "camelCase")]
    Directory {
        runner_id: String,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        bytes: Vec<u8>,
    },
    /// `listChats`: a summary or directory round of `runner` was refused; rows stay.
    DirectoryRefused {
        runner: RunnerInfo,
        error: WireError,
    },
    /// `openChat`: apply to the view (see `WireDelta`).
    Transcript {
        delta: WireDelta,
    },
    Freshness {
        freshness: WireFreshness,
    },
    /// `openChat`: store in place of the previous checkpoint of this chat.
    Checkpoint {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        bytes: Vec<u8>,
    },
    /// `openChat`: deliver `{kind: "allow", run}` now.
    AllowRun {
        run: String,
    },
    /// `openChat`: the runner asks for an SSH certificate this device may answer: call
    /// `answerSsh(requestId)` while the chat is open.
    #[serde(rename_all = "camelCase")]
    SshRequest {
        request_id: String,
    },
    /// `bindServers`: this device signed binding `grant` at `epoch`; the servers in
    /// `needsCaUpdate` still hold the shared `authorized_keys` line.
    #[serde(rename_all = "camelCase")]
    SshBound {
        grant: String,
        epoch: f64,
        needs_ca_update: Vec<String>,
    },
    /// `answerSsh`: this device signed a certificate for `servers` until `validBeforeMs`.
    #[serde(rename_all = "camelCase")]
    SshCertified {
        request_id: String,
        servers: Vec<String>,
        valid_before_ms: f64,
    },
    /// `openChat`: a replay round was refused; the verified prefix stays.
    Refused {
        error: WireError,
    },
    /// `deliver`: `state` is `delivered`, `accepted`, `refused` or `unreachable`.
    #[serde(rename_all = "camelCase")]
    Delivery {
        command_id: String,
        state: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        cursor: Option<u64>,
    },
    /// `createChat`: the runner took the chat.
    #[serde(rename_all = "camelCase")]
    Created {
        chat_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        instance_id: Option<String>,
        /// The registry was read again; `runners()` has the new list.
        runners_reloaded: bool,
    },
    /// `wakeSeat`: the agent's enrolled seat was started (an agent without one fails with
    /// `not_enrolled`; a chat never provisions a seat).
    Woken {
        instance: WireInstance,
    },
    /// `lease`: the hub delivered the provider lease; the flow renews it at `renewAtMs`. A
    /// prompt to this own-runner chat names `{provider, model}` (the leased key's, the one model
    /// the lease allows).
    #[serde(rename_all = "camelCase")]
    Lease {
        grant: String,
        provider: String,
        model: String,
        expires_at_ms: f64,
        renew_at_ms: f64,
    },
}

/// A transcript change. Apply in order: on `reset` clear; drop rows with `index <
/// firstIndex`; when `changedFrom` is set drop rows with `index >= changedFrom` and append
/// `rows`; replace `runs`, `approvals`, `pending` and `ssh` when present; take the rest as is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WireDelta {
    pub reset: bool,
    pub first_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub changed_from: Option<u64>,
    pub rows: Vec<WireRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub runs: Option<Vec<WireRun>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub approvals: Option<Vec<WireApproval>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub pending: Option<Vec<WirePending>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub ssh: Option<WireSsh>,
    pub control_revision: u64,
    pub deleted: bool,
    pub omitted_earlier: bool,
}
impl From<&TranscriptDelta> for WireDelta {
    fn from(delta: &TranscriptDelta) -> Self {
        Self {
            reset: delta.reset,
            first_index: delta.first_index,
            changed_from: delta.changed_from,
            rows: delta.rows.iter().map(WireRow::from).collect(),
            runs: delta
                .runs
                .as_ref()
                .map(|runs| runs.iter().map(WireRun::from).collect()),
            approvals: delta
                .approvals
                .as_ref()
                .map(|list| list.iter().map(WireApproval::from).collect()),
            pending: delta
                .pending
                .as_ref()
                .map(|list| list.iter().map(WirePending::from).collect()),
            ssh: delta.ssh.as_ref().map(WireSsh::from),
            control_revision: delta.control_revision,
            deleted: delta.deleted,
            omitted_earlier: delta.omitted_earlier,
        }
    }
}

/// `role`: `user`, `assistant`, `thought`, `tool` or `session`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireRow {
    pub index: u64,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub run: Option<String>,
    pub text: String,
    pub images: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub tool: Option<WireTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub session: Option<WireSession>,
    pub at_ms: u64,
    pub updated_at_ms: u64,
}
fn run_id(run: &RunCoordinate) -> String {
    hex::encode(run.id)
}
impl From<&TranscriptRow> for WireRow {
    fn from(row: &TranscriptRow) -> Self {
        Self {
            index: row.index,
            role: match row.role {
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::Thought => "thought",
                Role::Tool => "tool",
                Role::Session => "session",
            }
            .to_owned(),
            run: row.run.as_ref().map(run_id),
            text: row.text.clone(),
            images: row.images,
            tool: row.tool.as_ref().map(WireTool::from),
            session: row.session.as_ref().map(WireSession::from),
            at_ms: row.at_ms,
            updated_at_ms: row.updated_at_ms,
        }
    }
}

/// `status`: `running`, `awaiting_approval` (until `expiresAtMs`), `approved`, `denied`,
/// `succeeded`, `failed`, `unknown` or `background`. `title` is the row header every client shows
/// (`"<destination> · <label>"`), `label` the tool's short name. `outcomeKind` says what
/// `outcome` is: `pending` (no text), `ok` (JSON text) or `err` (redacted failure text).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireTool {
    pub intent: String,
    pub tool: String,
    pub label: String,
    pub title: String,
    pub arguments: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub destination: Option<String>,
    pub mutates: bool,
    pub redacted: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub expires_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "\"pending\" | \"ok\" | \"err\"")]
    pub outcome_kind: Option<String>,
}
impl From<&ToolCall> for WireTool {
    fn from(call: &ToolCall) -> Self {
        let (status, expires_at_ms) = match call.status {
            ToolStatus::Running => ("running", None),
            ToolStatus::AwaitingApproval { expires_at_ms } => {
                ("awaiting_approval", Some(expires_at_ms))
            }
            ToolStatus::Approved => ("approved", None),
            ToolStatus::Denied => ("denied", None),
            ToolStatus::Succeeded => ("succeeded", None),
            ToolStatus::Failed => ("failed", None),
            ToolStatus::Unknown => ("unknown", None),
            ToolStatus::Background => ("background", None),
        };
        Self {
            intent: hex::encode(call.intent),
            tool: call.tool.clone(),
            label: call.label().to_owned(),
            title: call.title(),
            arguments: call.arguments_json.clone(),
            destination: call.destination.clone(),
            mutates: call.mutates,
            redacted: call.redacted,
            status: status.to_owned(),
            expires_at_ms,
            output: call.output_json.clone(),
            outcome: match &call.outcome {
                Some(ToolOutcome::Ok(text) | ToolOutcome::Err(text)) => Some(text.clone()),
                Some(ToolOutcome::Pending) | None => None,
            },
            outcome_kind: call.outcome.as_ref().map(|outcome| {
                match outcome {
                    ToolOutcome::Pending => "pending",
                    ToolOutcome::Ok(_) => "ok",
                    ToolOutcome::Err(_) => "err",
                }
                .to_owned()
            }),
        }
    }
}

/// `status`: `awaiting_consent` (until `expiresAtMs`), `established`, `lost` or `refused`
/// (with `reason`: `denied`, `expired`, `cancelled`, `source_changed`, `unavailable`,
/// `unsupported`, `capacity`, `connection_lost`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireSession {
    pub attempt: String,
    pub principal: String,
    pub host_key_sha256: String,
    pub ssh: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub terminal: Option<bool>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub expires_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub reason: Option<String>,
}
fn failure(reason: SessionFailure) -> String {
    match reason {
        SessionFailure::Denied => "denied",
        SessionFailure::Expired => "expired",
        SessionFailure::Cancelled => "cancelled",
        SessionFailure::SourceChanged => "source_changed",
        SessionFailure::Unavailable => "unavailable",
        SessionFailure::Unsupported => "unsupported",
        SessionFailure::Capacity => "capacity",
        SessionFailure::ConnectionLost => "connection_lost",
    }
    .to_owned()
}
impl From<&SessionCall> for WireSession {
    fn from(call: &SessionCall) -> Self {
        let (status, expires_at_ms, reason) = match call.status {
            SessionStatus::AwaitingConsent { expires_at_ms } => {
                ("awaiting_consent", Some(expires_at_ms), None)
            }
            SessionStatus::Established => ("established", None, None),
            SessionStatus::Lost(reason) => ("lost", None, Some(failure(reason))),
            SessionStatus::Refused(reason) => ("refused", None, Some(failure(reason))),
        };
        Self {
            attempt: hex::encode(call.attempt),
            principal: call.principal.clone(),
            host_key_sha256: hex::encode(call.host_key),
            ssh: call.ssh,
            terminal: call.terminal,
            status: status.to_owned(),
            expires_at_ms,
            reason,
        }
    }
}

/// `status`: `queued`, `running`, `waiting_approval`, `needs_grant`, `needs_unlock`,
/// `needs_provider_access`, `outcome_unknown`, `interrupted`, `stopped` or `completed`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireRun {
    pub run: String,
    pub status: String,
    pub finished: bool,
    pub usage: WireUsage,
    pub provider: String,
    pub model: String,
    pub pricing: String,
    pub issuer_device: String,
    pub prompt_command: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub thought_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub cost_micros: Option<u64>,
}
impl From<&CloudUsage> for WireUsage {
    fn from(usage: &CloudUsage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            total_tokens: usage.total_tokens,
            cached_input_tokens: usage.cached_input_tokens,
            thought_tokens: usage.thought_tokens,
            cost_micros: usage.cost_micros,
        }
    }
}
fn run_status(status: CloudRunStatus) -> &'static str {
    match status {
        CloudRunStatus::Queued => "queued",
        CloudRunStatus::Running => "running",
        CloudRunStatus::WaitingApproval => "waiting_approval",
        CloudRunStatus::NeedsGrant => "needs_grant",
        CloudRunStatus::NeedsUnlock => "needs_unlock",
        CloudRunStatus::NeedsProviderAccess => "needs_provider_access",
        CloudRunStatus::OutcomeUnknown => "outcome_unknown",
        CloudRunStatus::Interrupted => "interrupted",
        CloudRunStatus::Stopped => "stopped",
        CloudRunStatus::Completed => "completed",
    }
}
impl From<&RunState> for WireRun {
    fn from(state: &RunState) -> Self {
        Self {
            run: run_id(&state.run),
            status: run_status(state.status).to_owned(),
            finished: state.finished(),
            usage: WireUsage::from(&state.usage),
            provider: state.model.provider.as_str().to_owned(),
            model: state.model.model.as_str().to_owned(),
            pricing: state.model.pricing_policy.as_str().to_owned(),
            issuer_device: state.issuer_device.clone(),
            prompt_command: hex::encode(state.prompt_command),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireApproval {
    pub intent: String,
    pub run: String,
    pub expires_at_ms: u64,
}
impl From<&ApprovalRequest> for WireApproval {
    fn from(request: &ApprovalRequest) -> Self {
        Self {
            intent: hex::encode(request.intent()),
            run: run_id(&request.run()),
            expires_at_ms: request.expires_at_ms(),
        }
    }
}

/// A command this device sent. `kind`: `prompt`, `stop`, `allow`, `answer`, `provider`;
/// `state`: `sending`, `delivered`, `unreachable`, `refused`, `accepted`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WirePending {
    pub command_id: String,
    pub kind: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub run: Option<String>,
    pub state: String,
    pub at_ms: f64,
}
pub(super) fn command_state(state: CommandState) -> String {
    match state {
        CommandState::Sending => "sending",
        CommandState::Delivered => "delivered",
        CommandState::Unreachable => "unreachable",
        CommandState::Refused => "refused",
        CommandState::Accepted => "accepted",
    }
    .to_owned()
}
impl From<&PendingCommand> for WirePending {
    fn from(pending: &PendingCommand) -> Self {
        Self {
            command_id: hex::encode(pending.command_id),
            kind: match pending.kind {
                PendingKind::Prompt => "prompt",
                PendingKind::Stop => "stop",
                PendingKind::Allow => "allow",
                PendingKind::Answer => "answer",
                PendingKind::Provider => "provider",
                PendingKind::Bind => "bind",
                PendingKind::Unbind => "unbind",
                PendingKind::Certificate => "certificate",
            }
            .to_owned(),
            text: pending.text.clone(),
            run: pending.run.as_ref().map(run_id),
            state: command_state(pending.state),
            at_ms: ms(pending.at_ms),
        }
    }
}

/// A model a prompt names (`provider: "managed"` for a managed agent's model).
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
pub struct ModelInput {
    pub provider: String,
    pub model: String,
}

/// What the person asks of an open chat. Ids are lowercase hex.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ChatActionInput {
    /// Without a model, the latest run's.
    Prompt {
        text: String,
        #[serde(default)]
        #[tsify(optional)]
        model: Option<ModelInput>,
    },
    /// Without a run, the active run.
    Stop {
        #[serde(default)]
        #[tsify(optional)]
        run: Option<String>,
    },
    Allow {
        run: String,
    },
    Answer {
        intent: String,
        approve: bool,
    },
}

/// Where a new chat runs.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum NewChatHost {
    /// A managed agent; its seat is started for the chat.
    #[serde(rename_all = "camelCase")]
    Managed { agent_id: String },
    /// An enrolled own runner (hex id).
    #[serde(rename_all = "camelCase")]
    Own { runner_id: String },
}
