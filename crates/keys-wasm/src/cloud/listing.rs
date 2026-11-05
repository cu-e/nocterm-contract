//! What `listChats` takes and reports (ADR 0008): rows merged from the runner's directory of
//! signed summaries and its fresh catalog witness, and the sealed directory checkpoints the page
//! stores per runner.
use nocterm_cloud_device::{
    directory::{ListedChat, RowStatus},
    list::ChatListUpdate,
};
use nocterm_hub_model::cloud::summary::{
    BoundServer, ChatState, ChatSummary, ServerState, SummaryHost,
};
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;

use super::{
    WebCloudError,
    types::WireError,
    view::{FlowOutput, RunnerInfo, ms},
};

/// `listChats` options: the `directories` checkpoints stored from earlier listings (any order,
/// one per runner), and `watch` to keep reading new summaries (the flow then never ends).
#[derive(Clone, Debug, Default, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct ListOptions {
    #[serde(default)]
    #[tsify(optional, type = "Uint8Array[]")]
    pub directories: Option<Vec<serde_bytes::ByteBuf>>,
    #[serde(default)]
    #[tsify(optional)]
    pub watch: Option<bool>,
}

/// One listed chat. `status`: `current` (the runner confirmed the summary), `stale` (the runner
/// witnessed newer history), `unsummarized` (no summary: show `Chat · <id>`), `pending` (the
/// runner's answer is still out), `asOf` (the runner did not confirm: show "as of
/// `summary.lastActivityMs`") or `unlisted` (the runner no longer lists the chat).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireChat {
    /// `ChatRef` text, the id `openChat` takes.
    pub chat_id: String,
    #[tsify(type = r#""current" | "stale" | "unsummarized" | "pending" | "asOf" | "unlisted""#)]
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub summary: Option<WireSummary>,
    pub control_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub head_sequence: Option<u64>,
    pub deleted: bool,
    /// When the runner witnessed the chat in this listing; absent when it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub witnessed_at_ms: Option<f64>,
}

/// A runner-signed chat summary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireSummary {
    /// Empty before the first accepted prompt.
    pub title: String,
    pub created_at_ms: f64,
    pub last_activity_ms: f64,
    /// `managed` (with `agentId`) or `own`.
    #[tsify(type = r#""managed" | "own""#)]
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub model: Option<String>,
    #[tsify(
        type = r#""idle" | "running" | "waitingApproval" | "needsGrant" | "needsProvider" | "needsSsh" | "failed" | "deleted""#
    )]
    pub state: String,
    pub pending_approvals: u16,
    pub servers: Vec<WireServer>,
    /// Runner features: 1 SSH binding, 2 own provider lease.
    pub features: u32,
}

/// A server the chat is bound to; `serverId` (32 hex) is its `agent_ssh_trust` registry id
/// (`srv-<serverId>`), so the page joins it with its trust record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireServer {
    pub server_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    #[tsify(type = r#""active" | "awaitingDevice" | "unreachable" | "needsCaUpdate""#)]
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub valid_before_ms: Option<f64>,
}

fn status(status: RowStatus) -> &'static str {
    match status {
        RowStatus::Current => "current",
        RowStatus::Stale => "stale",
        RowStatus::Unsummarized => "unsummarized",
        RowStatus::Pending => "pending",
        RowStatus::AsOf => "asOf",
        RowStatus::Unlisted => "unlisted",
    }
}
fn state(state: ChatState) -> &'static str {
    match state {
        ChatState::Idle => "idle",
        ChatState::Running => "running",
        ChatState::WaitingApproval => "waitingApproval",
        ChatState::NeedsGrant => "needsGrant",
        ChatState::NeedsProvider => "needsProvider",
        ChatState::NeedsSsh => "needsSsh",
        ChatState::Failed => "failed",
        ChatState::Deleted => "deleted",
    }
}
fn server(server: &BoundServer) -> WireServer {
    WireServer {
        server_id: hex::encode(server.server.as_bytes()),
        host: server.host.as_str().to_owned(),
        port: server.port,
        user: server.user.as_str().to_owned(),
        state: match server.state {
            ServerState::Active => "active",
            ServerState::AwaitingDevice => "awaitingDevice",
            ServerState::Unreachable => "unreachable",
            ServerState::NeedsCaUpdate => "needsCaUpdate",
        }
        .to_owned(),
        valid_before_ms: server.valid_before_ms.map(ms),
    }
}
fn summary(summary: &ChatSummary) -> WireSummary {
    let (host, agent_id) = match &summary.host {
        SummaryHost::Managed { agent_id } => ("managed", Some(agent_id.as_str().to_owned())),
        SummaryHost::Own => ("own", None),
    };
    WireSummary {
        title: summary.title.clone(),
        created_at_ms: ms(summary.created_at_ms),
        last_activity_ms: ms(summary.last_activity_ms),
        host: host.to_owned(),
        agent_id,
        provider: summary
            .model
            .as_ref()
            .map(|m| m.provider.as_str().to_owned()),
        model: summary.model.as_ref().map(|m| m.model.as_str().to_owned()),
        state: state(summary.state).to_owned(),
        pending_approvals: summary.pending_approvals,
        servers: summary.servers.iter().map(server).collect(),
        features: summary.features,
    }
}
fn chat(chat: &ListedChat) -> WireChat {
    WireChat {
        chat_id: chat.chat.to_string(),
        status: status(chat.status).to_owned(),
        summary: chat.summary.as_ref().map(summary),
        control_revision: chat.control_revision,
        head_sequence: chat.head_sequence,
        deleted: chat.deleted,
        witnessed_at_ms: chat.witnessed_at_ms.map(ms),
    }
}

/// A listing update as the page reads it.
pub(super) fn listed(update: ChatListUpdate) -> FlowOutput {
    let error = |error| -> WireError { WebCloudError::from(error).wire() };
    match update {
        ChatListUpdate::Seats(seats) => FlowOutput::Seats {
            seats: seats.iter().map(super::flow::instance_out).collect(),
        },
        ChatListUpdate::Runner {
            runner,
            chats,
            complete,
        } => FlowOutput::RunnerChats {
            runner: RunnerInfo::from(&runner),
            chats: chats.iter().map(chat).collect(),
            complete,
        },
        ChatListUpdate::Unreachable { runner, reason } => FlowOutput::Unreachable {
            runner: RunnerInfo::from(&runner),
            error: reason.map(error),
        },
        ChatListUpdate::Directory { runner, checkpoint } => FlowOutput::Directory {
            runner_id: hex::encode(runner),
            bytes: checkpoint.into_bytes(),
        },
        ChatListUpdate::DirectoryRefused { runner, reason } => FlowOutput::DirectoryRefused {
            runner: RunnerInfo::from(&runner),
            error: error(reason),
        },
    }
}
