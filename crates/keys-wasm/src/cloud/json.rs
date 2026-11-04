//! The JSON the page reads: witnessed heads, catalog pages and transcripts. Display data only;
//! identifiers are lowercase hex and times are milliseconds.
use nocterm_cloud_device::transcript::{Role, RunState, ToolStatus, Transcript, TranscriptRow};
use nocterm_hub_model::cloud::{
    RunCoordinate,
    events::{CloudRunStatus, CloudUsage},
    head::{CatalogHeadCursor, CatalogHeadPage, ChatHead},
};
use serde_json::{Value, json};

pub(super) fn head(head: &ChatHead) -> Value {
    json!({
        "chatId": hex::encode(head.chat_id),
        "keyEpoch": head.chat_key_epoch,
        "controlRevision": head.control_revision,
        "deleted": head.deleted,
        "headSequence": head.head.as_ref().map(|anchor| anchor.position.sequence),
        "retainedFrom": head.retained_from,
    })
}

pub(super) fn catalog(page: &CatalogHeadPage) -> Value {
    json!({
        "kind": "catalog",
        "chats": page.chats.iter().map(head).collect::<Vec<_>>(),
        "hasMore": page.has_more,
        "totalChats": page.total_chats,
        "next": page.next_cursor().map(|next| json!({
            "revision": next.revision,
            "digest": hex::encode(next.digest),
            "after": hex::encode(next.after),
            "seen": next.seen,
        })),
    })
}

/// The `next` value of a catalog page back into its cursor.
pub(super) fn cursor(value: &Value) -> Option<CatalogHeadCursor> {
    let bytes = |name: &str| hex::decode(value.get(name)?.as_str()?).ok();
    Some(CatalogHeadCursor {
        revision: value.get("revision")?.as_u64()?,
        digest: bytes("digest")?.try_into().ok()?,
        after: bytes("after")?.try_into().ok()?,
        seen: u32::try_from(value.get("seen")?.as_u64()?).ok()?,
    })
}

fn run_id(run: &RunCoordinate) -> String {
    hex::encode(run.id)
}

const fn role(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Thought => "thought",
        Role::Tool => "tool",
    }
}

pub(super) const fn run_status(status: CloudRunStatus) -> &'static str {
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

fn tool_status(status: ToolStatus) -> (&'static str, Option<u64>) {
    match status {
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
    }
}

fn row(row: &TranscriptRow) -> Value {
    let tool = row.tool.as_ref().map(|call| {
        let (status, expires) = tool_status(call.status);
        json!({
            "intent": hex::encode(call.intent),
            "tool": call.tool,
            "arguments": call.arguments_json,
            "destination": call.destination,
            "mutates": call.mutates,
            "redacted": call.redacted,
            "status": status,
            "expiresAtMs": expires,
            "output": call.output_json,
            "outcome": call.outcome,
        })
    });
    json!({
        "role": role(row.role),
        "run": row.run.as_ref().map(run_id),
        "text": row.text,
        "images": row.images,
        "tool": tool,
        "atMs": row.at_ms,
        "updatedAtMs": row.updated_at_ms,
    })
}

fn usage(usage: &CloudUsage) -> Value {
    json!({
        "inputTokens": usage.input_tokens,
        "outputTokens": usage.output_tokens,
        "totalTokens": usage.total_tokens,
        "cachedInputTokens": usage.cached_input_tokens,
        "thoughtTokens": usage.thought_tokens,
        "costMicros": usage.cost_micros,
    })
}

fn run(state: &RunState) -> Value {
    json!({
        "run": run_id(&state.run),
        "status": run_status(state.status),
        "finished": state.finished(),
        "usage": usage(&state.usage),
        "model": {
            "provider": state.model.provider.as_str(),
            "model": state.model.model.as_str(),
            "pricing": state.model.pricing_policy.as_str(),
        },
        "issuerDevice": state.issuer_device,
        "promptCommand": hex::encode(state.prompt_command),
    })
}

pub(super) fn transcript(transcript: &Transcript) -> Value {
    json!({
        "rows": transcript.rows().iter().map(row).collect::<Vec<_>>(),
        "runs": transcript.runs().iter().map(run).collect::<Vec<_>>(),
        "activeRun": transcript.active_run().map(|state| run_id(&state.run)),
        "approvals": transcript.pending_approvals().iter().map(|request| json!({
            "intent": hex::encode(request.intent()),
            "run": run_id(&request.run()),
            "expiresAtMs": request.expires_at_ms(),
        })).collect::<Vec<_>>(),
        "controlRevision": transcript.control_revision(),
        "deleted": transcript.deleted(),
        "omittedEarlier": transcript.omitted_earlier(),
    })
}
