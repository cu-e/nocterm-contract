//! The plain display values a transcript holds. None of them grants or admits anything.
use nocterm_hub_model::cloud::{
    RunCoordinate,
    events::{CloudRunStatus, CloudUsage},
    payload::{
        ApprovalChoice, ApprovalPayload, ExecutionReference, ModelSelection, SessionFailure,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// An accepted prompt.
    User,
    /// Assistant text.
    Assistant,
    /// Model reasoning text.
    Thought,
    /// A tool call and its outcome.
    Tool,
    /// A connection the runner asked for or opened (SSH consent, session lifecycle).
    Session,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolStatus {
    /// Announced and running, or waiting for its result.
    Running,
    /// Waiting for the person's answer until this time.
    AwaitingApproval {
        expires_at_ms: u64,
    },
    Approved,
    Denied,
    Succeeded,
    Failed,
    /// The effect may or may not have happened.
    Unknown,
    /// Continues as a background job.
    Background,
}

/// One tool call. Plain display data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    pub intent: [u8; 16],
    pub tool: String,
    pub arguments_json: String,
    pub destination: Option<String>,
    pub mutates: bool,
    pub redacted: bool,
    pub status: ToolStatus,
    pub output_json: Option<String>,
    /// The display outcome text the runner attached, if any.
    pub outcome: Option<String>,
}

/// Where a session stands, as the runner reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    /// The runner asks a device holding the SSH key to approve the login until this time.
    AwaitingConsent {
        expires_at_ms: u64,
    },
    Established,
    Lost(SessionFailure),
    Refused(SessionFailure),
}

/// One connection attempt of a run, keyed by its attempt id. Plain display data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCall {
    pub attempt: [u8; 16],
    /// The login name on the target.
    pub principal: String,
    /// SHA-256 of the target's pinned host key.
    pub host_key: [u8; 32],
    /// An SSH login (true) or a local session on the runner (false).
    pub ssh: bool,
    /// A terminal session (true) or a connection without a shell (false), when the runner's
    /// consent request stated it.
    pub terminal: Option<bool>,
    pub status: SessionStatus,
}

/// One display row. Plain data. `index` numbers rows from the first one this transcript ever
/// held, so a row keeps its index when earlier rows are dropped by the bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptRow {
    pub index: u64,
    pub role: Role,
    pub run: Option<RunCoordinate>,
    /// Prompt or streamed text; empty for tool and session rows.
    pub text: String,
    /// Images attached to a prompt.
    pub images: u32,
    pub tool: Option<ToolCall>,
    pub session: Option<SessionCall>,
    /// Publication time of the first event of this row.
    pub at_ms: u64,
    /// Publication time of the last event merged into this row.
    pub updated_at_ms: u64,
    pub(super) step: Option<[u8; 16]>,
}

/// One run started by an accepted prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunState {
    pub run: RunCoordinate,
    pub status: CloudRunStatus,
    pub usage: CloudUsage,
    pub model: ModelSelection,
    /// The device that sent the prompt.
    pub issuer_device: String,
    pub issuer_key: [u8; 32],
    pub prompt_command: [u8; 16],
}
impl RunState {
    /// Completed, stopped, interrupted or of unknown outcome.
    pub fn finished(&self) -> bool {
        matches!(
            self.status,
            CloudRunStatus::Completed
                | CloudRunStatus::Stopped
                | CloudRunStatus::Interrupted
                | CloudRunStatus::OutcomeUnknown
        )
    }
}

/// A tool call waiting for the person's answer, with what the answer must name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub(super) intent: [u8; 16],
    pub(super) arguments_digest: [u8; 32],
    pub(super) execution: ExecutionReference,
    pub(super) expires_at_ms: u64,
}
impl ApprovalRequest {
    pub fn intent(&self) -> [u8; 16] {
        self.intent
    }
    pub fn run(&self) -> RunCoordinate {
        self.execution.run
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// The `ResolveApproval` payload answering this request.
    pub fn answer(&self, choice: ApprovalChoice) -> ApprovalPayload {
        ApprovalPayload {
            intent: self.intent,
            arguments_digest: self.arguments_digest,
            execution: self.execution.clone(),
            choice,
        }
    }
}

/// What a command this device sent asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingKind {
    Prompt,
    Stop,
    Allow,
    Answer,
    Provider,
    /// Bind the chat to servers (`IssueGrant(SshBinding)`).
    Bind,
    /// Revoke the chat's binding (`RevokeGrant(SshBinding)`).
    Unbind,
    /// Answer a runner's certificate request (`IssueGrant(SshCertificate)`).
    Certificate,
}

/// Where a command this device sent stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandState {
    /// Signed and sealed; the hub has not confirmed it yet.
    Sending,
    /// The hub stored it for the runner (a delivery receipt), the runner has not answered.
    Delivered,
    /// Neither the hub nor the runner could be reached before the command expired.
    Unreachable,
    /// The hub or the runner refused it (a revision conflict, an expired window, a policy).
    Refused,
    /// The runner accepted it (an accepted event or a receipt witness).
    Accepted,
}

/// A command this device sent, shown until the runner accepts or it ends. Device-local: it is
/// not part of a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCommand {
    pub command_id: [u8; 16],
    pub kind: PendingKind,
    /// The prompt text of a prompt; empty otherwise.
    pub text: String,
    pub run: Option<RunCoordinate>,
    pub state: CommandState,
    pub at_ms: i64,
}
impl PendingCommand {
    /// Accepted, refused or unreachable: nothing more will happen to it.
    pub fn settled(&self) -> bool {
        !matches!(self.state, CommandState::Sending | CommandState::Delivered)
    }
}
