//! Projection facts only; no value here is a grant or native execution permit.
use crate::cloud::{
    CommandIssuer, CommandKind,
    payload::{ExecutionReference, ModelSelection, PromptPart, SessionReference, TargetAccess},
    tool_arguments::ToolArguments,
};
use core::fmt;

pub const MAX_SNAPSHOT_EVENTS: usize = 4096;
pub const MAX_EVENT_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_EVENT_JSON_BYTES: usize = 4 * 1024 * 1024;
/// Largest publication time representable by signed millisecond date APIs.
pub const MAX_PUBLICATION_TIMESTAMP_MS: u64 = u64::MAX >> 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedCommand {
    pub id: [u8; 16],
    pub kind: CommandKind,
    pub signed_message_digest: [u8; 32],
    pub issuer: CommandIssuer,
    pub expected_control_revision: u64,
}
/// Accepted display content. Execution limits, grants and credentials stay in
/// the original admitted command; replaying this value cannot restore them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedPrompt<'a> {
    pub content: Vec<PromptPart<'a>>,
    pub model: ModelSelection,
    pub target: Option<TargetAccess>,
    pub existing_session: Option<SessionReference>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CloudRunStatus {
    Queued = 1,
    Running = 2,
    WaitingApproval = 3,
    NeedsGrant = 4,
    NeedsUnlock = 5,
    NeedsProviderAccess = 6,
    OutcomeUnknown = 7,
    Interrupted = 8,
    Stopped = 9,
    Completed = 10,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CloudTextChannel {
    Assistant = 1,
    Thought = 2,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CloudUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub thought_tokens: Option<u64>,
    pub cost_micros: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolIntentPayload<'a> {
    pub id: [u8; 16],
    pub step: [u8; 16],
    pub execution: ExecutionReference,
    pub arguments_digest: [u8; 32],
    pub mutates: bool,
    pub arguments: ToolArguments<'a>,
    pub display: ToolPresentation<'a>,
}
#[derive(Clone, PartialEq, Eq)]
pub enum DisplayOutcome<'a> {
    Pending,
    Ok(&'a str),
    Err(&'a str),
}
impl fmt::Debug for DisplayOutcome<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "Pending",
            Self::Ok(_) => "Ok([redacted])",
            Self::Err(_) => "Err([redacted])",
        })
    }
}
/// JSON is bounded presentation data. It is not the canonical argument identity
/// and must never be converted into an execution permit by a consumer.
#[derive(Clone, PartialEq, Eq)]
pub struct ToolPresentation<'a> {
    pub tool: &'a str,
    pub arguments_json: &'a str,
    pub destination: Option<&'a str>,
    pub redacted: bool,
    pub outcome: Option<DisplayOutcome<'a>>,
}
impl fmt::Debug for ToolPresentation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolPresentation")
            .field("tool", &self.tool)
            .finish_non_exhaustive()
    }
}
/// Optional real native job timing. A grant expiry is not a job deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobWindow {
    pub created_at_ms: u64,
    pub deadline_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackgroundJob<'a> {
    pub intent: [u8; 16],
    pub execution: ExecutionReference,
    pub terminal: &'a str,
    pub command: &'a str,
    pub window: Option<JobWindow>,
}
/// Observation of the exact already admitted native dispatch. No original call,
/// display or new dispatch permit is manufactured from its arguments digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackgroundLifecyclePayload<'a> {
    pub job: BackgroundJob<'a>,
    pub step: [u8; 16],
    pub arguments_digest: [u8; 32],
    pub mutates: bool,
    pub dispatch_writer_epoch: u64,
    pub dispatch_revision: u64,
    pub outcome: BackgroundOutcome,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundOutcome {
    Retained,
    ObservedExit(u32),
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedEffect<'a> {
    Observed,
    Unknown,
    Background(Box<BackgroundJob<'a>>),
}
#[derive(Clone, PartialEq, Eq)]
pub struct ToolObservationPayload<'a> {
    pub intent: [u8; 16],
    pub output_json: &'a str,
    pub display: ToolPresentation<'a>,
    pub effect: ObservedEffect<'a>,
    pub failed: bool,
}
impl fmt::Debug for ToolObservationPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolObservationPayload")
            .field("intent", &self.intent)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
impl CloudRunStatus {
    pub(super) fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::Queued,
            2 => Self::Running,
            3 => Self::WaitingApproval,
            4 => Self::NeedsGrant,
            5 => Self::NeedsUnlock,
            6 => Self::NeedsProviderAccess,
            7 => Self::OutcomeUnknown,
            8 => Self::Interrupted,
            9 => Self::Stopped,
            10 => Self::Completed,
            _ => return None,
        })
    }
}
impl CloudTextChannel {
    pub(super) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Assistant),
            2 => Some(Self::Thought),
            _ => None,
        }
    }
}
