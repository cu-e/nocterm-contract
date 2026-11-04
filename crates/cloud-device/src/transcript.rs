//! A small reducer from verified runner events to neutral display rows.
//!
//! It is fed only events the replay verifier opened under the pinned runner, in sequence order.
//! Rows are display data: a pending approval row lets the caller build an answer, but nothing
//! here admits or grants anything. Session-start events are not projected (as on desktop).
use nocterm_hub_model::cloud::{
    RunCoordinate,
    events::{
        BackgroundOutcome, CloudEvent, CloudEventPayload, CloudRunStatus, CloudSnapshotPayload,
        CloudTextChannel, CloudUsage, DisplayOutcome, ObservedEffect, ToolIntentPayload,
        ToolObservationPayload,
    },
    payload::{ApprovalChoice, ApprovalPayload, ExecutionReference, ModelSelection, PromptPart},
};

/// Rows kept per chat; older rows are dropped and [`Transcript::omitted_earlier`] is set.
pub const MAX_TRANSCRIPT_ROWS: usize = 4096;

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

/// One display row. Plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptRow {
    pub role: Role,
    pub run: Option<RunCoordinate>,
    /// Prompt or streamed text; empty for tool rows.
    pub text: String,
    /// Images attached to a prompt.
    pub images: u32,
    pub tool: Option<ToolCall>,
    /// Publication time of the first event of this row.
    pub at_ms: u64,
    /// Publication time of the last event merged into this row.
    pub updated_at_ms: u64,
    step: Option<[u8; 16]>,
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
    intent: [u8; 16],
    arguments_digest: [u8; 32],
    execution: ExecutionReference,
    expires_at_ms: u64,
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

/// The reduced state of one chat.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transcript {
    rows: Vec<TranscriptRow>,
    runs: Vec<RunState>,
    approvals: Vec<ApprovalRequest>,
    control_revision: u64,
    deleted: bool,
    omitted_earlier: bool,
}
impl Transcript {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn rows(&self) -> &[TranscriptRow] {
        &self.rows
    }
    pub fn runs(&self) -> &[RunState] {
        &self.runs
    }
    /// The latest run that has not finished.
    pub fn active_run(&self) -> Option<&RunState> {
        self.runs.iter().rev().find(|run| !run.finished())
    }
    pub fn run(&self, run: &RunCoordinate) -> Option<&RunState> {
        self.runs.iter().find(|state| &state.run == run)
    }
    /// The highest control revision seen; commands name it as their expected chat revision.
    pub fn control_revision(&self) -> u64 {
        self.control_revision
    }
    pub fn deleted(&self) -> bool {
        self.deleted
    }
    /// True when history before the first row is not available (a snapshot window or the row
    /// bound).
    pub fn omitted_earlier(&self) -> bool {
        self.omitted_earlier
    }
    pub fn pending_approvals(&self) -> &[ApprovalRequest] {
        &self.approvals
    }
    pub fn approval(&self, intent: &[u8; 16]) -> Option<&ApprovalRequest> {
        self.approvals
            .iter()
            .find(|request| &request.intent == intent)
    }
    /// Replaces everything with the history a verified snapshot carries.
    pub fn restore(&mut self, snapshot: &CloudSnapshotPayload<'_>) {
        *self = Self::new();
        self.omitted_earlier = snapshot.omitted_earlier;
        for event in &snapshot.events {
            self.apply(event);
        }
        self.control_revision = self.control_revision.max(snapshot.control_revision);
    }
    /// Applies one verified event.
    pub fn apply(&mut self, event: &CloudEvent<'_>) {
        self.control_revision = self.control_revision.max(event.control_revision);
        let at = event.timestamp_ms;
        match &event.payload {
            CloudEventPayload::PromptAccepted {
                command,
                run,
                prompt,
            } => {
                let (text, images) = prompt_text(&prompt.content);
                if self.runs.len() == MAX_TRANSCRIPT_ROWS {
                    self.runs.remove(0);
                }
                self.runs.push(RunState {
                    run: *run,
                    status: CloudRunStatus::Queued,
                    usage: CloudUsage::default(),
                    model: prompt.model.clone(),
                    issuer_device: command.issuer.device_id.as_str().to_owned(),
                    issuer_key: command.issuer.signing_key,
                    prompt_command: command.id,
                });
                self.push(TranscriptRow {
                    role: Role::User,
                    run: Some(*run),
                    text,
                    images,
                    tool: None,
                    at_ms: at,
                    updated_at_ms: at,
                    step: None,
                });
            }
            CloudEventPayload::Status { run, status } => {
                if let Some(state) = self.runs.iter_mut().find(|state| &state.run == run) {
                    state.status = *status;
                }
            }
            CloudEventPayload::Text {
                run,
                step,
                channel,
                text,
            } => self.text(*run, *step, *channel, text, at),
            CloudEventPayload::Usage { run, usage } => {
                if let Some(state) = self.runs.iter_mut().find(|state| &state.run == run) {
                    add_usage(&mut state.usage, usage);
                }
            }
            CloudEventPayload::ToolIntent(intent) => {
                self.tool(intent, ToolStatus::Running, at);
            }
            CloudEventPayload::Approval {
                intent,
                expires_at_ms,
            } => {
                self.tool(
                    intent,
                    ToolStatus::AwaitingApproval {
                        expires_at_ms: *expires_at_ms,
                    },
                    at,
                );
                self.approvals.retain(|request| request.intent != intent.id);
                if self.approvals.len() == MAX_TRANSCRIPT_ROWS {
                    self.approvals.remove(0);
                }
                self.approvals.push(ApprovalRequest {
                    intent: intent.id,
                    arguments_digest: intent.arguments_digest,
                    execution: intent.execution.clone(),
                    expires_at_ms: *expires_at_ms,
                });
            }
            CloudEventPayload::ApprovalResolved { answer, .. } => {
                self.approvals
                    .retain(|request| request.intent != answer.intent);
                let status = match answer.choice {
                    ApprovalChoice::Deny | ApprovalChoice::ReconcileFailed => ToolStatus::Denied,
                    _ => ToolStatus::Approved,
                };
                self.update_tool(&answer.intent, at, |call| call.status = status);
            }
            CloudEventPayload::ToolResult { observation, .. } => self.result(observation, at),
            CloudEventPayload::BackgroundLifecycle(value) => {
                let status = match value.outcome {
                    BackgroundOutcome::Retained => ToolStatus::Background,
                    BackgroundOutcome::ObservedExit(0) => ToolStatus::Succeeded,
                    BackgroundOutcome::ObservedExit(_) => ToolStatus::Failed,
                    BackgroundOutcome::Unknown => ToolStatus::Unknown,
                };
                self.update_tool(&value.job.intent, at, |call| call.status = status);
            }
            CloudEventPayload::Deleted { .. } => self.deleted = true,
            CloudEventPayload::CommandAccepted { .. }
            | CloudEventPayload::AuthenticationRequested(_)
            | CloudEventPayload::SessionState(_) => {}
        }
    }

    fn push(&mut self, row: TranscriptRow) {
        if self.rows.len() == MAX_TRANSCRIPT_ROWS {
            self.rows.remove(0);
            self.omitted_earlier = true;
        }
        self.rows.push(row);
    }
    fn text(
        &mut self,
        run: RunCoordinate,
        step: Option<[u8; 16]>,
        channel: CloudTextChannel,
        text: &str,
        at: u64,
    ) {
        let role = match channel {
            CloudTextChannel::Assistant => Role::Assistant,
            CloudTextChannel::Thought => Role::Thought,
        };
        if let Some(last) = self.rows.last_mut()
            && last.role == role
            && last.run == Some(run)
            && last.step == step
        {
            last.text.push_str(text);
            last.updated_at_ms = at;
            return;
        }
        self.push(TranscriptRow {
            role,
            run: Some(run),
            text: text.to_owned(),
            images: 0,
            tool: None,
            at_ms: at,
            updated_at_ms: at,
            step,
        });
    }
    fn tool(&mut self, intent: &ToolIntentPayload<'_>, status: ToolStatus, at: u64) {
        let display = &intent.display;
        let outcome = display.outcome.as_ref().and_then(outcome_text);
        if self.update_tool(&intent.id, at, |call| {
            call.status = status;
            if outcome.is_some() {
                call.outcome.clone_from(&outcome);
            }
        }) {
            return;
        }
        self.push(TranscriptRow {
            role: Role::Tool,
            run: Some(intent.execution.run),
            text: String::new(),
            images: 0,
            tool: Some(ToolCall {
                intent: intent.id,
                tool: display.tool.to_owned(),
                arguments_json: display.arguments_json.to_owned(),
                destination: display.destination.map(str::to_owned),
                mutates: intent.mutates,
                redacted: display.redacted,
                status,
                output_json: None,
                outcome,
            }),
            at_ms: at,
            updated_at_ms: at,
            step: Some(intent.step),
        });
    }
    fn result(&mut self, observation: &ToolObservationPayload<'_>, at: u64) {
        let status = match (&observation.effect, observation.failed) {
            (ObservedEffect::Unknown, _) => ToolStatus::Unknown,
            (ObservedEffect::Background(_), false) => ToolStatus::Background,
            (_, true) => ToolStatus::Failed,
            (ObservedEffect::Observed, false) => ToolStatus::Succeeded,
        };
        let outcome = observation.display.outcome.as_ref().and_then(outcome_text);
        self.update_tool(&observation.intent, at, |call| {
            call.status = status;
            call.output_json = Some(observation.output_json.to_owned());
            if outcome.is_some() {
                call.outcome.clone_from(&outcome);
            }
        });
    }
    /// Updates the row of a tool call; false when no row announced it.
    fn update_tool(
        &mut self,
        intent: &[u8; 16],
        at: u64,
        change: impl FnOnce(&mut ToolCall),
    ) -> bool {
        let Some(row) = self
            .rows
            .iter_mut()
            .rev()
            .find(|row| row.tool.as_ref().is_some_and(|call| &call.intent == intent))
        else {
            return false;
        };
        row.updated_at_ms = at;
        if let Some(call) = row.tool.as_mut() {
            change(call);
        }
        true
    }
}

fn prompt_text(content: &[PromptPart<'_>]) -> (String, u32) {
    let mut text = String::new();
    let mut images = 0u32;
    for part in content {
        match part {
            PromptPart::Text(value) => text.push_str(value),
            PromptPart::Image { .. } => images = images.saturating_add(1),
        }
    }
    (text, images)
}
fn outcome_text(outcome: &DisplayOutcome<'_>) -> Option<String> {
    match outcome {
        DisplayOutcome::Pending => None,
        DisplayOutcome::Ok(text) | DisplayOutcome::Err(text) => Some((*text).to_owned()),
    }
}
fn add_usage(total: &mut CloudUsage, usage: &CloudUsage) {
    let add = |total: &mut Option<u64>, value: Option<u64>| {
        if let Some(value) = value {
            *total = Some(total.unwrap_or(0).saturating_add(value));
        }
    };
    add(&mut total.input_tokens, usage.input_tokens);
    add(&mut total.output_tokens, usage.output_tokens);
    add(&mut total.total_tokens, usage.total_tokens);
    add(&mut total.cached_input_tokens, usage.cached_input_tokens);
    add(&mut total.thought_tokens, usage.thought_tokens);
    add(&mut total.cost_micros, usage.cost_micros);
}

#[cfg(test)]
mod tests;
