//! The reducer from verified runner events to neutral display rows, shared by every device.
//!
//! It is fed only events the reader opened under the pinned runner, in sequence order. Rows are
//! display data: a pending approval row lets the caller build an answer, but nothing here admits
//! or grants anything. It shows what the native client shows (prompts, text, tool calls with
//! approvals and background jobs, runs with status and usage, snapshot windows, deletion) and,
//! beyond it, SSH consent requests and session lifecycle rows. Commands this device sent are
//! tracked as pending commands until the runner accepts them. Changes accumulate until the
//! caller takes them as a [`TranscriptDelta`].
pub(crate) mod codec;
mod delta;
mod types;

pub use delta::TranscriptDelta;
pub use types::{
    ApprovalRequest, CommandState, PendingCommand, PendingKind, Role, RunState, SessionCall,
    SessionStatus, ToolCall, ToolStatus, TranscriptRow,
};

use delta::Dirty;
use nocterm_hub_model::cloud::{
    RunCoordinate,
    events::{
        BackgroundOutcome, CloudEvent, CloudEventPayload, CloudRunStatus, CloudSnapshotPayload,
        CloudTextChannel, CloudUsage, DisplayOutcome, ObservedEffect, ToolIntentPayload,
        ToolObservationPayload,
    },
    payload::{ApprovalChoice, PromptPart, SessionOutcome, SessionStartup, TargetAccess},
};

/// Rows kept per chat; older rows are dropped and [`Transcript::omitted_earlier`] is set.
pub const MAX_TRANSCRIPT_ROWS: usize = 4096;
/// Commands of this device tracked at once; the oldest settled one goes first.
pub const MAX_PENDING_COMMANDS: usize = 32;
/// The reducer's version. A checkpoint made by another version is not restored: the chat is
/// read again from the start.
pub const REDUCER_VERSION: u16 = 1;

/// The reduced state of one chat.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transcript {
    rows: Vec<TranscriptRow>,
    runs: Vec<RunState>,
    approvals: Vec<ApprovalRequest>,
    pending: Vec<PendingCommand>,
    next_index: u64,
    control_revision: u64,
    deleted: bool,
    omitted_earlier: bool,
    dirty: Dirty,
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
    /// The run whose id is `id`, whatever its epoch.
    pub fn run_by_id(&self, id: &[u8; 16]) -> Option<&RunState> {
        self.runs.iter().find(|state| &state.run.id == id)
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
    /// Commands this device sent, oldest first.
    pub fn pending_commands(&self) -> &[PendingCommand] {
        &self.pending
    }

    /// Starts tracking a command this device sends. A command already tracked is replaced.
    pub fn track(&mut self, command: PendingCommand) {
        self.pending
            .retain(|known| known.command_id != command.command_id);
        if self.pending.len() >= MAX_PENDING_COMMANDS {
            let oldest = self
                .pending
                .iter()
                .position(PendingCommand::settled)
                .unwrap_or(0);
            self.pending.remove(oldest);
        }
        self.pending.push(command);
        self.dirty.pending = true;
    }
    /// Moves a tracked command to `state`; an accepted command stays accepted.
    pub fn set_command_state(&mut self, command_id: &[u8; 16], state: CommandState) {
        if let Some(known) = self
            .pending
            .iter_mut()
            .find(|known| &known.command_id == command_id)
            && known.state != CommandState::Accepted
            && known.state != state
        {
            known.state = state;
            self.dirty.pending = true;
        }
    }

    /// Everything as one reset delta, for a view that starts now.
    pub fn full_delta(&self) -> TranscriptDelta {
        TranscriptDelta {
            reset: true,
            first_index: self.first_index(),
            changed_from: Some(0),
            rows: self.rows.clone(),
            runs: Some(self.runs.clone()),
            approvals: Some(self.approvals.clone()),
            pending: Some(self.pending.clone()),
            control_revision: self.control_revision,
            deleted: self.deleted,
            omitted_earlier: self.omitted_earlier,
        }
    }
    /// What changed since the last call, or `None` when nothing did.
    pub fn take_delta(&mut self) -> Option<TranscriptDelta> {
        let dirty = std::mem::take(&mut self.dirty);
        if !dirty.any() {
            return None;
        }
        if dirty.reset {
            return Some(self.full_delta());
        }
        let rows = dirty.rows_from.map_or_else(Vec::new, |from| {
            self.rows
                .iter()
                .filter(|row| row.index >= from)
                .cloned()
                .collect()
        });
        Some(TranscriptDelta {
            reset: false,
            first_index: self.first_index(),
            changed_from: dirty.rows_from,
            rows,
            runs: dirty.runs.then(|| self.runs.clone()),
            approvals: dirty.approvals.then(|| self.approvals.clone()),
            pending: dirty.pending.then(|| self.pending.clone()),
            control_revision: self.control_revision,
            deleted: self.deleted,
            omitted_earlier: self.omitted_earlier,
        })
    }
    fn first_index(&self) -> u64 {
        self.rows.first().map_or(self.next_index, |row| row.index)
    }

    /// Replaces the history with what a verified snapshot carries; pending commands stay.
    pub fn restore(&mut self, snapshot: &CloudSnapshotPayload<'_>) {
        let pending = std::mem::take(&mut self.pending);
        let next_index = self.next_index;
        *self = Self::new();
        self.next_index = next_index;
        self.pending = pending;
        self.omitted_earlier = snapshot.omitted_earlier;
        for event in &snapshot.events {
            self.apply(event);
        }
        self.control_revision = self.control_revision.max(snapshot.control_revision);
        self.dirty = Dirty::everything();
    }
    /// Applies one verified event.
    pub fn apply(&mut self, event: &CloudEvent<'_>) {
        if event.control_revision > self.control_revision {
            self.control_revision = event.control_revision;
            self.dirty.flags = true;
        }
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
                self.dirty.runs = true;
                self.accepted(&command.id);
                self.push(Role::User, Some(*run), text, at, None).images = images;
            }
            CloudEventPayload::Status { run, status } => self.run_change(run, |state| {
                state.status = *status;
            }),
            CloudEventPayload::Text {
                run,
                step,
                channel,
                text,
            } => self.text(*run, *step, *channel, text, at),
            CloudEventPayload::Usage { run, usage } => self.run_change(run, |state| {
                add_usage(&mut state.usage, usage);
            }),
            CloudEventPayload::ToolIntent(intent) => self.tool(intent, ToolStatus::Running, at),
            CloudEventPayload::Approval {
                intent,
                expires_at_ms,
            } => self.approval_requested(intent, *expires_at_ms, at),
            CloudEventPayload::ApprovalResolved { command, answer } => {
                self.accepted(command);
                self.approvals
                    .retain(|request| request.intent != answer.intent);
                self.dirty.approvals = true;
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
            CloudEventPayload::Deleted { command } => {
                self.accepted(command);
                self.deleted = true;
                self.dirty.flags = true;
            }
            CloudEventPayload::CommandAccepted { command, .. } => self.accepted(&command.id),
            CloudEventPayload::AuthenticationRequested(request) => {
                let binding = &request.binding;
                let status = SessionStatus::AwaitingConsent {
                    expires_at_ms: binding.expires_ms,
                };
                let call = session_call(
                    binding.attempt,
                    &binding.access,
                    true,
                    Some(request.startup),
                );
                self.session(binding.run, call, status, at);
            }
            CloudEventPayload::SessionState(state) => {
                let binding = &state.binding;
                let status = match &state.outcome {
                    SessionOutcome::Established(_) => SessionStatus::Established,
                    SessionOutcome::Lost { reason, .. } => SessionStatus::Lost(*reason),
                    SessionOutcome::Refused(reason) => SessionStatus::Refused(*reason),
                };
                let ssh = self.session_is_ssh(&binding.attempt);
                let call = session_call(binding.attempt, &binding.access, ssh, None);
                self.session(binding.run, call, status, at);
            }
        }
    }

    fn accepted(&mut self, command: &[u8; 16]) {
        self.set_command_state(command, CommandState::Accepted);
    }
    fn run_change(&mut self, run: &RunCoordinate, change: impl FnOnce(&mut RunState)) {
        if let Some(state) = self.runs.iter_mut().find(|state| &state.run == run) {
            change(state);
            self.dirty.runs = true;
        }
    }
    fn push(
        &mut self,
        role: Role,
        run: Option<RunCoordinate>,
        text: String,
        at: u64,
        step: Option<[u8; 16]>,
    ) -> &mut TranscriptRow {
        if self.rows.len() == MAX_TRANSCRIPT_ROWS {
            self.rows.remove(0);
            self.omitted_earlier = true;
            self.dirty.flags = true;
        }
        let index = self.next_index;
        self.next_index += 1;
        self.dirty.row(index);
        self.rows.push(TranscriptRow {
            index,
            role,
            run,
            text,
            images: 0,
            tool: None,
            session: None,
            at_ms: at,
            updated_at_ms: at,
            step,
        });
        let last = self.rows.len() - 1;
        &mut self.rows[last]
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
            let index = last.index;
            self.dirty.row(index);
            return;
        }
        self.push(role, Some(run), text.to_owned(), at, step);
    }
    fn approval_requested(&mut self, intent: &ToolIntentPayload<'_>, expires_at_ms: u64, at: u64) {
        self.tool(intent, ToolStatus::AwaitingApproval { expires_at_ms }, at);
        self.approvals.retain(|request| request.intent != intent.id);
        if self.approvals.len() == MAX_TRANSCRIPT_ROWS {
            self.approvals.remove(0);
        }
        self.approvals.push(ApprovalRequest {
            intent: intent.id,
            arguments_digest: intent.arguments_digest,
            execution: intent.execution.clone(),
            expires_at_ms,
        });
        self.dirty.approvals = true;
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
        let row = self.push(
            Role::Tool,
            Some(intent.execution.run),
            String::new(),
            at,
            Some(intent.step),
        );
        row.tool = Some(ToolCall {
            intent: intent.id,
            tool: display.tool.to_owned(),
            arguments_json: display.arguments_json.to_owned(),
            destination: display.destination.map(str::to_owned),
            mutates: intent.mutates,
            redacted: display.redacted,
            status,
            output_json: None,
            outcome,
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
        let index = row.index;
        self.dirty.row(index);
        true
    }
    fn session_is_ssh(&self, attempt: &[u8; 16]) -> bool {
        self.rows
            .iter()
            .filter_map(|row| row.session.as_ref())
            .any(|call| &call.attempt == attempt && call.ssh)
    }
    /// Updates the row of a session attempt, or adds one.
    fn session(&mut self, run: RunCoordinate, call: SessionCall, status: SessionStatus, at: u64) {
        let known = self.rows.iter_mut().rev().find(|row| {
            row.session
                .as_ref()
                .is_some_and(|known| known.attempt == call.attempt)
        });
        if let Some(row) = known {
            if let Some(known) = row.session.as_mut() {
                known.status = status;
            }
            row.updated_at_ms = at;
            let index = row.index;
            self.dirty.row(index);
            return;
        }
        let row = self.push(Role::Session, Some(run), String::new(), at, None);
        row.session = Some(SessionCall { status, ..call });
    }
}

fn session_call(
    attempt: [u8; 16],
    access: &TargetAccess,
    ssh: bool,
    startup: Option<SessionStartup>,
) -> SessionCall {
    SessionCall {
        attempt,
        principal: access.target.principal.as_str().to_owned(),
        host_key: access.target.host_key,
        ssh,
        terminal: startup.map(|startup| startup == SessionStartup::Terminal),
        status: SessionStatus::Established,
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
