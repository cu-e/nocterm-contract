//! One aggregate payload sink; existing command sub-layouts are reused directly.
use super::{
    AcceptedCommand, AcceptedPrompt, BackgroundJob, BackgroundLifecyclePayload, BackgroundOutcome,
    CloudEvent, CloudEventPayload, CloudSnapshotPayload, CloudTextChannel, CloudUsage,
    DisplayOutcome, EventPayloadError, MAX_EVENT_JSON_BYTES, MAX_EVENT_TEXT_BYTES,
    MAX_SNAPSHOT_EVENTS, ObservedEffect, ToolIntentPayload, ToolObservationPayload,
    ToolPresentation, validate_timestamp,
};
use crate::cloud::{RunCoordinate, payload::writer::PayloadWriter};
use serde::Deserialize;

pub(super) const EVENT_LABEL: &[u8] = b"nocterm/cloud-event-payload/v1";
pub(super) const SNAPSHOT_LABEL: &[u8] = b"nocterm/cloud-snapshot-payload/v1";
pub(super) struct EventWriter {
    output: PayloadWriter,
}
impl EventWriter {
    pub(super) fn buffer() -> Self {
        Self {
            output: PayloadWriter::new(),
        }
    }
    pub(super) fn counter() -> Self {
        Self {
            output: PayloadWriter::counter(),
        }
    }
    pub(super) fn exact_buffer(length: usize) -> Result<Self, EventPayloadError> {
        Ok(Self {
            output: PayloadWriter::exact_buffer(length)?,
        })
    }
    pub(super) fn len(&self) -> usize {
        self.output.len()
    }
    pub(super) fn finish(self) -> Result<Vec<u8>, EventPayloadError> {
        Ok(self.output.finish()?)
    }
    fn raw(&mut self, value: &[u8]) -> Result<(), EventPayloadError> {
        Ok(self.output.raw(value)?)
    }
    fn tag(&mut self, value: u8) -> Result<(), EventPayloadError> {
        Ok(self.output.tag(value)?)
    }
    fn field(&mut self, value: &[u8]) -> Result<(), EventPayloadError> {
        Ok(self.output.field(value)?)
    }
    fn text(&mut self, value: &str, limit: usize) -> Result<(), EventPayloadError> {
        if value.len() > limit {
            return Err(EventPayloadError::Bounds);
        }
        self.field(value.as_bytes())
    }
    fn json(&mut self, value: &str) -> Result<(), EventPayloadError> {
        if value.len() > MAX_EVENT_JSON_BYTES {
            return Err(EventPayloadError::Bounds);
        }
        let mut parser = serde_json::Deserializer::from_str(value);
        serde::de::IgnoredAny::deserialize(&mut parser).map_err(|_| EventPayloadError::Value)?;
        parser.end().map_err(|_| EventPayloadError::Value)?;
        self.field(value.as_bytes())
    }
    fn run(&mut self, run: RunCoordinate) -> Result<(), EventPayloadError> {
        if run.expected_epoch == 0 {
            return Err(EventPayloadError::Value);
        }
        self.raw(&run.id)?;
        self.raw(&run.expected_epoch.to_be_bytes())
    }
    fn optional_run(&mut self, run: Option<RunCoordinate>) -> Result<(), EventPayloadError> {
        self.tag(u8::from(run.is_some()))?;
        if let Some(run) = run {
            self.run(run)?;
        }
        Ok(())
    }
    fn number(&mut self, value: Option<u64>) -> Result<(), EventPayloadError> {
        self.tag(u8::from(value.is_some()))?;
        if let Some(value) = value {
            self.raw(&value.to_be_bytes())?;
        }
        Ok(())
    }
    fn command(&mut self, value: &AcceptedCommand) -> Result<(), EventPayloadError> {
        self.raw(&value.id)?;
        self.raw(&(value.kind as u16).to_be_bytes())?;
        self.raw(&value.signed_message_digest)?;
        self.field(value.issuer.device_id.as_str().as_bytes())?;
        self.raw(&value.issuer.signing_key)?;
        self.raw(&value.issuer.access_token_digest)?;
        self.raw(&value.expected_control_revision.to_be_bytes())
    }
    fn display(&mut self, value: &ToolPresentation<'_>) -> Result<(), EventPayloadError> {
        if !matches!(
            value.tool,
            "list_terminals"
                | "open_terminal"
                | "read_terminal"
                | "send_input"
                | "run_command"
                | "exec_command"
                | "read_command"
                | "cancel_command"
        ) {
            return Err(EventPayloadError::Value);
        }
        self.text(value.tool, 128)?;
        self.json(value.arguments_json)?;
        self.tag(u8::from(value.destination.is_some()))?;
        if let Some(destination) = value.destination {
            self.text(destination, 1024)?;
        }
        self.tag(u8::from(value.redacted))?;
        match &value.outcome {
            None => self.tag(0),
            Some(DisplayOutcome::Pending) => self.tag(1),
            Some(DisplayOutcome::Ok(json)) => {
                self.tag(2)?;
                self.json(json)
            }
            Some(DisplayOutcome::Err(text)) => {
                self.tag(3)?;
                self.text(text, MAX_EVENT_JSON_BYTES)
            }
        }
    }
    fn intent(&mut self, value: &ToolIntentPayload<'_>) -> Result<(), EventPayloadError> {
        if value.arguments.digest()? != value.arguments_digest
            || value.display.tool != value.arguments.name()
        {
            return Err(EventPayloadError::Value);
        }
        self.raw(&value.id)?;
        self.raw(&value.step)?;
        self.output.execution(&value.execution)?;
        self.raw(&value.arguments_digest)?;
        self.tag(u8::from(value.mutates))?;
        self.output.tool_arguments(&value.arguments)?;
        self.display(&value.display)
    }
    fn job(&mut self, value: &BackgroundJob<'_>) -> Result<(), EventPayloadError> {
        if [&value.terminal, &value.command]
            .iter()
            .any(|v| v.is_empty() || v.len() > 128 || v.contains('\0'))
        {
            return Err(EventPayloadError::Value);
        }
        self.raw(&value.intent)?;
        self.output.execution(&value.execution)?;
        self.text(value.terminal, 128)?;
        self.text(value.command, 128)?;
        self.tag(u8::from(value.window.is_some()))?;
        if let Some(window) = value.window {
            if window.created_at_ms == 0 || window.deadline_ms <= window.created_at_ms {
                return Err(EventPayloadError::Value);
            }
            self.raw(&window.created_at_ms.to_be_bytes())?;
            self.raw(&window.deadline_ms.to_be_bytes())?;
        }
        Ok(())
    }
    fn accepted_prompt(&mut self, value: &AcceptedPrompt<'_>) -> Result<(), EventPayloadError> {
        self.output.prompt_selection(
            &value.model,
            value.target.as_ref(),
            value.existing_session.as_ref(),
        )?;
        Ok(self.output.prompt_content(&value.content)?)
    }
    fn background(
        &mut self,
        value: &BackgroundLifecyclePayload<'_>,
    ) -> Result<(), EventPayloadError> {
        if value.dispatch_writer_epoch == 0 || value.dispatch_revision == 0 {
            return Err(EventPayloadError::Value);
        }
        self.job(&value.job)?;
        self.raw(&value.step)?;
        self.raw(&value.arguments_digest)?;
        self.tag(u8::from(value.mutates))?;
        self.raw(&value.dispatch_writer_epoch.to_be_bytes())?;
        self.raw(&value.dispatch_revision.to_be_bytes())?;
        match value.outcome {
            BackgroundOutcome::Retained => self.tag(1),
            BackgroundOutcome::ObservedExit(status) => {
                self.tag(2)?;
                self.raw(&status.to_be_bytes())
            }
            BackgroundOutcome::Unknown => self.tag(3),
        }
    }
    fn observation(&mut self, value: &ToolObservationPayload<'_>) -> Result<(), EventPayloadError> {
        self.raw(&value.intent)?;
        self.json(value.output_json)?;
        self.display(&value.display)?;
        match &value.effect {
            ObservedEffect::Observed => self.tag(1)?,
            ObservedEffect::Unknown => self.tag(2)?,
            ObservedEffect::Background(job) => {
                if job.intent != value.intent {
                    return Err(EventPayloadError::Context);
                }
                self.tag(3)?;
                self.job(job)?;
            }
        }
        self.tag(u8::from(value.failed))
    }
    fn timestamp(&mut self, timestamp_ms: u64) -> Result<(), EventPayloadError> {
        validate_timestamp(timestamp_ms)?;
        self.raw(&timestamp_ms.to_be_bytes())
    }
    fn text_event(
        &mut self,
        run: RunCoordinate,
        step: Option<[u8; 16]>,
        channel: CloudTextChannel,
        text: &str,
    ) -> Result<(), EventPayloadError> {
        self.run(run)?;
        self.tag(u8::from(step.is_some()))?;
        if let Some(step) = step {
            self.raw(&step)?;
        }
        self.tag(channel as u8)?;
        self.text(text, MAX_EVENT_TEXT_BYTES)
    }
    fn usage_event(
        &mut self,
        run: RunCoordinate,
        usage: CloudUsage,
    ) -> Result<(), EventPayloadError> {
        self.run(run)?;
        for value in [
            usage.input_tokens,
            usage.output_tokens,
            usage.total_tokens,
            usage.cached_input_tokens,
            usage.thought_tokens,
            usage.cost_micros,
        ] {
            self.number(value)?;
        }
        Ok(())
    }
    pub(super) fn event(&mut self, value: &CloudEvent<'_>) -> Result<(), EventPayloadError> {
        self.field(EVENT_LABEL)?;
        self.raw(&value.control_revision.to_be_bytes())?;
        self.timestamp(value.timestamp_ms)?;
        self.payload(&value.payload)
    }
    pub(super) fn payload(
        &mut self,
        value: &CloudEventPayload<'_>,
    ) -> Result<(), EventPayloadError> {
        self.tag(value.tag())?;
        match value {
            CloudEventPayload::CommandAccepted { command, run } => {
                self.command(command)?;
                self.optional_run(*run)
            }
            CloudEventPayload::PromptAccepted {
                command,
                run,
                prompt,
            } => {
                if command.kind != crate::cloud::CommandKind::SubmitPrompt {
                    return Err(EventPayloadError::Kind);
                }
                self.command(command)?;
                self.run(*run)?;
                self.accepted_prompt(prompt)
            }
            CloudEventPayload::Status { run, status } => {
                self.run(*run)?;
                self.tag(*status as u8)
            }
            CloudEventPayload::Text {
                run,
                step,
                channel,
                text,
            } => self.text_event(*run, *step, *channel, text),
            CloudEventPayload::Usage { run, usage } => self.usage_event(*run, *usage),
            CloudEventPayload::ToolIntent(intent) => self.intent(intent),
            CloudEventPayload::Approval {
                intent,
                expires_at_ms,
            } => {
                if *expires_at_ms == 0 {
                    return Err(EventPayloadError::Value);
                }
                self.intent(intent)?;
                self.raw(&expires_at_ms.to_be_bytes())
            }
            CloudEventPayload::ApprovalResolved { command, answer } => {
                self.raw(command)?;
                Ok(self.output.approval(answer)?)
            }
            CloudEventPayload::ToolResult { run, observation } => {
                if matches!(&observation.effect, ObservedEffect::Background(job) if job.execution.run != *run)
                {
                    return Err(EventPayloadError::Context);
                }
                self.run(*run)?;
                self.observation(observation)
            }
            CloudEventPayload::Deleted { command } => self.raw(command),
            CloudEventPayload::BackgroundLifecycle(value) => self.background(value),
            CloudEventPayload::AuthenticationRequested(value) => Ok(
                crate::cloud::payload::session_codec::write_request(&mut self.output, value)?,
            ),
            CloudEventPayload::SessionState(value) => Ok(
                crate::cloud::payload::session_codec::write_state(&mut self.output, value)?,
            ),
        }
    }
    pub(super) fn snapshot(
        &mut self,
        value: &CloudSnapshotPayload<'_>,
    ) -> Result<(), EventPayloadError> {
        if value.events.len() > MAX_SNAPSHOT_EVENTS {
            return Err(EventPayloadError::Bounds);
        }
        self.field(SNAPSHOT_LABEL)?;
        self.raw(&value.control_revision.to_be_bytes())?;
        self.timestamp(value.timestamp_ms)?;
        self.tag(u8::from(value.omitted_earlier))?;
        self.raw(
            &u32::try_from(value.events.len())
                .map_err(|_| EventPayloadError::Bounds)?
                .to_be_bytes(),
        )?;
        let mut previous = (0, 0);
        for event in &value.events {
            if event.control_revision < previous.0
                || event.timestamp_ms < previous.1
                || event.control_revision > value.control_revision
                || event.timestamp_ms > value.timestamp_ms
            {
                return Err(EventPayloadError::SnapshotOrder);
            }
            self.event(event)?;
            previous = (event.control_revision, event.timestamp_ms);
        }
        Ok(())
    }
}
