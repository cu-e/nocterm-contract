//! Borrowed inverse of the sole event/snapshot format, with closed tags and EOF.
use super::{
    AcceptedCommand, AcceptedPrompt, BackgroundJob, BackgroundLifecyclePayload, BackgroundOutcome,
    CloudEvent, CloudEventPayload, CloudRunStatus, CloudSnapshotPayload, CloudTextChannel,
    CloudUsage, DisplayOutcome, EventPayloadError, JobWindow, MAX_EVENT_JSON_BYTES,
    MAX_EVENT_TEXT_BYTES, MAX_SNAPSHOT_EVENTS, ObservedEffect, ToolIntentPayload,
    ToolObservationPayload, ToolPresentation, validate_timestamp,
};
use crate::cloud::{
    CloudTextId, CommandIssuer, CommandKind, RunCoordinate,
    payload::reader::PayloadReader,
    tool_arguments::{MAX_TOOL_ARGUMENT_BYTES, ToolArguments},
};

pub(super) fn read_event(bytes: &[u8]) -> Result<CloudEvent<'_>, EventPayloadError> {
    let mut input = EventReader(PayloadReader::new(bytes)?);
    let value = input.event()?;
    input.0.finish()?;
    value.validate()?;
    Ok(value)
}
pub(super) fn read_snapshot(bytes: &[u8]) -> Result<CloudSnapshotPayload<'_>, EventPayloadError> {
    let mut input = EventReader(PayloadReader::new(bytes)?);
    if input.0.field(64)? != super::writer::SNAPSHOT_LABEL {
        return Err(EventPayloadError::Value);
    }
    let control_revision = u64::from_be_bytes(input.0.array()?);
    let timestamp_ms = input.timestamp()?;
    let omitted_earlier = input.0.present()?;
    let count = usize::try_from(u32::from_be_bytes(input.0.array()?))
        .map_err(|_| EventPayloadError::Bounds)?;
    if count > MAX_SNAPSHOT_EVENTS {
        return Err(EventPayloadError::Bounds);
    }
    let events = (0..count)
        .map(|_| input.event())
        .collect::<Result<Vec<_>, _>>()?;
    input.0.finish()?;
    let snapshot = CloudSnapshotPayload {
        control_revision,
        timestamp_ms,
        omitted_earlier,
        events,
    };
    snapshot.validate()?;
    Ok(snapshot)
}
struct EventReader<'a>(PayloadReader<'a>);
impl<'a> EventReader<'a> {
    fn timestamp(&mut self) -> Result<u64, EventPayloadError> {
        let value = u64::from_be_bytes(self.0.array()?);
        validate_timestamp(value)?;
        Ok(value)
    }
    fn text(&mut self, limit: usize) -> Result<&'a str, EventPayloadError> {
        core::str::from_utf8(self.0.field(limit)?).map_err(|_| EventPayloadError::Value)
    }
    fn run(&mut self) -> Result<RunCoordinate, EventPayloadError> {
        Ok(RunCoordinate {
            id: self.0.array()?,
            expected_epoch: u64::from_be_bytes(self.0.array()?),
        })
    }
    fn optional_run(&mut self) -> Result<Option<RunCoordinate>, EventPayloadError> {
        if self.0.present()? {
            Ok(Some(self.run()?))
        } else {
            Ok(None)
        }
    }
    fn number(&mut self) -> Result<Option<u64>, EventPayloadError> {
        if self.0.present()? {
            Ok(Some(u64::from_be_bytes(self.0.array()?)))
        } else {
            Ok(None)
        }
    }
    fn command(&mut self) -> Result<AcceptedCommand, EventPayloadError> {
        Ok(AcceptedCommand {
            id: self.0.array()?,
            kind: CommandKind::try_from(u16::from_be_bytes(self.0.array()?))?,
            signed_message_digest: self.0.array()?,
            issuer: CommandIssuer {
                device_id: CloudTextId::new(self.text(128)?)?,
                signing_key: self.0.array()?,
                access_token_digest: self.0.array()?,
            },
            expected_control_revision: u64::from_be_bytes(self.0.array()?),
        })
    }
    fn display(&mut self) -> Result<ToolPresentation<'a>, EventPayloadError> {
        let tool = self.text(128)?;
        let arguments_json = self.text(MAX_EVENT_JSON_BYTES)?;
        let destination = if self.0.present()? {
            Some(self.text(1024)?)
        } else {
            None
        };
        let redacted = self.0.present()?;
        let outcome = match self.0.tag()? {
            0 => None,
            1 => Some(DisplayOutcome::Pending),
            2 => Some(DisplayOutcome::Ok(self.text(MAX_EVENT_JSON_BYTES)?)),
            3 => Some(DisplayOutcome::Err(self.text(MAX_EVENT_JSON_BYTES)?)),
            _ => return Err(EventPayloadError::Value),
        };
        Ok(ToolPresentation {
            tool,
            arguments_json,
            destination,
            redacted,
            outcome,
        })
    }
    fn intent(&mut self) -> Result<ToolIntentPayload<'a>, EventPayloadError> {
        Ok(ToolIntentPayload {
            id: self.0.array()?,
            step: self.0.array()?,
            execution: self.0.execution()?,
            arguments_digest: self.0.array()?,
            mutates: self.0.present()?,
            arguments: ToolArguments::from_canonical_bytes(self.0.field(MAX_TOOL_ARGUMENT_BYTES)?)?,
            display: self.display()?,
        })
    }
    fn job(&mut self) -> Result<BackgroundJob<'a>, EventPayloadError> {
        Ok(BackgroundJob {
            intent: self.0.array()?,
            execution: self.0.execution()?,
            terminal: self.text(128)?,
            command: self.text(128)?,
            window: if self.0.present()? {
                Some(JobWindow {
                    created_at_ms: u64::from_be_bytes(self.0.array()?),
                    deadline_ms: u64::from_be_bytes(self.0.array()?),
                })
            } else {
                None
            },
        })
    }
    fn accepted_prompt(&mut self) -> Result<AcceptedPrompt<'a>, EventPayloadError> {
        let (model, target, existing_session) = self.0.prompt_selection()?;
        Ok(AcceptedPrompt {
            model,
            target,
            existing_session,
            content: self.0.prompt_content()?,
        })
    }
    fn background(&mut self) -> Result<BackgroundLifecyclePayload<'a>, EventPayloadError> {
        let job = self.job()?;
        let step = self.0.array()?;
        let arguments_digest = self.0.array()?;
        let mutates = self.0.present()?;
        let dispatch_writer_epoch = u64::from_be_bytes(self.0.array()?);
        let dispatch_revision = u64::from_be_bytes(self.0.array()?);
        let outcome = match self.0.tag()? {
            1 => BackgroundOutcome::Retained,
            2 => BackgroundOutcome::ObservedExit(u32::from_be_bytes(self.0.array()?)),
            3 => BackgroundOutcome::Unknown,
            _ => return Err(EventPayloadError::Value),
        };
        Ok(BackgroundLifecyclePayload {
            job,
            step,
            arguments_digest,
            mutates,
            dispatch_writer_epoch,
            dispatch_revision,
            outcome,
        })
    }
    fn observation(&mut self) -> Result<ToolObservationPayload<'a>, EventPayloadError> {
        let intent = self.0.array()?;
        let output_json = self.text(MAX_EVENT_JSON_BYTES)?;
        let display = self.display()?;
        let effect = match self.0.tag()? {
            1 => ObservedEffect::Observed,
            2 => ObservedEffect::Unknown,
            3 => ObservedEffect::Background(Box::new(self.job()?)),
            _ => return Err(EventPayloadError::Value),
        };
        Ok(ToolObservationPayload {
            intent,
            output_json,
            display,
            effect,
            failed: self.0.present()?,
        })
    }
    fn usage(&mut self) -> Result<CloudUsage, EventPayloadError> {
        Ok(CloudUsage {
            input_tokens: self.number()?,
            output_tokens: self.number()?,
            total_tokens: self.number()?,
            cached_input_tokens: self.number()?,
            thought_tokens: self.number()?,
            cost_micros: self.number()?,
        })
    }
    fn event(&mut self) -> Result<CloudEvent<'a>, EventPayloadError> {
        if self.0.field(64)? != super::writer::EVENT_LABEL {
            return Err(EventPayloadError::Value);
        }
        Ok(CloudEvent {
            control_revision: u64::from_be_bytes(self.0.array()?),
            timestamp_ms: self.timestamp()?,
            payload: self.payload()?,
        })
    }
    fn payload(&mut self) -> Result<CloudEventPayload<'a>, EventPayloadError> {
        Ok(match self.0.tag()? {
            1 => CloudEventPayload::CommandAccepted {
                command: self.command()?,
                run: self.optional_run()?,
            },
            2 => CloudEventPayload::PromptAccepted {
                command: self.command()?,
                run: self.run()?,
                prompt: Box::new(self.accepted_prompt()?),
            },
            3 => CloudEventPayload::Status {
                run: self.run()?,
                status: CloudRunStatus::from_tag(self.0.tag()?).ok_or(EventPayloadError::Value)?,
            },
            4 => CloudEventPayload::Text {
                run: self.run()?,
                step: if self.0.present()? {
                    Some(self.0.array()?)
                } else {
                    None
                },
                channel: CloudTextChannel::from_tag(self.0.tag()?)
                    .ok_or(EventPayloadError::Value)?,
                text: self.text(MAX_EVENT_TEXT_BYTES)?,
            },
            5 => CloudEventPayload::Usage {
                run: self.run()?,
                usage: self.usage()?,
            },
            6 => CloudEventPayload::ToolIntent(Box::new(self.intent()?)),
            7 => CloudEventPayload::Approval {
                intent: Box::new(self.intent()?),
                expires_at_ms: u64::from_be_bytes(self.0.array()?),
            },
            8 => CloudEventPayload::ApprovalResolved {
                command: self.0.array()?,
                answer: Box::new(self.0.approval()?),
            },
            9 => CloudEventPayload::ToolResult {
                run: self.run()?,
                observation: Box::new(self.observation()?),
            },
            10 => CloudEventPayload::Deleted {
                command: self.0.array()?,
            },
            11 => CloudEventPayload::BackgroundLifecycle(Box::new(self.background()?)),
            12 => CloudEventPayload::AuthenticationRequested(Box::new(
                crate::cloud::payload::session_codec::read_request(&mut self.0)?,
            )),
            13 => CloudEventPayload::SessionState(Box::new(
                crate::cloud::payload::session_codec::read_state(&mut self.0)?,
            )),
            _ => return Err(EventPayloadError::Value),
        })
    }
}
