//! The canonical bytes of a transcript inside a device checkpoint (reducer version
//! [`super::REDUCER_VERSION`]). Device-local and sealed; pending commands are not part of it.
//! Version 2 appends the chat's SSH bindings and open requests after the flags.
//!
//! Integers are big-endian, texts and lists carry a u32 length, options a 0/1 tag.
use super::{
    ApprovalRequest, RunState, SessionCall, SessionStatus, ToolCall, ToolStatus, Transcript,
    TranscriptRow, delta::Dirty, types::Role,
};
use crate::CloudDeviceError;
use nocterm_hub_model::cloud::{
    CloudTextId, RunCoordinate,
    events::{CloudRunStatus, CloudUsage},
    payload::{
        AuthenticationSelection, ExecutionReference, GrantReference, ModelSelection,
        SessionFailure, SessionReference, TargetAccess, TargetSelection,
    },
};

const MAX_LIST: usize = super::MAX_TRANSCRIPT_ROWS;

pub(crate) struct Writer(pub(crate) Vec<u8>);
impl Writer {
    pub(crate) fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }
    pub(crate) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub(crate) fn i64(&mut self, value: i64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    pub(crate) fn len(&mut self, length: usize) -> Result<(), CloudDeviceError> {
        self.u32(u32::try_from(length).map_err(|_| CloudDeviceError::Capacity)?);
        Ok(())
    }
    pub(crate) fn text(&mut self, value: &str) -> Result<(), CloudDeviceError> {
        self.len(value.len())?;
        self.bytes(value.as_bytes());
        Ok(())
    }
    pub(crate) fn optional<T>(
        &mut self,
        value: Option<&T>,
        write: impl FnOnce(&mut Self, &T) -> Result<(), CloudDeviceError>,
    ) -> Result<(), CloudDeviceError> {
        self.bool(value.is_some());
        value.map_or(Ok(()), |value| write(self, value))
    }
    fn run(&mut self, run: &RunCoordinate) {
        self.bytes(&run.id);
        self.u64(run.expected_epoch);
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);
impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], CloudDeviceError> {
        let (value, rest) = self
            .0
            .split_at_checked(count)
            .ok_or(CloudDeviceError::Checkpoint)?;
        self.0 = rest;
        Ok(value)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], CloudDeviceError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CloudDeviceError::Checkpoint)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, CloudDeviceError> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn bool(&mut self) -> Result<bool, CloudDeviceError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CloudDeviceError::Checkpoint),
        }
    }
    pub(crate) fn u32(&mut self) -> Result<u32, CloudDeviceError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, CloudDeviceError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(crate) fn i64(&mut self) -> Result<i64, CloudDeviceError> {
        Ok(i64::from_be_bytes(self.array()?))
    }
    pub(crate) fn len(&mut self, max: usize) -> Result<usize, CloudDeviceError> {
        let length = usize::try_from(self.u32()?).map_err(|_| CloudDeviceError::Checkpoint)?;
        if length > max || length > self.0.len() {
            return Err(CloudDeviceError::Checkpoint);
        }
        Ok(length)
    }
    pub(crate) fn text(&mut self) -> Result<String, CloudDeviceError> {
        let length = self.len(usize::MAX)?;
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| CloudDeviceError::Checkpoint)
    }
    pub(crate) fn optional<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, CloudDeviceError>,
    ) -> Result<Option<T>, CloudDeviceError> {
        if self.bool()? {
            read(self).map(Some)
        } else {
            Ok(None)
        }
    }
    pub(crate) fn finish(&self) -> Result<(), CloudDeviceError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(CloudDeviceError::Checkpoint)
        }
    }
    fn run(&mut self) -> Result<RunCoordinate, CloudDeviceError> {
        Ok(RunCoordinate {
            id: self.array()?,
            expected_epoch: self.u64()?,
        })
    }
    fn id(&mut self) -> Result<CloudTextId, CloudDeviceError> {
        CloudTextId::new(&self.text()?).map_err(|_| CloudDeviceError::Checkpoint)
    }
}

impl Transcript {
    pub(crate) fn encode(&self, out: &mut Writer) -> Result<(), CloudDeviceError> {
        out.len(self.rows.len())?;
        for row in &self.rows {
            row_out(out, row)?;
        }
        out.len(self.runs.len())?;
        for run in &self.runs {
            run_out(out, run)?;
        }
        out.len(self.approvals.len())?;
        for approval in &self.approvals {
            approval_out(out, approval)?;
        }
        out.u64(self.next_index);
        out.u64(self.control_revision);
        out.bool(self.deleted);
        out.bool(self.omitted_earlier);
        self.ssh.encode(out)
    }
    pub(crate) fn decode(input: &mut Reader<'_>) -> Result<Self, CloudDeviceError> {
        let mut rows = Vec::new();
        for _ in 0..input.len(MAX_LIST)? {
            rows.push(row_in(input)?);
        }
        let mut runs = Vec::new();
        for _ in 0..input.len(MAX_LIST)? {
            runs.push(run_in(input)?);
        }
        let mut approvals = Vec::new();
        for _ in 0..input.len(MAX_LIST)? {
            approvals.push(approval_in(input)?);
        }
        let transcript = Self {
            rows,
            runs,
            approvals,
            pending: Vec::new(),
            next_index: input.u64()?,
            control_revision: input.u64()?,
            deleted: input.bool()?,
            omitted_earlier: input.bool()?,
            ssh: super::ChatSsh::decode(input)?,
            dirty: Dirty::everything(),
        };
        let ordered = transcript
            .rows
            .windows(2)
            .all(|pair| pair[0].index < pair[1].index);
        if !ordered
            || transcript
                .rows
                .last()
                .is_some_and(|row| row.index >= transcript.next_index)
        {
            return Err(CloudDeviceError::Checkpoint);
        }
        Ok(transcript)
    }
}

fn row_out(out: &mut Writer, row: &TranscriptRow) -> Result<(), CloudDeviceError> {
    out.u64(row.index);
    out.u8(match row.role {
        Role::User => 1,
        Role::Assistant => 2,
        Role::Thought => 3,
        Role::Tool => 4,
        Role::Session => 5,
    });
    out.optional(row.run.as_ref(), |out, run| {
        out.run(run);
        Ok(())
    })?;
    out.text(&row.text)?;
    out.u32(row.images);
    out.optional(row.tool.as_ref(), tool_out)?;
    out.optional(row.session.as_ref(), session_out)?;
    out.u64(row.at_ms);
    out.u64(row.updated_at_ms);
    out.optional(row.step.as_ref(), |out, step| {
        out.bytes(step);
        Ok(())
    })
}
fn row_in(input: &mut Reader<'_>) -> Result<TranscriptRow, CloudDeviceError> {
    let index = input.u64()?;
    let role = match input.u8()? {
        1 => Role::User,
        2 => Role::Assistant,
        3 => Role::Thought,
        4 => Role::Tool,
        5 => Role::Session,
        _ => return Err(CloudDeviceError::Checkpoint),
    };
    Ok(TranscriptRow {
        index,
        role,
        run: input.optional(Reader::run)?,
        text: input.text()?,
        images: input.u32()?,
        tool: input.optional(tool_in)?,
        session: input.optional(session_in)?,
        at_ms: input.u64()?,
        updated_at_ms: input.u64()?,
        step: input.optional(Reader::array)?,
    })
}

fn tool_out(out: &mut Writer, call: &ToolCall) -> Result<(), CloudDeviceError> {
    out.bytes(&call.intent);
    out.text(&call.tool)?;
    out.text(&call.arguments_json)?;
    out.optional(call.destination.as_ref(), |out, text| out.text(text))?;
    out.bool(call.mutates);
    out.bool(call.redacted);
    let (tag, expires) = match call.status {
        ToolStatus::Running => (1, None),
        ToolStatus::AwaitingApproval { expires_at_ms } => (2, Some(expires_at_ms)),
        ToolStatus::Approved => (3, None),
        ToolStatus::Denied => (4, None),
        ToolStatus::Succeeded => (5, None),
        ToolStatus::Failed => (6, None),
        ToolStatus::Unknown => (7, None),
        ToolStatus::Background => (8, None),
    };
    out.u8(tag);
    if let Some(expires) = expires {
        out.u64(expires);
    }
    out.optional(call.output_json.as_ref(), |out, text| out.text(text))?;
    out.optional(call.outcome.as_ref(), |out, text| out.text(text))
}
fn tool_in(input: &mut Reader<'_>) -> Result<ToolCall, CloudDeviceError> {
    let intent = input.array()?;
    let tool = input.text()?;
    let arguments_json = input.text()?;
    let destination = input.optional(Reader::text)?;
    let mutates = input.bool()?;
    let redacted = input.bool()?;
    let status = match input.u8()? {
        1 => ToolStatus::Running,
        2 => ToolStatus::AwaitingApproval {
            expires_at_ms: input.u64()?,
        },
        3 => ToolStatus::Approved,
        4 => ToolStatus::Denied,
        5 => ToolStatus::Succeeded,
        6 => ToolStatus::Failed,
        7 => ToolStatus::Unknown,
        8 => ToolStatus::Background,
        _ => return Err(CloudDeviceError::Checkpoint),
    };
    Ok(ToolCall {
        intent,
        tool,
        arguments_json,
        destination,
        mutates,
        redacted,
        status,
        output_json: input.optional(Reader::text)?,
        outcome: input.optional(Reader::text)?,
    })
}

fn session_out(out: &mut Writer, call: &SessionCall) -> Result<(), CloudDeviceError> {
    out.bytes(&call.attempt);
    out.text(&call.principal)?;
    out.bytes(&call.host_key);
    out.bool(call.ssh);
    out.u8(match call.terminal {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
    match call.status {
        SessionStatus::AwaitingConsent { expires_at_ms } => {
            out.u8(1);
            out.u64(expires_at_ms);
        }
        SessionStatus::Established => out.u8(2),
        SessionStatus::Lost(reason) => {
            out.u8(3);
            out.u8(reason as u8);
        }
        SessionStatus::Refused(reason) => {
            out.u8(4);
            out.u8(reason as u8);
        }
    }
    Ok(())
}
fn session_in(input: &mut Reader<'_>) -> Result<SessionCall, CloudDeviceError> {
    let attempt = input.array()?;
    let principal = input.text()?;
    let host_key = input.array()?;
    let ssh = input.bool()?;
    let terminal = match input.u8()? {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        _ => return Err(CloudDeviceError::Checkpoint),
    };
    let status = match input.u8()? {
        1 => SessionStatus::AwaitingConsent {
            expires_at_ms: input.u64()?,
        },
        2 => SessionStatus::Established,
        3 => SessionStatus::Lost(failure(input.u8()?)?),
        4 => SessionStatus::Refused(failure(input.u8()?)?),
        _ => return Err(CloudDeviceError::Checkpoint),
    };
    Ok(SessionCall {
        attempt,
        principal,
        host_key,
        ssh,
        terminal,
        status,
    })
}
fn failure(tag: u8) -> Result<SessionFailure, CloudDeviceError> {
    use SessionFailure as F;
    [
        F::Denied,
        F::Expired,
        F::Cancelled,
        F::SourceChanged,
        F::Unavailable,
        F::Unsupported,
        F::Capacity,
        F::ConnectionLost,
    ]
    .into_iter()
    .find(|reason| *reason as u8 == tag)
    .ok_or(CloudDeviceError::Checkpoint)
}

fn run_out(out: &mut Writer, state: &RunState) -> Result<(), CloudDeviceError> {
    out.run(&state.run);
    out.u8(state.status as u8);
    let usage = &state.usage;
    for value in [
        usage.input_tokens,
        usage.output_tokens,
        usage.total_tokens,
        usage.cached_input_tokens,
        usage.thought_tokens,
        usage.cost_micros,
    ] {
        out.optional(value.as_ref(), |out, value| {
            out.u64(*value);
            Ok(())
        })?;
    }
    for text in [
        &state.model.provider,
        &state.model.model,
        &state.model.pricing_policy,
    ] {
        out.text(text.as_str())?;
    }
    out.text(&state.issuer_device)?;
    out.bytes(&state.issuer_key);
    out.bytes(&state.prompt_command);
    Ok(())
}
fn run_in(input: &mut Reader<'_>) -> Result<RunState, CloudDeviceError> {
    use CloudRunStatus as S;
    let run = input.run()?;
    let tag = input.u8()?;
    let status = [
        S::Queued,
        S::Running,
        S::WaitingApproval,
        S::NeedsGrant,
        S::NeedsUnlock,
        S::NeedsProviderAccess,
        S::OutcomeUnknown,
        S::Interrupted,
        S::Stopped,
        S::Completed,
    ]
    .into_iter()
    .find(|status| *status as u8 == tag)
    .ok_or(CloudDeviceError::Checkpoint)?;
    let mut counts = [None; 6];
    for count in &mut counts {
        *count = input.optional(Reader::u64)?;
    }
    let [
        input_tokens,
        output_tokens,
        total_tokens,
        cached,
        thought,
        cost,
    ] = counts;
    Ok(RunState {
        run,
        status,
        usage: CloudUsage {
            input_tokens,
            output_tokens,
            total_tokens,
            cached_input_tokens: cached,
            thought_tokens: thought,
            cost_micros: cost,
        },
        model: ModelSelection {
            provider: input.id()?,
            model: input.id()?,
            pricing_policy: input.id()?,
        },
        issuer_device: input.text()?,
        issuer_key: input.array()?,
        prompt_command: input.array()?,
    })
}

fn approval_out(out: &mut Writer, request: &ApprovalRequest) -> Result<(), CloudDeviceError> {
    out.bytes(&request.intent);
    out.bytes(&request.arguments_digest);
    let execution = &request.execution;
    out.run(&execution.run);
    let session = &execution.session;
    out.bytes(&session.id);
    out.u64(session.epoch);
    let target = &session.access.target;
    out.bytes(&target.host_key);
    out.bytes(&target.route);
    out.text(target.principal.as_str())?;
    out.bytes(&target.workspace);
    out.bytes(&session.access.authentication.public_key);
    out.bytes(&session.access.authentication.credential_revision);
    out.bytes(&execution.grant.id);
    out.u64(execution.grant.epoch);
    out.u64(request.expires_at_ms);
    Ok(())
}
fn approval_in(input: &mut Reader<'_>) -> Result<ApprovalRequest, CloudDeviceError> {
    let intent = input.array()?;
    let arguments_digest = input.array()?;
    let run = input.run()?;
    let session = SessionReference {
        id: input.array()?,
        epoch: input.u64()?,
        access: TargetAccess {
            target: TargetSelection {
                host_key: input.array()?,
                route: input.array()?,
                principal: input.id()?,
                workspace: input.array()?,
            },
            authentication: AuthenticationSelection {
                public_key: input.array()?,
                credential_revision: input.array()?,
            },
        },
    };
    let grant = GrantReference {
        id: input.array()?,
        epoch: input.u64()?,
    };
    Ok(ApprovalRequest {
        intent,
        arguments_digest,
        execution: ExecutionReference {
            run,
            session,
            grant,
        },
        expires_at_ms: input.u64()?,
    })
}
