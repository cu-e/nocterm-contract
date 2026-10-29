//! Canonical runner observations and bounded projection snapshots, never authority.
//! Bodies must be opened with the separately pinned runner signature before this
//! codec is used. Replay ordering, known heads, residency and actions belong to
//! consumers. A displayed intent or snapshot never creates a DispatchPermit.
mod reader;
mod values;
mod writer;
use crate::cloud::{RecordContext, RecordError, RecordKind, SignedRecord};
pub use values::*;

fn validate_timestamp(timestamp_ms: u64) -> Result<(), EventPayloadError> {
    if timestamp_ms == 0 || timestamp_ms > MAX_PUBLICATION_TIMESTAMP_MS {
        return Err(EventPayloadError::Timestamp);
    }
    Ok(())
}

/// An original runner publication. Control revision is independent of the
/// journal transaction revision; background observations may leave it unchanged.
/// The injected producer clock supplies publication time once, before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudEvent<'a> {
    pub control_revision: u64,
    pub timestamp_ms: u64,
    pub payload: CloudEventPayload<'a>,
}
impl<'a> CloudEvent<'a> {
    /// Validates with the canonical counter before a consumer reserves its bytes.
    /// No encoded payload buffer is allocated by this pass. JSON validation
    /// may use parser scratch; this is not a general allocation-free guarantee.
    pub fn canonical_len(&self) -> Result<usize, EventPayloadError> {
        let mut counter = writer::EventWriter::counter();
        counter.event(self)?;
        Ok(counter.len())
    }
    /// Encodes into one pre-sized buffer after the caller's admission. A stale
    /// length refuses before growth. Nested arguments write directly into this
    /// buffer; JSON parser scratch is separate from the encoded-buffer bound.
    pub fn canonical_bytes_exact(&self, length: usize) -> Result<Vec<u8>, EventPayloadError> {
        let mut output = writer::EventWriter::exact_buffer(length)?;
        output.event(self)?;
        if output.len() != length {
            return Err(EventPayloadError::Bounds);
        }
        output.finish()
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EventPayloadError> {
        let mut output = writer::EventWriter::buffer();
        output.event(self)?;
        output.finish()
    }
    pub fn validate(&self) -> Result<(), EventPayloadError> {
        writer::EventWriter::counter().event(self)
    }
    pub fn from_canonical_bytes(bytes: &'a [u8]) -> Result<Self, EventPayloadError> {
        reader::read_event(bytes)
    }
    /// Signature validity alone does not establish the independently configured
    /// runner or expected chat. The caller must use the pinned record opener.
    pub fn from_record(record: &SignedRecord<'a>) -> Result<Self, EventPayloadError> {
        if record.header().kind() != RecordKind::Event {
            return Err(EventPayloadError::Kind);
        }
        let body = Self::from_canonical_bytes(record.payload())?;
        body.require_context(record.header().context())?;
        Ok(body)
    }
    pub fn require_context(&self, context: &RecordContext) -> Result<(), EventPayloadError> {
        self.validate()?;
        self.payload.require_context(context)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum CloudEventPayload<'a> {
    CommandAccepted {
        command: AcceptedCommand,
        run: Option<crate::cloud::RunCoordinate>,
    },
    PromptAccepted {
        command: AcceptedCommand,
        run: crate::cloud::RunCoordinate,
        prompt: Box<AcceptedPrompt<'a>>,
    },
    Status {
        run: crate::cloud::RunCoordinate,
        status: CloudRunStatus,
    },
    Text {
        run: crate::cloud::RunCoordinate,
        step: Option<[u8; 16]>,
        channel: CloudTextChannel,
        text: &'a str,
    },
    Usage {
        run: crate::cloud::RunCoordinate,
        usage: CloudUsage,
    },
    ToolIntent(Box<ToolIntentPayload<'a>>),
    Approval {
        intent: Box<ToolIntentPayload<'a>>,
        expires_at_ms: u64,
    },
    ApprovalResolved {
        command: [u8; 16],
        answer: Box<crate::cloud::payload::ApprovalPayload>,
    },
    ToolResult {
        run: crate::cloud::RunCoordinate,
        observation: Box<ToolObservationPayload<'a>>,
    },
    Deleted {
        command: [u8; 16],
    },
    BackgroundLifecycle(Box<BackgroundLifecyclePayload<'a>>),
}
impl CloudEventPayload<'_> {
    pub(super) fn tag(&self) -> u8 {
        match self {
            Self::CommandAccepted { .. } => 1,
            Self::PromptAccepted { .. } => 2,
            Self::Status { .. } => 3,
            Self::Text { .. } => 4,
            Self::Usage { .. } => 5,
            Self::ToolIntent(_) => 6,
            Self::Approval { .. } => 7,
            Self::ApprovalResolved { .. } => 8,
            Self::ToolResult { .. } => 9,
            Self::Deleted { .. } => 10,
            Self::BackgroundLifecycle(_) => 11,
        }
    }

    pub fn validate(&self) -> Result<(), EventPayloadError> {
        writer::EventWriter::counter().payload(self)
    }
    pub fn require_context(&self, context: &RecordContext) -> Result<(), EventPayloadError> {
        let run = match self {
            Self::CommandAccepted { run, .. } => *run,
            Self::PromptAccepted { run, .. }
            | Self::Status { run, .. }
            | Self::Text { run, .. }
            | Self::Usage { run, .. }
            | Self::ToolResult { run, .. } => Some(*run),
            Self::ToolIntent(intent) | Self::Approval { intent, .. } => Some(intent.execution.run),
            Self::ApprovalResolved { answer, .. } => Some(answer.execution.run),
            Self::BackgroundLifecycle(observation) => Some(observation.job.execution.run),
            Self::Deleted { .. } => return self.validate(),
        };
        if run != context.run() {
            return Err(EventPayloadError::Context);
        }
        self.validate()
    }
}

/// A snapshot is a bounded, ordered projection history, not native Postcard or
/// a model checkpoint. The producer coalesces/prunes complete display records;
/// omitted_earlier explicitly records that the retained history is a window.
/// Control and publication times are nondecreasing and bounded by the snapshot
/// head. Historical runs are deliberately independent of its outer current run;
/// a late background observation retains the original run and execution ids.
/// This is display history, not restoration of execution grants or effects.
#[derive(Clone, PartialEq, Eq)]
pub struct CloudSnapshotPayload<'a> {
    /// Current projection/control head, even when no display events remain.
    pub control_revision: u64,
    /// Time this snapshot was originally published, not a restored event time.
    pub timestamp_ms: u64,
    pub omitted_earlier: bool,
    pub events: Vec<CloudEvent<'a>>,
}
impl<'a> CloudSnapshotPayload<'a> {
    /// Counts the same canonical layout without allocating an encoded buffer.
    /// JSON validation may use parser scratch.
    pub fn canonical_len(&self) -> Result<usize, EventPayloadError> {
        let mut counter = writer::EventWriter::counter();
        counter.snapshot(self)?;
        Ok(counter.len())
    }
    /// Uses the admitted exact canonical length, refusing a mismatched preflight.
    pub fn canonical_bytes_exact(&self, length: usize) -> Result<Vec<u8>, EventPayloadError> {
        let mut output = writer::EventWriter::exact_buffer(length)?;
        output.snapshot(self)?;
        if output.len() != length {
            return Err(EventPayloadError::Bounds);
        }
        output.finish()
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EventPayloadError> {
        let mut out = writer::EventWriter::buffer();
        out.snapshot(self)?;
        out.finish()
    }
    pub fn validate(&self) -> Result<(), EventPayloadError> {
        writer::EventWriter::counter().snapshot(self)
    }
    pub fn from_canonical_bytes(bytes: &'a [u8]) -> Result<Self, EventPayloadError> {
        reader::read_snapshot(bytes)
    }
    pub fn from_record(record: &SignedRecord<'a>) -> Result<Self, EventPayloadError> {
        if record.header().kind() != RecordKind::Snapshot {
            return Err(EventPayloadError::Kind);
        }
        Self::from_canonical_bytes(record.payload())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EventPayloadError {
    #[error("Cloud observation publication time is outside the supported epoch range")]
    Timestamp,
    #[error("Cloud snapshot observations exceed or regress its control/time head")]
    SnapshotOrder,
    #[error("Cloud event body contains an unknown or invalid value")]
    Value,
    #[error("Cloud event body exceeds its aggregate or collection bound")]
    Bounds,
    #[error("Cloud event body has another signed purpose")]
    Kind,
    #[error("Cloud event body names another run or context")]
    Context,
    #[error("Cloud event body framing is invalid")]
    Framing(#[from] crate::cloud::CommandError),
    #[error("Cloud event nested payload is invalid")]
    Payload(#[from] crate::cloud::payload::PayloadError),
    #[error("Cloud signed record is invalid")]
    Record(#[from] RecordError),
}

impl core::fmt::Debug for CloudEventPayload<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudEventPayload")
            .field("kind", &self.tag())
            .finish_non_exhaustive()
    }
}
impl core::fmt::Debug for CloudSnapshotPayload<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudSnapshotPayload")
            .field("events", &self.events.len())
            .field("omitted_earlier", &self.omitted_earlier)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
