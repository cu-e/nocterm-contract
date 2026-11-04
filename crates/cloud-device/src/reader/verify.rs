//! The per-record checks of a replay round: publisher, routing, order, integrity, signature
//! and witnessed anchors. The reader owns the position these checks advance.
use super::Position;
use crate::{
    CloudDeviceError,
    records::{ChatSelector, RunnerPins},
    transcript::Transcript,
    trust::HubCapabilities,
};
use nocterm_hub_model::cloud::{
    ChatCoordinate, RecordKind,
    events::{CloudEvent, CloudSnapshotPayload},
    head::HeadRecordAnchor,
    relay::{
        MAX_RELAY_PAGE_RECORDS, PublicationMetadata, PublicationVerifier, RelayBinding, RelayKind,
    },
};
use nocterm_keys::cloud::{ChatKey, open_event, open_snapshot};

/// The publisher the hub reports for a delivered record (`CloudPublicationOrigin`).
#[derive(Clone, Copy, Debug)]
pub struct DeliveredOrigin<'a> {
    pub account_id: &'a str,
    pub signing_key: &'a [u8],
    /// `issuer.runner_id`; `None` when the origin names a device instead.
    pub runner_id: Option<&'a [u8]>,
}

/// One `CloudDeliveredRecord` header frame as plain data.
#[derive(Clone, Copy, Debug)]
pub struct DeliveredRecord<'a> {
    pub publication_id: &'a [u8],
    pub binding: &'a [u8],
    pub total_bytes: u32,
    pub ciphertext_sha256: &'a [u8],
    pub cursor: u64,
    pub origin: DeliveredOrigin<'a>,
}

/// What an accepted record changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedRecord {
    pub cursor: u64,
    pub sequence: u64,
    pub kind: RecordKind,
    /// True when a snapshot replaced the transcript after a gap.
    pub restored: bool,
    /// The record as a head witness names it.
    pub anchor: HeadRecordAnchor,
}

/// Recover from a gap with `Replay(after_cursor, max_records = 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GapRecovery {
    pub after_cursor: u64,
    pub snapshot_publication_id: [u8; 16],
}

/// Who may have published this chat's records.
#[derive(Debug)]
pub(super) struct Origin {
    pub(super) chat: ChatCoordinate,
    account: String,
    pins: RunnerPins,
}
impl Origin {
    pub(super) fn of(selector: &ChatSelector) -> Result<Self, CloudDeviceError> {
        Ok(Self {
            chat: selector.coordinate()?,
            account: selector.scope().account_id().to_owned(),
            pins: selector.pins(),
        })
    }
    fn publisher(&self, origin: DeliveredOrigin<'_>) -> bool {
        origin.account_id == self.account
            && origin.signing_key == self.pins.proof
            && origin.runner_id == Some(self.chat.runner().id.as_slice())
    }
}

/// The hub's verified frame and envelope bounds.
#[derive(Debug)]
pub(super) struct Limits {
    max_frame_bytes: usize,
    max_envelope_bytes: u32,
}
impl Limits {
    pub(super) fn of(capabilities: &HubCapabilities) -> Result<Self, CloudDeviceError> {
        let limits = capabilities.limits();
        Ok(Self {
            max_frame_bytes: usize::try_from(limits.max_frame_bytes)
                .map_err(|_| CloudDeviceError::Capacity)?,
            max_envelope_bytes: limits.max_envelope_bytes,
        })
    }
}

#[derive(Debug)]
pub(super) struct Pending {
    metadata: PublicationMetadata,
    cursor: u64,
    verifier: PublicationVerifier,
    ciphertext: Vec<u8>,
    recovery: bool,
}

#[derive(Debug)]
pub(super) enum State {
    Between,
    /// After a gap: only the named snapshot is accepted.
    AwaitSnapshot([u8; 16]),
    Record(Box<Pending>),
    Failed,
}

pub(super) fn header(
    state: &mut State,
    origin: &Origin,
    limits: &Limits,
    position: &Position,
    writer_cap: Option<u64>,
    page_records: u32,
    header: &DeliveredRecord<'_>,
) -> Result<Pending, CloudDeviceError> {
    let recovery = match std::mem::replace(state, State::Failed) {
        State::Between => None,
        State::AwaitSnapshot(snapshot) => Some(snapshot),
        State::Record(_) | State::Failed => return Err(CloudDeviceError::ReplayOrder),
    };
    if Some(header.cursor) != position.cursor.checked_add(1)
        || page_records >= MAX_RELAY_PAGE_RECORDS
    {
        return Err(CloudDeviceError::ReplayOrder);
    }
    let id: [u8; 16] = header
        .publication_id
        .try_into()
        .map_err(|_| CloudDeviceError::ReplayIntegrity)?;
    let digest: [u8; 32] = header
        .ciphertext_sha256
        .try_into()
        .map_err(|_| CloudDeviceError::ReplayIntegrity)?;
    let binding = RelayBinding::from_canonical_bytes(header.binding)?;
    let context = binding
        .record_context()
        .ok_or(CloudDeviceError::ReplaySource)?;
    if context.chat() != &origin.chat || !origin.publisher(header.origin) {
        return Err(CloudDeviceError::ReplaySource);
    }
    if header.total_bytes > limits.max_envelope_bytes {
        return Err(CloudDeviceError::Capacity);
    }
    let record = context.position();
    if writer_cap.is_some_and(|writer| record.writer_epoch > writer)
        || record.writer_epoch < position.writer
    {
        return Err(CloudDeviceError::ReplaySource);
    }
    match recovery {
        Some(snapshot) => {
            if id != snapshot
                || binding.kind() != RelayKind::Snapshot
                || record.sequence <= position.sequence
            {
                return Err(CloudDeviceError::SnapshotRequired);
            }
        }
        None if Some(record.sequence) != position.sequence.checked_add(1) => {
            return Err(CloudDeviceError::ReplayOrder);
        }
        None => {}
    }
    let metadata = PublicationMetadata::new(id, binding, header.total_bytes, digest)?;
    let capacity = usize::try_from(header.total_bytes).map_err(|_| CloudDeviceError::Capacity)?;
    Ok(Pending {
        verifier: PublicationVerifier::new(metadata.clone()),
        metadata,
        cursor: header.cursor,
        ciphertext: Vec::with_capacity(capacity),
        recovery: recovery.is_some(),
    })
}

pub(super) fn data(
    state: &mut State,
    limits: &Limits,
    bytes: &[u8],
) -> Result<(), CloudDeviceError> {
    let State::Record(pending) = state else {
        *state = State::Failed;
        return Err(CloudDeviceError::ReplayOrder);
    };
    if bytes.len() > limits.max_frame_bytes || pending.verifier.chunk(bytes).is_err() {
        *state = State::Failed;
        return Err(CloudDeviceError::ReplayIntegrity);
    }
    pending.ciphertext.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn end(
    state: &mut State,
    origin: &Origin,
    witnessed: &[Option<HeadRecordAnchor>; 2],
    publication_id: &[u8],
    key: &ChatKey,
    transcript: &mut Transcript,
) -> Result<AcceptedRecord, CloudDeviceError> {
    let State::Record(pending) = std::mem::replace(state, State::Failed) else {
        return Err(CloudDeviceError::ReplayOrder);
    };
    let Pending {
        metadata,
        cursor,
        mut verifier,
        ciphertext,
        recovery,
    } = *pending;
    if publication_id != metadata.id() {
        return Err(CloudDeviceError::ReplayOrder);
    }
    verifier
        .finish_marker()
        .map_err(|_| CloudDeviceError::ReplayIntegrity)?;
    let binding = metadata.binding();
    let context = binding
        .record_context()
        .ok_or(CloudDeviceError::ReplaySource)?;
    let kind = match binding.kind() {
        RelayKind::Event => RecordKind::Event,
        RelayKind::Snapshot => RecordKind::Snapshot,
        RelayKind::Command | RelayKind::ChatKeyGrant | RelayKind::Summary => {
            return Err(CloudDeviceError::ReplaySource);
        }
    };
    let anchor = HeadRecordAnchor {
        kind,
        position: context.position(),
        id: context.id(),
        run: context.run(),
        ciphertext_digest: metadata.digest(),
    };
    for seen in witnessed.iter().flatten() {
        if seen.position.sequence == anchor.position.sequence && seen != &anchor {
            return Err(CloudDeviceError::Withheld);
        }
    }
    let opened = match kind {
        RecordKind::Event => open_event(key, &origin.pins.signing, context, &ciphertext)?,
        RecordKind::Snapshot => open_snapshot(key, &origin.pins.signing, context, &ciphertext)?,
    };
    let record = opened.record()?;
    match kind {
        RecordKind::Event => transcript.apply(&CloudEvent::from_record(&record)?),
        RecordKind::Snapshot => {
            let snapshot = CloudSnapshotPayload::from_record(&record)?;
            if recovery {
                transcript.restore(&snapshot);
            }
        }
    }
    Ok(AcceptedRecord {
        cursor,
        sequence: anchor.position.sequence,
        kind,
        restored: recovery,
        anchor,
    })
}

pub(super) fn gap(
    state: &mut State,
    cursor: &mut u64,
    records: u32,
    retained_from: u64,
    snapshot_publication_id: &[u8],
) -> Result<GapRecovery, CloudDeviceError> {
    let after = retained_from.checked_sub(1);
    if !matches!(state, State::Between)
        || records != 0
        || after.is_none_or(|after| after <= *cursor)
    {
        *state = State::Failed;
        return Err(CloudDeviceError::ReplayOrder);
    }
    let Ok(snapshot) = <[u8; 16]>::try_from(snapshot_publication_id) else {
        *state = State::Failed;
        return Err(CloudDeviceError::SnapshotRequired);
    };
    let after_cursor = after.ok_or(CloudDeviceError::ReplayOrder)?;
    *state = State::AwaitSnapshot(snapshot);
    *cursor = after_cursor;
    Ok(GapRecovery {
        after_cursor,
        snapshot_publication_id: snapshot,
    })
}
