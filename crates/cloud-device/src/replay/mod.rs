//! Verification of one chat's `CloudService.Replay` frames, one frame at a time.
//!
//! The caller first obtains a fresh chat head witness ([`crate::probe`]), then replays with
//! `after_cursor = ` [`ChatReplay::cursor`] and passes every frame here in arrival order:
//! [`ChatReplay::record_header`], [`ChatReplay::record_data`] for each data frame,
//! [`ChatReplay::record_end`], then [`ChatReplay::page_end`] or [`ChatReplay::gap`].
//! A record is accepted only when:
//! - its transport cursor is the next one and the hub names the pinned runner (account, runner
//!   id and proof key) as its publisher;
//! - its routing names this chat generation, its sequence is the next one and its writer is not
//!   newer than the witnessed current writer;
//! - its ciphertext has the announced length and digest, opens under the chat key and carries
//!   the pinned runner's signature over exactly that context;
//! - where it reaches the witnessed head or snapshot position, it is that witnessed record.
//!
//! A page that ends without more records before the witnessed head is refused
//! ([`CloudDeviceError::Withheld`]): the hub cannot hide the newest history from a fresh read.
//! The browser never acknowledges; this verifier keeps no acknowledgement state.
use crate::{
    CloudDeviceError,
    records::{ChatSelector, RunnerPins},
    transcript::Transcript,
    trust::HubCapabilities,
};
use nocterm_hub_model::cloud::{
    ChatCoordinate, RecordKind,
    events::{CloudEvent, CloudSnapshotPayload},
    head::{ChatHead, HeadRecordAnchor},
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedRecord {
    pub cursor: u64,
    pub sequence: u64,
    pub kind: RecordKind,
    /// True when a snapshot replaced the transcript after a gap.
    pub restored: bool,
}

/// How a page ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageEnd {
    /// Replay again from [`ChatReplay::cursor`].
    More,
    /// The replay reached at least the witnessed head.
    Complete,
}

/// Recover from a gap with `Replay(after_cursor, max_records = 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GapRecovery {
    pub after_cursor: u64,
    pub snapshot_publication_id: [u8; 16],
}

#[derive(Debug)]
struct Pending {
    metadata: PublicationMetadata,
    cursor: u64,
    verifier: PublicationVerifier,
    ciphertext: Vec<u8>,
    recovery: bool,
}

#[derive(Debug)]
enum State {
    Between,
    AwaitSnapshot([u8; 16]),
    Record(Box<Pending>),
    Failed,
}

/// The replay of one chat generation against its fresh head.
#[derive(Debug)]
pub struct ChatReplay {
    chat: ChatCoordinate,
    account: String,
    pins: RunnerPins,
    head: ChatHead,
    max_frame_bytes: usize,
    max_envelope_bytes: u32,
    cursor: u64,
    sequence: u64,
    page_records: u32,
    reached_head: bool,
    state: State,
}
impl ChatReplay {
    /// Starts at cursor 0 for `selector`, whose generation `head` (a fresh witness) must name.
    pub fn new(
        selector: &ChatSelector,
        head: ChatHead,
        capabilities: &HubCapabilities,
    ) -> Result<Self, CloudDeviceError> {
        capabilities.require_reading()?;
        if head.chat_id != selector.chat_id() || head.chat_key_epoch != selector.key_epoch() {
            return Err(CloudDeviceError::Withheld);
        }
        let limits = capabilities.limits();
        Ok(Self {
            chat: selector.coordinate()?,
            account: selector.scope().account_id().to_owned(),
            pins: selector.pins(),
            reached_head: head.head.is_none(),
            head,
            max_frame_bytes: usize::try_from(limits.max_frame_bytes)
                .map_err(|_| CloudDeviceError::Capacity)?,
            max_envelope_bytes: limits.max_envelope_bytes,
            cursor: 0,
            sequence: 0,
            page_records: 0,
            state: State::Between,
        })
    }
    /// The `after_cursor` of the next `Replay` request.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    /// The last accepted event sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// The witnessed head this replay must reach.
    pub fn head(&self) -> &ChatHead {
        &self.head
    }
    /// The most records one page may ask for.
    pub fn max_page_records() -> u32 {
        MAX_RELAY_PAGE_RECORDS
    }
    /// A header frame. Any refusal fails this replay; start a new one.
    pub fn record_header(&mut self, header: &DeliveredRecord<'_>) -> Result<(), CloudDeviceError> {
        let recovery = match std::mem::replace(&mut self.state, State::Failed) {
            State::Between => None,
            State::AwaitSnapshot(id) => Some(id),
            State::Record(_) | State::Failed => return Err(CloudDeviceError::ReplayOrder),
        };
        if Some(header.cursor) != self.cursor.checked_add(1)
            || self.page_records >= MAX_RELAY_PAGE_RECORDS
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
        if context.chat() != &self.chat || !self.publisher(header.origin) {
            return Err(CloudDeviceError::ReplaySource);
        }
        if header.total_bytes > self.max_envelope_bytes {
            return Err(CloudDeviceError::Capacity);
        }
        let position = context.position();
        if self
            .head
            .current_writer
            .is_some_and(|writer| position.writer_epoch > writer)
        {
            return Err(CloudDeviceError::ReplaySource);
        }
        match recovery {
            Some(snapshot) => {
                if id != snapshot
                    || binding.kind() != RelayKind::Snapshot
                    || position.sequence <= self.sequence
                {
                    return Err(CloudDeviceError::SnapshotRequired);
                }
            }
            None if Some(position.sequence) != self.sequence.checked_add(1) => {
                return Err(CloudDeviceError::ReplayOrder);
            }
            None => {}
        }
        let metadata = PublicationMetadata::new(id, binding, header.total_bytes, digest)?;
        let capacity =
            usize::try_from(header.total_bytes).map_err(|_| CloudDeviceError::Capacity)?;
        self.state = State::Record(Box::new(Pending {
            verifier: PublicationVerifier::new(metadata.clone()),
            metadata,
            cursor: header.cursor,
            ciphertext: Vec::with_capacity(capacity),
            recovery: recovery.is_some(),
        }));
        Ok(())
    }
    /// A data frame of the current record.
    pub fn record_data(&mut self, bytes: &[u8]) -> Result<(), CloudDeviceError> {
        let State::Record(pending) = &mut self.state else {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayOrder);
        };
        if bytes.len() > self.max_frame_bytes {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayIntegrity);
        }
        if pending.verifier.chunk(bytes).is_err() {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayIntegrity);
        }
        pending.ciphertext.extend_from_slice(bytes);
        Ok(())
    }
    /// The end of the current record: verifies, opens and applies it to `transcript`.
    pub fn record_end(
        &mut self,
        publication_id: &[u8],
        key: &ChatKey,
        transcript: &mut Transcript,
    ) -> Result<AcceptedRecord, CloudDeviceError> {
        let State::Record(pending) = std::mem::replace(&mut self.state, State::Failed) else {
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
            RelayKind::Command | RelayKind::ChatKeyGrant => {
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
        self.check_anchor(&anchor)?;
        let opened = match kind {
            RecordKind::Event => open_event(key, &self.pins.signing, context, &ciphertext)?,
            RecordKind::Snapshot => open_snapshot(key, &self.pins.signing, context, &ciphertext)?,
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
        self.cursor = cursor;
        self.sequence = anchor.position.sequence;
        self.page_records += 1;
        if self
            .head
            .head
            .as_ref()
            .is_some_and(|head| self.sequence >= head.position.sequence)
        {
            self.reached_head = true;
        }
        self.state = State::Between;
        Ok(AcceptedRecord {
            cursor,
            sequence: self.sequence,
            kind,
            restored: recovery,
        })
    }
    /// The end of a page. Without more records, the replay must have reached the head.
    pub fn page_end(
        &mut self,
        through_cursor: u64,
        has_more: bool,
    ) -> Result<PageEnd, CloudDeviceError> {
        let records = std::mem::take(&mut self.page_records);
        if !matches!(self.state, State::Between)
            || through_cursor != self.cursor
            || (has_more && records == 0)
        {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayOrder);
        }
        if has_more {
            return Ok(PageEnd::More);
        }
        if !self.reached_head {
            self.state = State::Failed;
            return Err(CloudDeviceError::Withheld);
        }
        Ok(PageEnd::Complete)
    }
    /// A gap frame: older records were purged. Returns where to fetch the retained snapshot.
    pub fn gap(
        &mut self,
        retained_from: u64,
        snapshot_publication_id: &[u8],
    ) -> Result<GapRecovery, CloudDeviceError> {
        let records = std::mem::take(&mut self.page_records);
        let after = retained_from.checked_sub(1);
        if !matches!(self.state, State::Between)
            || records != 0
            || after.is_none_or(|after| after <= self.cursor)
        {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayOrder);
        }
        let snapshot: [u8; 16] = snapshot_publication_id.try_into().map_err(|_| {
            self.state = State::Failed;
            CloudDeviceError::SnapshotRequired
        })?;
        let after_cursor = after.ok_or(CloudDeviceError::ReplayOrder)?;
        self.cursor = after_cursor;
        self.state = State::AwaitSnapshot(snapshot);
        Ok(GapRecovery {
            after_cursor,
            snapshot_publication_id: snapshot,
        })
    }

    fn publisher(&self, origin: DeliveredOrigin<'_>) -> bool {
        origin.account_id == self.account
            && origin.signing_key == self.pins.proof
            && origin.runner_id == Some(self.chat.runner().id.as_slice())
    }
    fn check_anchor(&self, anchor: &HeadRecordAnchor) -> Result<(), CloudDeviceError> {
        for witnessed in [&self.head.head, &self.head.snapshot].into_iter().flatten() {
            if witnessed.position.sequence == anchor.position.sequence && witnessed != anchor {
                return Err(CloudDeviceError::Withheld);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
