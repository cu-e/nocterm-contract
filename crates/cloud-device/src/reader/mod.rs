//! The resumable, verified reader of one chat generation (ADR 0007).
//!
//! A reader keeps its position across replay rounds: the transport cursor, the event sequence,
//! the writer epoch and the last accepted record. Each round replays from [`ChatReader::cursor`]
//! and passes every frame here in arrival order: [`ChatReader::record_header`],
//! [`ChatReader::record_data`] for each data frame, [`ChatReader::record_end`], then
//! [`ChatReader::page_end`] or [`ChatReader::gap`]. A record is accepted only when:
//! - its transport cursor is the next one and the hub names the pinned runner (account, runner
//!   id and proof key) as its publisher;
//! - its routing names this chat generation, its sequence is the next one, its writer is not
//!   older than the last accepted writer nor newer than a witnessed current writer;
//! - its ciphertext has the announced length and digest, opens under the chat key and carries
//!   the pinned runner's signature over exactly that context;
//! - where it reaches a witnessed head or snapshot position, it is that witnessed record.
//!
//! Freshness says how much the reader knows ([`Freshness`]): a new or restored reader is
//! `Opening` until its first round completes; a round after a fresh witness
//! ([`ChatReader::witness`]) that reaches the witnessed head is `Current`; one that ends below it
//! is `Withheld` (the hub hid newer history the runner witnessed); a round after a probe the
//! runner did not answer ([`ChatReader::unanswered`]) is `Unconfirmed`, a verified prefix that
//! newer history may follow. Rounds driven by Watch hints keep the state. A refused frame ends
//! the round; records accepted before it stay, so the transcript is always a verified prefix.
//! A reader's state can be sealed into a checkpoint ([`checkpoint`]) and restored later.
//! The browser never acknowledges; this reader keeps no acknowledgement state.
pub mod checkpoint;
mod verify;

pub use checkpoint::VerifiedChat;
pub use verify::{AcceptedRecord, DeliveredOrigin, DeliveredRecord, GapRecovery};

use crate::{
    CloudDeviceError, records::ChatSelector, transcript::Transcript, trust::HubCapabilities,
};
use nocterm_hub_model::cloud::{
    ChatCoordinate,
    head::{ChatHead, HeadRecordAnchor},
    relay::MAX_RELAY_PAGE_RECORDS,
};
use verify::{Limits, Origin, State};

/// How far a reader's transcript is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// No round has finished since the reader was made or restored: a restored transcript is
    /// shown, but nothing has been asked of the runner yet (not "the seat is asleep").
    Opening { last_witnessed_at_ms: Option<i64> },
    /// A fresh head witness answered and the replay reached it. Later records that Watch hints
    /// bring are verified one by one and keep this state.
    Current { witnessed_at_ms: i64 },
    /// The runner did not answer a probe: the hub's records are a verified prefix that newer
    /// history may follow (a sleeping seat).
    Unconfirmed { last_witnessed_at_ms: Option<i64> },
    /// The runner witnessed a head the hub's replay did not reach: the hub withholds history.
    Withheld { witnessed_at_ms: i64 },
}

/// How a page ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundEnd {
    /// Replay again from [`ChatReader::cursor`].
    More,
    /// The round is over; the reader is in this state now.
    Complete(Freshness),
}

/// Where the reader stands. Plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Position {
    pub(crate) cursor: u64,
    pub(crate) sequence: u64,
    pub(crate) writer: u64,
    pub(crate) last: Option<HeadRecordAnchor>,
}

/// The last head a runner witnessed to this device, and when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Witnessed {
    pub(crate) head: ChatHead,
    pub(crate) at_ms: i64,
}

/// One chat generation's verified position, transcript and freshness.
#[derive(Debug)]
pub struct ChatReader {
    origin: Origin,
    limits: Limits,
    position: Position,
    witnessed: Option<Witnessed>,
    /// A fresh witness the current or a later round must reach.
    target: Option<Witnessed>,
    unanswered: bool,
    /// The cursor before a gap moved it, until the snapshot is accepted.
    resume: Option<u64>,
    freshness: Freshness,
    transcript: Transcript,
    page_records: u32,
    state: State,
}
impl ChatReader {
    /// A reader of `selector` from cursor 0.
    pub fn new(
        selector: &ChatSelector,
        capabilities: &HubCapabilities,
    ) -> Result<Self, CloudDeviceError> {
        Self::with_state(
            selector,
            capabilities,
            Position {
                cursor: 0,
                sequence: 0,
                writer: 0,
                last: None,
            },
            None,
            Transcript::new(),
        )
    }
    pub(crate) fn with_state(
        selector: &ChatSelector,
        capabilities: &HubCapabilities,
        position: Position,
        witnessed: Option<Witnessed>,
        transcript: Transcript,
    ) -> Result<Self, CloudDeviceError> {
        capabilities.require_reading()?;
        Ok(Self {
            origin: Origin::of(selector)?,
            limits: Limits::of(capabilities)?,
            freshness: Freshness::Opening {
                last_witnessed_at_ms: witnessed.as_ref().map(|seen| seen.at_ms),
            },
            position,
            witnessed,
            target: None,
            unanswered: false,
            resume: None,
            transcript,
            page_records: 0,
            state: State::Between,
        })
    }
    pub fn chat(&self) -> &ChatCoordinate {
        &self.origin.chat
    }
    /// The `after_cursor` of the next `Replay` request.
    pub fn cursor(&self) -> u64 {
        self.position.cursor
    }
    /// The last accepted event sequence.
    pub fn sequence(&self) -> u64 {
        self.position.sequence
    }
    pub fn freshness(&self) -> Freshness {
        self.freshness
    }
    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }
    pub fn transcript_mut(&mut self) -> &mut Transcript {
        &mut self.transcript
    }
    /// The last head a runner witnessed to this reader, if any.
    pub fn witnessed_head(&self) -> Option<&ChatHead> {
        self.witnessed.as_ref().map(|seen| &seen.head)
    }
    /// The most records one page may ask for.
    pub fn max_page_records() -> u32 {
        MAX_RELAY_PAGE_RECORDS
    }
    /// True between rounds or pages, when a new round may start.
    pub fn idle(&self) -> bool {
        matches!(self.state, State::Between)
    }

    /// A head the pinned runner witnessed to a fresh probe at `at_ms`. It must name this
    /// generation and must not be behind what this reader already verified.
    pub fn witness(&mut self, head: ChatHead, at_ms: i64) -> Result<(), CloudDeviceError> {
        if head.chat_id != self.origin.chat.chat_id()
            || head.chat_key_epoch != self.origin.chat.key_epoch()
        {
            return Err(CloudDeviceError::Withheld);
        }
        let ours = &self.position;
        let behind = match &head.head {
            None => ours.sequence > 0,
            Some(anchor) => {
                anchor.position.sequence < ours.sequence
                    || (anchor.position.sequence == ours.sequence
                        && ours.last.as_ref().is_some_and(|last| last != anchor))
            }
        };
        if behind
            || head
                .current_writer
                .is_some_and(|writer| writer < ours.writer)
        {
            return Err(CloudDeviceError::Rollback);
        }
        let seen = Witnessed { head, at_ms };
        self.witnessed = Some(seen.clone());
        self.target = Some(seen);
        self.unanswered = false;
        Ok(())
    }
    /// The runner did not answer a probe: the next round ends `Unconfirmed`.
    pub fn unanswered(&mut self) {
        self.unanswered = true;
    }

    /// A header frame. A refusal ends the round; call [`Self::abandon`] before the next one.
    pub fn record_header(&mut self, header: &DeliveredRecord<'_>) -> Result<(), CloudDeviceError> {
        let writer_cap = self
            .target
            .as_ref()
            .and_then(|seen| seen.head.current_writer);
        let pending = verify::header(
            &mut self.state,
            &self.origin,
            &self.limits,
            &self.position,
            writer_cap,
            self.page_records,
            header,
        )?;
        self.state = State::Record(Box::new(pending));
        Ok(())
    }
    /// A data frame of the current record.
    pub fn record_data(&mut self, bytes: &[u8]) -> Result<(), CloudDeviceError> {
        verify::data(&mut self.state, &self.limits, bytes)
    }
    /// The end of the current record: verifies and opens it under `key` and applies it.
    pub fn record_end(
        &mut self,
        publication_id: &[u8],
        key: &nocterm_keys::cloud::ChatKey,
    ) -> Result<AcceptedRecord, CloudDeviceError> {
        let anchors = [
            self.witnessed
                .as_ref()
                .and_then(|seen| seen.head.head.clone()),
            self.witnessed
                .as_ref()
                .and_then(|seen| seen.head.snapshot.clone()),
        ];
        let accepted = verify::end(
            &mut self.state,
            &self.origin,
            &anchors,
            publication_id,
            key,
            &mut self.transcript,
        )?;
        self.position = Position {
            cursor: accepted.cursor,
            sequence: accepted.sequence,
            writer: accepted.anchor.position.writer_epoch,
            last: Some(accepted.anchor.clone()),
        };
        self.page_records += 1;
        self.resume = None;
        self.state = State::Between;
        Ok(accepted)
    }
    /// The end of a page.
    pub fn page_end(
        &mut self,
        through_cursor: u64,
        has_more: bool,
    ) -> Result<RoundEnd, CloudDeviceError> {
        let records = std::mem::take(&mut self.page_records);
        if !matches!(self.state, State::Between)
            || through_cursor != self.position.cursor
            || (has_more && records == 0)
        {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayOrder);
        }
        if has_more {
            return Ok(RoundEnd::More);
        }
        self.freshness = match self.target.take() {
            Some(seen) if self.reached(&seen.head) => Freshness::Current {
                witnessed_at_ms: seen.at_ms,
            },
            Some(seen) => {
                let at = seen.at_ms;
                self.target = Some(seen);
                Freshness::Withheld {
                    witnessed_at_ms: at,
                }
            }
            None if std::mem::take(&mut self.unanswered) => Freshness::Unconfirmed {
                last_witnessed_at_ms: self.witnessed.as_ref().map(|seen| seen.at_ms),
            },
            // A first round without any witness or probe confirms nothing either.
            None => match self.freshness {
                Freshness::Opening {
                    last_witnessed_at_ms,
                } => Freshness::Unconfirmed {
                    last_witnessed_at_ms,
                },
                freshness => freshness,
            },
        };
        Ok(RoundEnd::Complete(self.freshness))
    }
    /// A gap frame: older records were purged. Returns where to fetch the retained snapshot.
    pub fn gap(
        &mut self,
        retained_from: u64,
        snapshot_publication_id: &[u8],
    ) -> Result<GapRecovery, CloudDeviceError> {
        let records = std::mem::take(&mut self.page_records);
        let before = self.position.cursor;
        let recovery = verify::gap(
            &mut self.state,
            &mut self.position.cursor,
            records,
            retained_from,
            snapshot_publication_id,
        )?;
        self.resume = Some(before);
        Ok(recovery)
    }
    /// Ends a round that will not finish (a refused frame or a failed request). Accepted
    /// records stay; the next round starts from the last accepted cursor.
    pub fn abandon(&mut self) {
        if let Some(resume) = self.resume.take() {
            self.position.cursor = resume;
        }
        self.state = State::Between;
        self.page_records = 0;
    }

    fn reached(&self, head: &ChatHead) -> bool {
        head.head
            .as_ref()
            .is_none_or(|anchor| self.position.sequence >= anchor.position.sequence)
    }
    pub(crate) fn position(&self) -> &Position {
        &self.position
    }
    pub(crate) fn witnessed(&self) -> Option<&Witnessed> {
        self.witnessed.as_ref()
    }
}

#[cfg(test)]
mod tests;
