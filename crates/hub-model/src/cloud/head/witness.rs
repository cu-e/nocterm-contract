use super::{HeadProbeError, HeadQuery, HeadTarget, MAX_HEAD_CLOCK_SKEW_MS, reader, writer};
use crate::{
    cloud::{RecordKind, RecordPosition, RunCoordinate},
    pop,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRecordAnchor {
    pub kind: RecordKind,
    pub position: RecordPosition,
    pub id: [u8; 16],
    pub run: Option<RunCoordinate>,
    pub ciphertext_digest: [u8; 32],
}
/// Actual current metadata. The current writer can be newer than its last event.
/// A zero-event chat has no synthetic event id or digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatHead {
    pub chat_id: [u8; 16],
    pub chat_key_epoch: u64,
    pub current_writer: Option<u64>,
    pub control_revision: u64,
    pub deleted: bool,
    pub head: Option<HeadRecordAnchor>,
    pub retained_from: u64,
    pub snapshot: Option<HeadRecordAnchor>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogHeadCursor {
    pub revision: u64,
    pub digest: [u8; 32],
    pub after: [u8; 16],
    pub seen: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogHeadPage {
    pub revision: u64,
    pub digest: [u8; 32],
    pub total_chats: u32,
    pub after: Option<CatalogHeadCursor>,
    pub chats: Vec<ChatHead>,
    pub has_more: bool,
}
impl CatalogHeadPage {
    pub fn next_cursor(&self) -> Option<CatalogHeadCursor> {
        if !self.has_more {
            return None;
        }
        Some(CatalogHeadCursor {
            revision: self.revision,
            digest: self.digest,
            after: self.chats.last()?.chat_id,
            seen: self
                .after
                .as_ref()
                .map_or(0, |c| c.seen)
                .checked_add(u32::try_from(self.chats.len()).ok()?)?,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptOutcome {
    NotFound,
    Accepted {
        control_revision: u64,
    },
    Conflict,
    /// No admission or rejection is established; retain the exact original M.
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadValue {
    Catalog(Box<CatalogHeadPage>),
    Chat(Box<ChatHead>),
    CommandReceipt(ReceiptOutcome),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadWitness {
    pub query: HeadQuery,
    pub observed_at_ms: i64,
    pub value: HeadValue,
}
impl HeadWitness {
    pub fn validate(&self) -> Result<(), HeadProbeError> {
        self.query.validate()?;
        if self.observed_at_ms <= 0
            || self.observed_at_ms
                < self
                    .query
                    .window
                    .issued_at_ms
                    .saturating_sub(MAX_HEAD_CLOCK_SKEW_MS)
            || self.observed_at_ms
                > self
                    .query
                    .window
                    .expires_at_ms
                    .saturating_add(MAX_HEAD_CLOCK_SKEW_MS)
        {
            return Err(HeadProbeError::Time);
        }
        match (&self.query.target, &self.value) {
            (HeadTarget::Catalog { after }, HeadValue::Catalog(page)) if after == &page.after => {}
            (
                HeadTarget::Chat {
                    chat_id,
                    chat_key_epoch,
                },
                HeadValue::Chat(head),
            ) if chat_id == &head.chat_id && chat_key_epoch == &head.chat_key_epoch => {}
            (
                HeadTarget::CommandReceipt {
                    expected_control_revision,
                    ..
                },
                HeadValue::CommandReceipt(outcome),
            ) => {
                if let ReceiptOutcome::Accepted { control_revision } = outcome
                    && expected_control_revision.checked_add(1) != Some(*control_revision)
                {
                    return Err(HeadProbeError::Position);
                }
            }
            _ => return Err(HeadProbeError::Target),
        }
        writer::validate_witness(self)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HeadProbeError> {
        self.validate()?;
        writer::witness(self)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HeadProbeError> {
        reader::witness(bytes)
    }
}
#[derive(Clone, Debug)]
pub struct SignedHeadWitness {
    witness: HeadWitness,
    signature: [u8; 64],
}
impl SignedHeadWitness {
    pub fn new(witness: HeadWitness, signature: [u8; 64]) -> Result<Self, HeadProbeError> {
        pop::verify(
            &witness.query.scope.keys.runner_signing,
            &witness.canonical_bytes()?,
            &signature,
        )?;
        Ok(Self { witness, signature })
    }
    pub fn witness(&self) -> &HeadWitness {
        &self.witness
    }
    pub fn require_query(&self, expected: &HeadQuery, now_ms: i64) -> Result<(), HeadProbeError> {
        if &self.witness.query != expected {
            return Err(HeadProbeError::Scope);
        }
        expected.require_fresh(now_ms)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HeadProbeError> {
        writer::signed(
            &self.witness.canonical_bytes()?,
            &self.signature,
            super::MAX_HEAD_REPLY_ENVELOPE_BYTES,
        )
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HeadProbeError> {
        let (body, signature) = reader::signed(bytes, super::MAX_HEAD_REPLY_ENVELOPE_BYTES)?;
        Self::new(HeadWitness::from_canonical_bytes(body)?, signature)
    }
}
