//! What changed in a transcript since the caller last looked, so a view applies a small change
//! instead of rebuilding everything.
//!
//! A view applies a [`TranscriptDelta`] in this order: on `reset` it clears everything; it drops
//! rows whose index is below `first_index`; when `changed_from` is set it drops the rows from
//! that index on and appends `rows`; it replaces runs, approvals and pending commands that are
//! present; it takes the scalar fields as they are.
use super::{ApprovalRequest, PendingCommand, RunState, TranscriptRow};

/// One transcript change. Plain data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TranscriptDelta {
    /// The transcript was replaced (first read, a snapshot after a gap, a restored checkpoint).
    pub reset: bool,
    /// The index of the first row still held.
    pub first_index: u64,
    /// Rows from this index on were changed or added; they are `rows`.
    pub changed_from: Option<u64>,
    pub rows: Vec<TranscriptRow>,
    pub runs: Option<Vec<RunState>>,
    pub approvals: Option<Vec<ApprovalRequest>>,
    pub pending: Option<Vec<PendingCommand>>,
    pub control_revision: u64,
    pub deleted: bool,
    pub omitted_earlier: bool,
}
impl TranscriptDelta {
    /// True when the delta changes nothing a view shows.
    pub fn is_empty(&self) -> bool {
        !self.reset
            && self.changed_from.is_none()
            && self.runs.is_none()
            && self.approvals.is_none()
            && self.pending.is_none()
    }
}

/// The parts of a transcript changed since the last delta.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent change marks of independent parts"
)]
pub(super) struct Dirty {
    pub(super) reset: bool,
    pub(super) rows_from: Option<u64>,
    pub(super) runs: bool,
    pub(super) approvals: bool,
    pub(super) pending: bool,
    pub(super) flags: bool,
}
impl Dirty {
    pub(super) fn row(&mut self, index: u64) {
        self.rows_from = Some(self.rows_from.map_or(index, |from| from.min(index)));
    }
    pub(super) fn everything() -> Self {
        Self {
            reset: true,
            rows_from: Some(0),
            runs: true,
            approvals: true,
            pending: true,
            flags: true,
        }
    }
    pub(super) fn any(&self) -> bool {
        self != &Self::default()
    }
}
