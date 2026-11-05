//! A runner's chat directory as a device verifies it (ADR 0008): the latest runner-signed
//! summary of each chat, read incrementally from the directory stream, merged with the runner's
//! fresh catalog witness ([`merge`]) and kept between listings as a sealed checkpoint
//! ([`VerifiedDirectory`]).
//!
//! A round replays from [`RunnerDirectory::cursor`] and passes every frame here in arrival
//! order: [`RunnerDirectory::record_header`], [`RunnerDirectory::record_data`],
//! [`RunnerDirectory::record_end`], then [`RunnerDirectory::page_end`]. Cursors grow but have
//! holes (the hub keeps only the latest summary of a chat); a gap frame is refused. A record is
//! read only when the hub names the pinned runner as its publisher (account, runner id, proof
//! key), its routing names this runner generation in the account's namespace, and its
//! ciphertext has the announced length and digest; otherwise the round ends and the cursor
//! stays. A record that reads is applied only when it opens from the pinned runner to the
//! account under exactly its routing context, carries the runner's signature and is newer than
//! the summary held for its chat. Records are independent, so a summary that does not apply
//! (another signer, an older revision replayed by the hub, two summaries at one revision) is
//! skipped, never applied, and reported ([`RecordOutcome::Skipped`]).
pub mod checkpoint;
pub mod merge;

pub use checkpoint::VerifiedDirectory;
pub use merge::{ListedChat, RowStatus};

use crate::{
    AccountScope, CloudDeviceError,
    context::AccountKeys,
    reader::DeliveredRecord,
    records::{RunnerPins, TrustedRunner},
    trust::HubCapabilities,
};
use nocterm_hub_model::cloud::{
    CloudNamespace, RunnerCoordinate,
    relay::{
        MAX_RELAY_PAGE_RECORDS, PublicationMetadata, PublicationVerifier, RelayBinding, RelayKind,
    },
    summary::{MAX_SEALED_SUMMARY_BYTES, SignedChatSummary},
};
use nocterm_keys::cloud::{SummaryPins, open_summary};
use std::collections::BTreeMap;

/// Chats a device keeps summaries of, per runner.
pub const MAX_DIRECTORY_CHATS: usize = 1024;
/// Records one directory page asks for.
pub const DIRECTORY_PAGE_RECORDS: u32 = MAX_RELAY_PAGE_RECORDS;
/// Bytes one directory page may carry: a full page of the largest sealed summaries.
#[allow(
    clippy::cast_possible_truncation,
    reason = "64 sealed summaries of at most MAX_SEALED_SUMMARY_BYTES fit u32"
)]
pub const DIRECTORY_PAGE_BYTES: u32 = DIRECTORY_PAGE_RECORDS * MAX_SEALED_SUMMARY_BYTES as u32;

/// The summary held for one chat and the cursor it arrived at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRow {
    summary: SignedChatSummary,
    cursor: u64,
}
impl DirectoryRow {
    pub fn summary(&self) -> &SignedChatSummary {
        &self.summary
    }
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
}

/// What a completed record did.
#[derive(Debug)]
pub enum RecordOutcome {
    /// A newer summary of its chat replaced the held one (or was the first).
    Applied,
    /// The same summary was delivered again.
    Unchanged,
    /// The summary was not applied; the cursor moved past it.
    Skipped(CloudDeviceError),
}

/// Who may have published this directory's records, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryOrigin {
    pub(crate) namespace: CloudNamespace,
    pub(crate) account: String,
    pub(crate) runner: RunnerCoordinate,
    pub(crate) pins: RunnerPins,
}
impl DirectoryOrigin {
    fn publisher(&self, record: &DeliveredRecord<'_>) -> bool {
        record.origin.account_id == self.account
            && record.origin.signing_key == self.pins.proof
            && record.origin.runner_id == Some(self.runner.id.as_slice())
    }
}

#[derive(Debug)]
struct Pending {
    metadata: PublicationMetadata,
    cursor: u64,
    verifier: PublicationVerifier,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
enum State {
    Between,
    Record(Box<Pending>),
    Failed,
}

/// One runner's verified directory: rows, cursor and the record being read.
#[derive(Debug)]
pub struct RunnerDirectory {
    origin: DirectoryOrigin,
    max_frame_bytes: usize,
    cursor: u64,
    rows: BTreeMap<[u8; 16], DirectoryRow>,
    page_records: u32,
    state: State,
}
impl RunnerDirectory {
    /// An empty directory of `runner`, read from cursor 0.
    pub fn new(
        scope: &AccountScope,
        runner: &TrustedRunner,
        capabilities: &HubCapabilities,
    ) -> Result<Self, CloudDeviceError> {
        Self::with_rows(
            Self::origin(scope, runner),
            capabilities,
            0,
            BTreeMap::new(),
        )
    }
    fn origin(scope: &AccountScope, runner: &TrustedRunner) -> DirectoryOrigin {
        DirectoryOrigin {
            namespace: scope.namespace(),
            account: scope.account_id().to_owned(),
            runner: runner.runner(),
            pins: runner.pins(),
        }
    }
    fn with_rows(
        origin: DirectoryOrigin,
        capabilities: &HubCapabilities,
        cursor: u64,
        rows: BTreeMap<[u8; 16], DirectoryRow>,
    ) -> Result<Self, CloudDeviceError> {
        if !capabilities.chat_directory() {
            return Err(CloudDeviceError::Unsupported);
        }
        Ok(Self {
            origin,
            max_frame_bytes: usize::try_from(capabilities.limits().max_frame_bytes)
                .map_err(|_| CloudDeviceError::Capacity)?,
            cursor,
            rows,
            page_records: 0,
            state: State::Between,
        })
    }
    pub fn runner(&self) -> RunnerCoordinate {
        self.origin.runner
    }
    /// The cursor the next round replays after.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    /// The held summaries, by chat id.
    pub fn rows(&self) -> impl Iterator<Item = &DirectoryRow> {
        self.rows.values()
    }
    pub fn row(&self, chat_id: &[u8; 16]) -> Option<&DirectoryRow> {
        self.rows.get(chat_id)
    }
    /// True between records.
    pub fn idle(&self) -> bool {
        matches!(self.state, State::Between)
    }
    /// Forgets a round that ended early (a refused frame or a failed replay effect).
    pub fn abandon(&mut self) {
        self.state = State::Between;
        self.page_records = 0;
    }

    /// A `CloudDeliveredRecord` header.
    pub fn record_header(&mut self, record: &DeliveredRecord<'_>) -> Result<(), CloudDeviceError> {
        if !matches!(
            std::mem::replace(&mut self.state, State::Failed),
            State::Between
        ) {
            return Err(CloudDeviceError::ReplayOrder);
        }
        if record.cursor <= self.cursor || self.page_records >= DIRECTORY_PAGE_RECORDS {
            return Err(CloudDeviceError::ReplayOrder);
        }
        let id: [u8; 16] = record
            .publication_id
            .try_into()
            .map_err(|_| CloudDeviceError::ReplayIntegrity)?;
        let digest: [u8; 32] = record
            .ciphertext_sha256
            .try_into()
            .map_err(|_| CloudDeviceError::ReplayIntegrity)?;
        let binding = RelayBinding::from_canonical_bytes(record.binding)?;
        let context = binding
            .summary_context()
            .filter(|_| binding.kind() == RelayKind::Summary)
            .ok_or(CloudDeviceError::ReplaySource)?;
        if context.chat().namespace() != &self.origin.namespace
            || context.chat().runner() != self.origin.runner
            || !self.origin.publisher(record)
        {
            return Err(CloudDeviceError::ReplaySource);
        }
        let total = usize::try_from(record.total_bytes).map_err(|_| CloudDeviceError::Capacity)?;
        if total > MAX_SEALED_SUMMARY_BYTES {
            return Err(CloudDeviceError::Capacity);
        }
        let metadata = PublicationMetadata::new(id, binding, record.total_bytes, digest)?;
        self.state = State::Record(Box::new(Pending {
            verifier: PublicationVerifier::new(metadata.clone()),
            metadata,
            cursor: record.cursor,
            ciphertext: Vec::with_capacity(total),
        }));
        Ok(())
    }
    /// One data frame of the current record.
    pub fn record_data(&mut self, bytes: &[u8]) -> Result<(), CloudDeviceError> {
        let State::Record(pending) = &mut self.state else {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayOrder);
        };
        if bytes.len() > self.max_frame_bytes || pending.verifier.chunk(bytes).is_err() {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayIntegrity);
        }
        pending.ciphertext.extend_from_slice(bytes);
        Ok(())
    }
    /// The end of the current record: opens and applies it, or skips it.
    pub fn record_end(
        &mut self,
        publication_id: &[u8],
        keys: &AccountKeys,
    ) -> Result<RecordOutcome, CloudDeviceError> {
        let State::Record(pending) = std::mem::replace(&mut self.state, State::Failed) else {
            return Err(CloudDeviceError::ReplayOrder);
        };
        let Pending {
            metadata,
            cursor,
            mut verifier,
            ciphertext,
        } = *pending;
        if publication_id != metadata.id() {
            return Err(CloudDeviceError::ReplayOrder);
        }
        verifier
            .finish_marker()
            .map_err(|_| CloudDeviceError::ReplayIntegrity)?;
        self.state = State::Between;
        self.page_records += 1;
        self.cursor = cursor;
        let outcome = match self.apply(&metadata, &ciphertext, keys, cursor) {
            Ok(outcome) => outcome,
            Err(error) => RecordOutcome::Skipped(error),
        };
        Ok(outcome)
    }
    fn apply(
        &mut self,
        metadata: &PublicationMetadata,
        ciphertext: &[u8],
        keys: &AccountKeys,
        cursor: u64,
    ) -> Result<RecordOutcome, CloudDeviceError> {
        let context = metadata
            .binding()
            .summary_context()
            .ok_or(CloudDeviceError::ReplaySource)?;
        let pins = SummaryPins {
            runner_encryption: self.origin.pins.encryption,
            runner_signing: self.origin.pins.signing,
        };
        let summary = open_summary(keys.pair(), &pins, context, ciphertext)?;
        let chat_id = context.chat().chat_id();
        match self.rows.get(&chat_id) {
            Some(held) => {
                let revision = held.summary.context().revision();
                if context.revision() < revision {
                    return Err(CloudDeviceError::Rollback);
                }
                if context.revision() == revision {
                    return if held.summary == summary {
                        Ok(RecordOutcome::Unchanged)
                    } else {
                        Err(CloudDeviceError::SummaryConflict)
                    };
                }
            }
            None if self.rows.len() >= MAX_DIRECTORY_CHATS => {
                return Err(CloudDeviceError::Capacity);
            }
            None => {}
        }
        self.rows.insert(chat_id, DirectoryRow { summary, cursor });
        Ok(RecordOutcome::Applied)
    }
    /// The page end: `true` when the hub has more records after this page.
    pub fn page_end(
        &mut self,
        through_cursor: u64,
        has_more: bool,
    ) -> Result<bool, CloudDeviceError> {
        let records = std::mem::take(&mut self.page_records);
        if !self.idle() || through_cursor != self.cursor || (has_more && records == 0) {
            self.state = State::Failed;
            return Err(CloudDeviceError::ReplayOrder);
        }
        Ok(has_more)
    }
    /// A directory has no gaps: superseded summaries leave cursor holes instead.
    pub fn gap(&mut self) -> CloudDeviceError {
        self.state = State::Failed;
        CloudDeviceError::ReplayOrder
    }
}

#[cfg(test)]
pub(crate) mod tests;
