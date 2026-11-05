//! One runner's directory rounds inside a listing: replay from the cursor in pages, report what
//! changed, and, in a watching listing, a Watch whose hints start the next round.
use super::{ListIo, Purpose};
use crate::{
    AccountScope, CloudDeviceError,
    context::AccountKeys,
    directory::{
        DIRECTORY_PAGE_BYTES, DIRECTORY_PAGE_RECORDS, RecordOutcome, RunnerDirectory,
        VerifiedDirectory,
    },
    flow::{Effect, EffectId, Frame, StreamKind, StreamSelector},
    open::{RETRY_MAX_MS, RETRY_MIN_MS},
    reader::{DeliveredOrigin, DeliveredRecord},
};

/// Pages one round reads before it reports and leaves the rest to the next round.
pub const MAX_DIRECTORY_PAGES: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Round {
    Idle,
    Wanted,
    Running { pages: u32 },
}

/// What a completed round leaves to report.
#[derive(Debug)]
pub(super) struct RoundReport {
    pub(super) refused: Option<CloudDeviceError>,
    pub(super) checkpoint: Option<VerifiedDirectory>,
}

#[derive(Debug)]
struct Watching {
    live: bool,
    id: Option<EffectId>,
    retry_at: Option<i64>,
    delay: i64,
    connected: bool,
    hinted: u64,
}

#[derive(Debug)]
pub(super) struct DirectoryScan {
    directory: RunnerDirectory,
    round: Round,
    replay: Option<EffectId>,
    rounds: u32,
    reported_cursor: u64,
    refused: Option<CloudDeviceError>,
    watch: Watching,
}
impl DirectoryScan {
    pub(super) fn new(directory: RunnerDirectory, live: bool) -> Self {
        Self {
            reported_cursor: directory.cursor(),
            directory,
            round: Round::Wanted,
            replay: None,
            rounds: 0,
            refused: None,
            watch: Watching {
                live,
                id: None,
                retry_at: None,
                delay: RETRY_MIN_MS,
                connected: false,
                hinted: 0,
            },
        }
    }
    /// Keeps a Watch on the directory once the first round completed.
    pub(super) fn watch(&mut self) {
        self.watch.live = true;
    }
    pub(super) fn directory(&self) -> &RunnerDirectory {
        &self.directory
    }
    /// The first round completed and no round runs.
    pub(super) fn settled(&self) -> bool {
        self.rounds > 0 && !matches!(self.round, Round::Running { .. })
    }
    fn selector(&self) -> StreamSelector {
        let runner = self.directory.runner();
        StreamSelector {
            runner_id: runner.id,
            runner_key_epoch: runner.key_epoch,
            stream: StreamKind::Directory,
        }
    }
    fn request(&mut self, io: &mut ListIo, index: usize, pages: u32) {
        self.round = Round::Running { pages };
        self.replay = Some(io.issue(
            Purpose::Replay(index),
            Effect::Replay {
                selector: self.selector(),
                after_cursor: self.directory.cursor(),
                max_records: DIRECTORY_PAGE_RECORDS,
                max_bytes: DIRECTORY_PAGE_BYTES,
            },
        ));
    }
    /// Starts what is due: a wanted round, a watch (re)connect. True when an effect was issued.
    pub(super) fn tick(&mut self, io: &mut ListIo, index: usize, now_ms: i64) -> bool {
        let mut busy = false;
        if self.round == Round::Wanted {
            self.request(io, index, 0);
            busy = true;
        }
        if self.watch.live
            && self.rounds > 0
            && self.watch.id.is_none()
            && self.watch.retry_at.is_none_or(|at| now_ms >= at)
        {
            if std::mem::replace(&mut self.watch.connected, true) && self.round == Round::Idle {
                // A reconnect may have missed hints: catch up from the cursor.
                self.round = Round::Wanted;
            }
            self.watch.retry_at = None;
            let effect = Effect::Watch {
                selector: self.selector(),
                after_cursor: self.directory.cursor(),
            };
            self.watch.id = Some(io.issue(Purpose::Watch(index), effect));
            busy = true;
        }
        busy
    }
    /// When a watch reconnect is due.
    pub(super) fn wake_at(&self) -> Option<i64> {
        self.watch.retry_at.filter(|_| self.watch.id.is_none())
    }
    pub(super) fn hint(&mut self, head_cursor: u64) {
        self.watch.delay = RETRY_MIN_MS;
        self.watch.hinted = self.watch.hinted.max(head_cursor);
        if head_cursor > self.directory.cursor() && self.round == Round::Idle {
            self.round = Round::Wanted;
        }
    }
    pub(super) fn watch_ended(&mut self, now_ms: i64) {
        self.watch.id = None;
        self.watch.retry_at = Some(now_ms.saturating_add(self.watch.delay));
        self.watch.delay = (self.watch.delay * 2).min(RETRY_MAX_MS);
    }
    /// The replay effect failed: the round ends with that failure.
    pub(super) fn replay_failed(&mut self, error: CloudDeviceError) {
        self.replay = None;
        self.directory.abandon();
        self.refused.get_or_insert(error);
        self.end_round();
    }
    /// One replay frame; true when the round completed (a refused frame ends it).
    pub(super) fn frame(
        &mut self,
        io: &mut ListIo,
        index: usize,
        frame: Frame,
        keys: &AccountKeys,
    ) -> bool {
        match self.read(io, index, frame, keys) {
            Ok(done) => done,
            Err(error) => {
                if let Some(id) = self.replay.take() {
                    io.abandon(id);
                }
                self.replay_failed(error);
                true
            }
        }
    }
    fn read(
        &mut self,
        io: &mut ListIo,
        index: usize,
        frame: Frame,
        keys: &AccountKeys,
    ) -> Result<bool, CloudDeviceError> {
        match frame {
            Frame::Header(header) => self.directory.record_header(&DeliveredRecord {
                publication_id: &header.publication_id,
                binding: &header.binding,
                total_bytes: header.total_bytes,
                ciphertext_sha256: &header.ciphertext_sha256,
                cursor: header.cursor,
                origin: DeliveredOrigin {
                    account_id: &header.origin_account_id,
                    signing_key: &header.origin_signing_key,
                    runner_id: header.origin_runner_id.as_deref(),
                },
            })?,
            Frame::Data(bytes) => self.directory.record_data(&bytes)?,
            Frame::End { publication_id } => {
                if let RecordOutcome::Skipped(error) =
                    self.directory.record_end(&publication_id, keys)?
                {
                    self.refused.get_or_insert(error);
                }
            }
            Frame::PageEnd {
                through_cursor,
                has_more,
            } => {
                self.replay = None;
                let more = self.directory.page_end(through_cursor, has_more)?;
                let Round::Running { pages } = self.round else {
                    return Err(CloudDeviceError::Protocol);
                };
                if more && pages + 1 < MAX_DIRECTORY_PAGES {
                    self.request(io, index, pages + 1);
                    return Ok(false);
                }
                self.end_round();
                return Ok(true);
            }
            Frame::Gap { .. } => return Err(self.directory.gap()),
            Frame::Hint { .. } => return Err(CloudDeviceError::Protocol),
        }
        Ok(false)
    }
    fn end_round(&mut self) {
        self.rounds = self.rounds.saturating_add(1);
        self.round = if self.watch.hinted > self.directory.cursor() && self.refused.is_none() {
            Round::Wanted
        } else {
            Round::Idle
        };
    }
    /// What the round that just completed changed.
    pub(super) fn report(&mut self, scope: &AccountScope, keys: &AccountKeys) -> RoundReport {
        let cursor = self.directory.cursor();
        let checkpoint = if cursor == self.reported_cursor {
            None
        } else {
            self.reported_cursor = cursor;
            self.directory.checkpoint(scope, keys).ok()
        };
        RoundReport {
            refused: self.refused.take(),
            checkpoint,
        }
    }
}
