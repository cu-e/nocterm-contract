//! The `ListChats` flow: every trusted runner's chats from its directory of runner-signed
//! summaries, confirmed by a fresh catalog witness, without replaying any chat (ADR 0007, 0008).
//!
//! For each runner at once, the flow probes the runner's catalog (at most
//! [`MAX_CATALOG_PAGES`] pages) and, when the hub keeps chat directories (capability bit 256),
//! replays the runner's directory from the cursor of its last checkpoint
//! ([`ListChats::with_directories`]). The account's seats are listed to tell managed agents from
//! own runners. Every runner reports on its own, so a sleeping seat does not hold back the
//! others. [`ChatListUpdate::Runner`] carries all rows of a runner and replaces any earlier rows
//! of it: once when its directory was read (rows `Pending` while the catalog probe is out) and
//! once when its catalog answered or did not ([`crate::directory::merge`] gives the row states).
//! A runner that did not answer is also reported as [`ChatListUpdate::Unreachable`]; with a
//! directory its rows stay, shown as of their last activity. After a round that moved the
//! directory cursor the flow hands out a sealed [`ChatListUpdate::Directory`] checkpoint to
//! store per runner. Without bit 256 the rows are the catalog's alone (`Unsummarized`).
//!
//! A watching listing ([`ListChats::watching`]) keeps a Watch on every directory and reads each
//! new summary as it is published, reporting the runner's rows again; it never ends by itself.
//! The catalog is not probed again: there is never periodic probing.
mod directory_scan;

pub use crate::directory::{ListedChat, RowStatus};
pub use directory_scan::MAX_DIRECTORY_PAGES;

use crate::{
    CloudDeviceError, DeviceIdentity,
    context::CloudSession,
    directory::{
        RunnerDirectory, VerifiedDirectory,
        merge::{self, Catalog, WitnessedChat},
    },
    flow::{
        Arrival, Driven, Effect, EffectId, Flow, Frame, Input, InstanceEntry, Io, Machine, Step,
        Wait,
    },
    probe::{ProbeCall, ProbeTarget},
    records::TrustedRunner,
};
use directory_scan::DirectoryScan;
use nocterm_hub_model::cloud::head::{CatalogHeadCursor, HeadValue};
use std::sync::Arc;

/// Catalog pages read per runner (64 chats each).
pub const MAX_CATALOG_PAGES: u32 = 8;

/// What a listing reports, runner by runner.
#[derive(Debug)]
pub enum ChatListUpdate {
    /// The account's seats (agent instances), to name the agent of a runner.
    Seats(Vec<InstanceEntry>),
    /// All rows of a runner, replacing earlier ones; `complete` once its whole catalog was read.
    Runner {
        runner: TrustedRunner,
        chats: Vec<ListedChat>,
        complete: bool,
    },
    /// A runner did not answer (`reason` is `None`) or its answer was refused.
    Unreachable {
        runner: TrustedRunner,
        reason: Option<CloudDeviceError>,
    },
    /// The sealed directory of `runner`: store it in place of the previous one and pass it to
    /// the next listing.
    Directory {
        runner: [u8; 16],
        checkpoint: VerifiedDirectory,
    },
    /// A directory record or round was refused; summaries verified before stay.
    DirectoryRefused {
        runner: TrustedRunner,
        reason: CloudDeviceError,
    },
}

/// The `ListChats` flow.
#[derive(Debug)]
pub struct ListChats(Driven<Listing>);
impl ListChats {
    pub fn new(session: Arc<CloudSession>, device: DeviceIdentity) -> Self {
        let scans = session
            .runners()
            .iter()
            .map(|runner| Scan {
                directory: RunnerDirectory::new(session.scope(), runner, session.capabilities())
                    .ok()
                    .map(|directory| DirectoryScan::new(directory, false)),
                runner: runner.clone(),
                probe: None,
                pages: 0,
                after: None,
                chats: Vec::new(),
                catalog: CatalogState::Unstarted,
            })
            .collect();
        Self(Driven::new(Listing {
            session,
            device,
            scans,
            seats: Seats::Unasked,
            live: false,
        }))
    }
    /// Resumes each runner's directory at its checkpoint among `checkpoints`. A checkpoint of
    /// another runner, account or hub, or one that does not open, is ignored.
    #[must_use]
    pub fn with_directories(mut self, checkpoints: &[VerifiedDirectory]) -> Self {
        let listing = &mut self.0;
        listing.with(|listing, _| {
            let session = listing.session.clone();
            for scan in &mut listing.scans {
                let restored = checkpoints.iter().find_map(|checkpoint| {
                    RunnerDirectory::restore(
                        session.scope(),
                        &scan.runner,
                        session.capabilities(),
                        session.keys(),
                        checkpoint,
                    )
                    .ok()
                });
                if let Some(directory) = restored {
                    scan.directory = Some(DirectoryScan::new(directory, listing.live));
                }
            }
        });
        self
    }
    /// Keeps watching every directory after the first round; the flow then never ends.
    #[must_use]
    pub fn watching(mut self) -> Self {
        self.0.with(|listing, _| {
            listing.live = true;
            for directory in listing
                .scans
                .iter_mut()
                .filter_map(|s| s.directory.as_mut())
            {
                directory.watch();
            }
        });
        self
    }
}
impl Flow for ListChats {
    type Output = ChatListUpdate;
    fn next(&mut self, now_ms: i64) -> Step<ChatListUpdate> {
        self.0.next(now_ms)
    }
    fn resolve(&mut self, id: EffectId, input: Input) {
        self.0.resolve(id, input);
    }
    fn frame(&mut self, id: EffectId, frame: Frame) {
        self.0.frame(id, frame);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    Seats,
    Sign(usize),
    Probe(usize),
    Replay(usize),
    Watch(usize),
}

#[derive(Debug, PartialEq, Eq)]
enum Seats {
    Unasked,
    Asked,
    Answered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CatalogState {
    Unstarted,
    Probing,
    Answered { complete: bool },
    Unanswered,
}

#[derive(Debug)]
struct Scan {
    runner: TrustedRunner,
    probe: Option<ProbeCall>,
    pages: u32,
    after: Option<CatalogHeadCursor>,
    chats: Vec<WitnessedChat>,
    catalog: CatalogState,
    directory: Option<DirectoryScan>,
}
impl Scan {
    fn resolved(&self) -> bool {
        matches!(
            self.catalog,
            CatalogState::Answered { .. } | CatalogState::Unanswered
        )
    }
    fn rows(&self) -> Vec<ListedChat> {
        let catalog = match self.catalog {
            CatalogState::Unstarted | CatalogState::Probing => Catalog::Pending,
            CatalogState::Answered { complete } => Catalog::Answered {
                chats: &self.chats,
                complete,
            },
            CatalogState::Unanswered => Catalog::Unanswered,
        };
        merge::merge(
            self.runner.runner().id,
            self.directory.as_ref().map(DirectoryScan::directory),
            catalog,
        )
    }
    fn runner_update(&self) -> ChatListUpdate {
        ChatListUpdate::Runner {
            runner: self.runner.clone(),
            chats: self.rows(),
            complete: self.catalog == CatalogState::Answered { complete: true },
        }
    }
}

#[derive(Debug)]
pub(crate) struct Listing {
    session: Arc<CloudSession>,
    device: DeviceIdentity,
    scans: Vec<Scan>,
    seats: Seats,
    live: bool,
}
type ListIo = Io<Purpose, ChatListUpdate>;

impl Listing {
    fn scan(&mut self, index: usize) -> Result<&mut Scan, CloudDeviceError> {
        self.scans.get_mut(index).ok_or(CloudDeviceError::Protocol)
    }
    fn probe(
        &mut self,
        io: &mut ListIo,
        index: usize,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let scan = &mut self.scans[index];
        let target = ProbeTarget::Catalog(scan.after.clone());
        let (probe, request) =
            ProbeCall::start(&self.session, &self.device, &scan.runner, target, now_ms)?;
        scan.probe = Some(probe);
        scan.catalog = CatalogState::Probing;
        io.issue(Purpose::Sign(index), Effect::Sign(request));
        Ok(())
    }
    /// The catalog of runner `index` resolved: report it, merged with its directory once read.
    fn catalog_done(&mut self, io: &mut ListIo, index: usize, state: CatalogState) {
        let scan = &mut self.scans[index];
        scan.catalog = state;
        // Without a directory an unanswered runner has no rows; with one, a round still
        // running reports when it completes.
        let report = match scan.directory.as_ref() {
            None => state != CatalogState::Unanswered,
            Some(directory) => directory.settled(),
        };
        if report {
            io.output(scan.runner_update());
        }
    }
    fn unreachable(&mut self, io: &mut ListIo, index: usize, reason: Option<CloudDeviceError>) {
        io.output(ChatListUpdate::Unreachable {
            runner: self.scans[index].runner.clone(),
            reason,
        });
        self.catalog_done(io, index, CatalogState::Unanswered);
    }
    fn answered(
        &mut self,
        io: &mut ListIo,
        index: usize,
        input: Input,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let keys = self.session.keys().clone();
        let scan = self.scan(index)?;
        let mut probe = scan.probe.take().ok_or(CloudDeviceError::Protocol)?;
        let page = match probe.answered(&keys, input, now_ms) {
            Ok(Some(HeadValue::Catalog(page))) => page,
            Ok(Some(_)) => {
                self.unreachable(io, index, Some(CloudDeviceError::Protocol));
                return Ok(());
            }
            Ok(None) => {
                self.unreachable(io, index, None);
                return Ok(());
            }
            Err(error) => {
                self.unreachable(io, index, Some(error));
                return Ok(());
            }
        };
        scan.chats
            .extend(page.chats.iter().map(|head| WitnessedChat {
                head: head.clone(),
                at_ms: now_ms,
            }));
        scan.pages += 1;
        scan.after = page.next_cursor();
        if scan.after.is_some() && scan.pages < MAX_CATALOG_PAGES {
            return self.probe(io, index, now_ms);
        }
        let complete = scan.after.is_none();
        self.catalog_done(io, index, CatalogState::Answered { complete });
        Ok(())
    }
    /// A directory round of runner `index` completed: report what it changed and the rows.
    fn round_done(&mut self, io: &mut ListIo, index: usize) {
        let session = self.session.clone();
        let scan = &mut self.scans[index];
        let Some(directory) = scan.directory.as_mut() else {
            return;
        };
        let report = directory.report(session.scope(), session.keys());
        let has_rows = directory.directory().rows().next().is_some();
        if let Some(reason) = report.refused {
            io.output(ChatListUpdate::DirectoryRefused {
                runner: scan.runner.clone(),
                reason,
            });
        }
        if let Some(checkpoint) = report.checkpoint {
            io.output(ChatListUpdate::Directory {
                runner: scan.runner.runner().id,
                checkpoint,
            });
        }
        if scan.resolved() || has_rows {
            io.output(scan.runner_update());
        }
    }
    fn directory_input(
        &mut self,
        io: &mut ListIo,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let keys = self.session.keys().clone();
        let (Purpose::Replay(index) | Purpose::Watch(index)) = purpose else {
            return Err(CloudDeviceError::Protocol);
        };
        let directory = self
            .scan(index)?
            .directory
            .as_mut()
            .ok_or(CloudDeviceError::Protocol)?;
        match (purpose, arrival) {
            (Purpose::Replay(_), Arrival::Frame(frame)) => {
                if directory.frame(io, index, frame, &keys) {
                    self.round_done(io, index);
                }
            }
            (Purpose::Replay(_), Arrival::Input(Input::Failed(failure))) => {
                directory.replay_failed(CloudDeviceError::Effect(failure));
                self.round_done(io, index);
            }
            (Purpose::Watch(_), Arrival::Frame(Frame::Hint { head_cursor })) => {
                directory.hint(head_cursor);
            }
            (Purpose::Watch(_), Arrival::Input(Input::Failed(_))) => directory.watch_ended(now_ms),
            _ => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
}

impl Machine for Listing {
    type Purpose = Purpose;
    type Output = ChatListUpdate;
    fn handle(
        &mut self,
        io: &mut ListIo,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let input = match (purpose, arrival) {
            (Purpose::Replay(_) | Purpose::Watch(_), arrival) => {
                return self.directory_input(io, purpose, arrival, now_ms);
            }
            (_, Arrival::Input(input)) => input,
            (_, Arrival::Frame(_)) => return Err(CloudDeviceError::Protocol),
        };
        match purpose {
            Purpose::Seats => {
                self.seats = Seats::Answered;
                let seats = match input {
                    Input::Instances(seats) => seats,
                    Input::Failed(_) => Vec::new(),
                    _ => return Err(CloudDeviceError::Protocol),
                };
                io.output(ChatListUpdate::Seats(seats));
            }
            Purpose::Sign(index) => {
                let keys = self.session.keys().clone();
                let scan = self.scan(index)?;
                let probe = scan.probe.as_mut().ok_or(CloudDeviceError::Protocol)?;
                match probe.signed(&keys, input) {
                    Ok(request) => {
                        io.issue(Purpose::Probe(index), Effect::Probe(request));
                    }
                    Err(error) => {
                        scan.probe = None;
                        self.unreachable(io, index, Some(error));
                    }
                }
            }
            Purpose::Probe(index) => self.answered(io, index, input, now_ms)?,
            Purpose::Replay(_) | Purpose::Watch(_) => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn tick(&mut self, io: &mut ListIo, now_ms: i64) -> Result<Wait, CloudDeviceError> {
        let mut busy = false;
        if self.seats == Seats::Unasked {
            self.seats = Seats::Asked;
            io.issue(Purpose::Seats, Effect::ListInstances);
            busy = true;
        }
        for index in 0..self.scans.len() {
            if self.scans[index].catalog == CatalogState::Unstarted {
                self.probe(io, index, now_ms)?;
                busy = true;
            }
            if let Some(directory) = self.scans[index].directory.as_mut() {
                busy |= directory.tick(io, index, now_ms);
            }
        }
        if busy {
            return Ok(Wait::Busy);
        }
        let settled = self.scans.iter().all(|scan| {
            scan.resolved() && scan.directory.as_ref().is_none_or(DirectoryScan::settled)
        });
        if self.seats == Seats::Answered && settled && !self.live {
            return Ok(Wait::Done);
        }
        let wake = self
            .scans
            .iter()
            .filter_map(|scan| scan.directory.as_ref()?.wake_at())
            .min();
        Ok(Wait::Idle(wake))
    }
}

#[cfg(test)]
mod tests;
