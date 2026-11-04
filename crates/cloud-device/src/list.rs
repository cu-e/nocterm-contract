//! The `ListChats` flow: every trusted runner's chat catalog, witnessed fresh, without replay.
//!
//! Each runner is probed for its catalog (at most [`MAX_CATALOG_PAGES`] pages) at the same time,
//! and the account's seats are listed to tell managed agents from own runners. Every runner
//! reports on its own as soon as it answered, so a sleeping seat does not hold back the others:
//! [`ChatListUpdate::Runner`] with its chats, or [`ChatListUpdate::Unreachable`]. Rows carry no
//! title: the catalog witnesses heads, not content (a runner chat directory adds summaries).
use crate::{
    CloudDeviceError, DeviceIdentity,
    context::{ChatRef, CloudSession},
    flow::{
        Arrival, Driven, Effect, EffectId, Flow, Frame, Input, InstanceEntry, Io, Machine, Step,
        Wait,
    },
    probe::{ProbeCall, ProbeTarget},
    records::TrustedRunner,
};
use nocterm_hub_model::cloud::head::{CatalogHeadCursor, ChatHead, HeadValue};
use std::sync::Arc;

/// Catalog pages read per runner (64 chats each).
pub const MAX_CATALOG_PAGES: u32 = 8;

/// One witnessed chat of a runner. Plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedChat {
    pub chat: ChatRef,
    pub control_revision: u64,
    /// The sequence of the newest record, `None` for a chat without records.
    pub head_sequence: Option<u64>,
    pub deleted: bool,
    pub witnessed_at_ms: i64,
}
impl ListedChat {
    fn of(runner: [u8; 16], head: &ChatHead, at_ms: i64) -> Self {
        Self {
            chat: ChatRef {
                runner,
                chat_id: head.chat_id,
                key_epoch: head.chat_key_epoch,
            },
            control_revision: head.control_revision,
            head_sequence: head.head.as_ref().map(|anchor| anchor.position.sequence),
            deleted: head.deleted,
            witnessed_at_ms: at_ms,
        }
    }
}

/// What a listing reports, runner by runner.
#[derive(Debug)]
pub enum ChatListUpdate {
    /// The account's seats (agent instances), to name the agent of a runner.
    Seats(Vec<InstanceEntry>),
    /// A runner witnessed its catalog; `complete` is false when it has more pages than read.
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
                runner: runner.clone(),
                probe: None,
                pages: 0,
                after: None,
                chats: Vec::new(),
                started: false,
                done: false,
            })
            .collect();
        Self(Driven::new(Listing {
            session,
            device,
            scans,
            seats: Seats::Unasked,
        }))
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
}

#[derive(Debug, PartialEq, Eq)]
enum Seats {
    Unasked,
    Asked,
    Answered,
}

#[derive(Debug)]
struct Scan {
    runner: TrustedRunner,
    probe: Option<ProbeCall>,
    pages: u32,
    after: Option<CatalogHeadCursor>,
    chats: Vec<ListedChat>,
    started: bool,
    done: bool,
}

#[derive(Debug)]
pub(crate) struct Listing {
    session: Arc<CloudSession>,
    device: DeviceIdentity,
    scans: Vec<Scan>,
    seats: Seats,
}
type ListIo = Io<Purpose, ChatListUpdate>;

impl Listing {
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
        scan.started = true;
        io.issue(Purpose::Sign(index), Effect::Sign(request));
        Ok(())
    }
    fn unreachable(&mut self, io: &mut ListIo, index: usize, reason: Option<CloudDeviceError>) {
        let scan = &mut self.scans[index];
        scan.done = true;
        io.output(ChatListUpdate::Unreachable {
            runner: scan.runner.clone(),
            reason,
        });
    }
    fn answered(
        &mut self,
        io: &mut ListIo,
        index: usize,
        input: Input,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let scan = self
            .scans
            .get_mut(index)
            .ok_or(CloudDeviceError::Protocol)?;
        let mut probe = scan.probe.take().ok_or(CloudDeviceError::Protocol)?;
        let page = match probe.answered(self.session.keys(), input, now_ms) {
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
        let runner = scan.runner.runner().id;
        scan.chats.extend(
            page.chats
                .iter()
                .map(|head| ListedChat::of(runner, head, now_ms)),
        );
        scan.pages += 1;
        scan.after = page.next_cursor();
        if scan.after.is_some() && scan.pages < MAX_CATALOG_PAGES {
            return self.probe(io, index, now_ms);
        }
        scan.done = true;
        io.output(ChatListUpdate::Runner {
            runner: scan.runner.clone(),
            chats: std::mem::take(&mut scan.chats),
            complete: scan.after.is_none(),
        });
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
        let Arrival::Input(input) = arrival else {
            return Err(CloudDeviceError::Protocol);
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
                let scan = self
                    .scans
                    .get_mut(index)
                    .ok_or(CloudDeviceError::Protocol)?;
                let probe = scan.probe.as_mut().ok_or(CloudDeviceError::Protocol)?;
                match probe.signed(self.session.keys(), input) {
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
            if !self.scans[index].started {
                self.probe(io, index, now_ms)?;
                busy = true;
            }
        }
        if busy {
            return Ok(Wait::Busy);
        }
        if self.seats == Seats::Answered && self.scans.iter().all(|scan| scan.done) {
            return Ok(Wait::Done);
        }
        Ok(Wait::Idle(None))
    }
}

#[cfg(test)]
mod tests;
