//! Waking a managed agent's seat (ADR 0122 and 0133 of the native client, in the core since
//! contract ADR 0010).
//!
//! A chat never provisions a seat. The core lists the caller's seats ([`Effect::ListInstances`]),
//! picks the agent's enrolled one ([`hosting_seat`]) and asks to start exactly that seat's pool
//! ([`Effect::StartInstance`] with its `pool_id`), so a client sends the call as it is and never
//! chooses a pool. An agent without an enrolled seat is [`CloudDeviceError::NotEnrolled`]: it is
//! started first, outside any chat, which enrols its runner. [`WakeSeat`] is the flow of an
//! explicit Wake; `Deliver` and `CreateChat` take the same steps themselves.
use crate::{
    CloudDeviceError,
    flow::{
        Arrival, Driven, Effect, EffectId, Flow, Frame, Input, InstanceEntry, InstanceState, Io,
        Machine, Step, Wait,
    },
};

/// The agent's seat that hosts its chats: it has a runner and a pool and is neither being
/// deleted, failed nor waiting for enrolment. A ready seat is preferred over a sleeping one.
pub fn hosting_seat<'a>(seats: &'a [InstanceEntry], agent_id: &str) -> Option<&'a InstanceEntry> {
    let hosting = |seat: &&InstanceEntry| {
        seat.agent_id == agent_id
            && seat.runner_id.is_some()
            && !seat.pool_id.is_empty()
            && !matches!(
                seat.state,
                InstanceState::Deleting | InstanceState::Failed | InstanceState::AwaitingEnrolment
            )
    };
    let mut candidates = seats.iter().filter(hosting);
    let first = candidates.clone().next()?;
    Some(
        candidates
            .find(|seat| seat.state == InstanceState::Ready)
            .unwrap_or(first),
    )
}

/// The `StartInstance` effect that wakes the hosting seat of `agent_id` for `chat_id`.
pub(crate) fn start(
    seats: &[InstanceEntry],
    agent_id: &str,
    chat_id: Option<[u8; 16]>,
) -> Result<Effect, CloudDeviceError> {
    let seat = hosting_seat(seats, agent_id).ok_or(CloudDeviceError::NotEnrolled)?;
    Ok(Effect::StartInstance {
        agent_id: seat.agent_id.clone(),
        pool_id: seat.pool_id.clone(),
        chat_id: chat_id.map(hex::encode),
    })
}

/// The seats of a `ListInstances` answer; a refusal is an effect failure.
pub(crate) fn listed(input: Input) -> Result<Vec<InstanceEntry>, CloudDeviceError> {
    match input {
        Input::Instances(seats) => Ok(seats),
        Input::Failed(failure) => Err(CloudDeviceError::Effect(failure)),
        _ => Err(CloudDeviceError::Protocol),
    }
}

/// Wakes the enrolled seat of a managed agent, for a chat when one is named: outputs the
/// started seat once, then is done.
#[derive(Debug)]
pub struct WakeSeat(Driven<Waking>);
impl WakeSeat {
    pub fn new(agent_id: impl Into<String>, chat_id: Option<[u8; 16]>) -> Self {
        Self(Driven::new(Waking {
            agent_id: agent_id.into(),
            chat_id,
            asked: false,
            finished: false,
        }))
    }
}
impl Flow for WakeSeat {
    type Output = InstanceEntry;
    fn next(&mut self, now_ms: i64) -> Step<InstanceEntry> {
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
    Start,
}

#[derive(Debug)]
pub(crate) struct Waking {
    agent_id: String,
    chat_id: Option<[u8; 16]>,
    asked: bool,
    finished: bool,
}
impl Machine for Waking {
    type Purpose = Purpose;
    type Output = InstanceEntry;
    fn handle(
        &mut self,
        io: &mut Io<Purpose, InstanceEntry>,
        purpose: Purpose,
        arrival: Arrival,
        _now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let Arrival::Input(input) = arrival else {
            return Err(CloudDeviceError::Protocol);
        };
        match (purpose, input) {
            (Purpose::Seats, input) => {
                let seats = listed(input)?;
                io.issue(Purpose::Start, start(&seats, &self.agent_id, self.chat_id)?);
            }
            (Purpose::Start, Input::Instance(seat)) => {
                io.output(seat);
                self.finished = true;
            }
            (Purpose::Start, Input::Failed(failure)) => {
                return Err(CloudDeviceError::Effect(failure));
            }
            (Purpose::Start, _) => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn tick(
        &mut self,
        io: &mut Io<Purpose, InstanceEntry>,
        _now_ms: i64,
    ) -> Result<Wait, CloudDeviceError> {
        if self.finished {
            return Ok(Wait::Done);
        }
        if !std::mem::replace(&mut self.asked, true) {
            io.issue(Purpose::Seats, Effect::ListInstances);
            return Ok(Wait::Busy);
        }
        Ok(Wait::Idle(None))
    }
}

#[cfg(test)]
mod tests;
