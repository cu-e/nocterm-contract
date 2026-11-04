//! The `Deliver` flow: one command from signature to a settled outcome.
//!
//! 1. A managed seat is woken first when the caller names its agent (`StartInstance` for the
//!    chat), so a sleeping seat receives the command; a refusal to wake does not stop delivery.
//! 2. The device signs the command header; the command is sealed once.
//! 3. The sealed publication is published with `PublishOne`. Every retry sends exactly the same
//!    bytes under the same publication id, so the hub delivers it at most once.
//! 4. A receipt that names the publication settles it as `Delivered`. A refusal settles it as
//!    `Refused`. An unknown outcome (nothing came back) is retried with backoff; every third
//!    attempt the runner is asked whether it admitted the command (a receipt probe): `Accepted`
//!    and `Conflict` settle it, `NotFound` republishes at once. When the command's admission
//!    window ends it is `Unreachable`.
use super::{SealedCommand, UnsignedCommand};
use crate::{
    CloudDeviceError, DeviceIdentity,
    context::CloudSession,
    flow::{
        Arrival, Driven, Effect, EffectFailure, EffectId, Flow, Frame, Input, Io, Machine, Step,
        Wait,
    },
    probe::{ProbeCall, ProbeTarget},
    records::ChatSelector,
    transcript::CommandState,
};
use nocterm_hub_model::cloud::head::{HeadValue, ReceiptOutcome};
use std::sync::Arc;

/// The longest wait between two attempts.
pub const MAX_RETRY_DELAY_MS: i64 = 15_000;
/// Attempts between two receipt probes.
pub const RECEIPT_PROBE_EVERY: u32 = 3;

/// A settled or advanced delivery state of one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryUpdate {
    pub command_id: [u8; 16],
    pub state: CommandState,
    /// The hub's delivery cursor, once a receipt named it.
    pub cursor: Option<u64>,
}

/// The `Deliver` flow of one prepared command.
#[derive(Debug)]
pub struct Deliver(Driven<Delivery>);
impl Deliver {
    /// `wake` names the managed agent whose seat serves this chat.
    pub fn new(
        session: Arc<CloudSession>,
        device: DeviceIdentity,
        selector: ChatSelector,
        command: UnsignedCommand,
        wake: Option<String>,
    ) -> Self {
        Self(Driven::new(Delivery {
            session,
            device,
            command_id: command.command_id(),
            selector,
            command: Some(command),
            sealed: None,
            probe: None,
            wake,
            attempts: 0,
            phase: Phase::Start,
        }))
    }
    pub fn command_id(&self) -> [u8; 16] {
        self.0.machine().command_id
    }
}
impl Flow for Deliver {
    type Output = DeliveryUpdate;
    fn next(&mut self, now_ms: i64) -> Step<DeliveryUpdate> {
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
enum Phase {
    Start,
    Waiting(i64),
    Busy,
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    Wake,
    Sign,
    Publish,
    ReceiptSign,
    Receipt,
}

#[derive(Debug)]
pub(crate) struct Delivery {
    session: Arc<CloudSession>,
    device: DeviceIdentity,
    selector: ChatSelector,
    command_id: [u8; 16],
    command: Option<UnsignedCommand>,
    sealed: Option<SealedCommand>,
    probe: Option<ProbeCall>,
    wake: Option<String>,
    attempts: u32,
    phase: Phase,
}
impl Delivery {
    fn settle(
        &mut self,
        io: &mut Io<Purpose, DeliveryUpdate>,
        state: CommandState,
        cursor: Option<u64>,
    ) {
        io.output(DeliveryUpdate {
            command_id: self.command_id,
            state,
            cursor,
        });
        self.phase = Phase::Finished;
    }
    fn sign(&mut self, io: &mut Io<Purpose, DeliveryUpdate>) -> Result<(), CloudDeviceError> {
        let command = self.command.as_ref().ok_or(CloudDeviceError::Protocol)?;
        io.issue(Purpose::Sign, Effect::Sign(command.sign_request()?));
        self.phase = Phase::Busy;
        Ok(())
    }
    fn sealed(&self) -> Result<&SealedCommand, CloudDeviceError> {
        self.sealed.as_ref().ok_or(CloudDeviceError::Protocol)
    }
    fn retry(&mut self, now_ms: i64) {
        self.attempts += 1;
        let exponent = self.attempts.saturating_sub(1).min(4);
        let delay = (1_000_i64 << exponent).min(MAX_RETRY_DELAY_MS);
        self.phase = Phase::Waiting(now_ms.saturating_add(delay));
    }
    fn receipt_probe(
        &mut self,
        io: &mut Io<Purpose, DeliveryUpdate>,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let sealed = self.sealed()?;
        let target = ProbeTarget::CommandReceipt {
            chat_id: self.selector.chat_id(),
            key_epoch: self.selector.key_epoch(),
            command_id: self.command_id,
            semantic_digest: sealed.semantic_digest(),
            expected_control_revision: sealed.expected_control_revision(),
        };
        let runner = self.session.runner(&self.selector.runner().id)?;
        let (probe, request) =
            ProbeCall::start(&self.session, &self.device, runner, target, now_ms)?;
        self.probe = Some(probe);
        io.issue(Purpose::ReceiptSign, Effect::Sign(request));
        self.phase = Phase::Busy;
        Ok(())
    }
    fn publish(&mut self, io: &mut Io<Purpose, DeliveryUpdate>) -> Result<(), CloudDeviceError> {
        let publication = self.sealed()?.publication().clone();
        io.issue(Purpose::Publish, Effect::Publish(publication));
        self.phase = Phase::Busy;
        Ok(())
    }
    fn published(
        &mut self,
        io: &mut Io<Purpose, DeliveryUpdate>,
        input: Input,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        match input {
            Input::Receipt {
                publication_id,
                cursor,
                ciphertext_sha256,
            } if self.sealed()?.publication().is_receipt(
                &publication_id,
                cursor,
                &ciphertext_sha256,
            ) =>
            {
                self.settle(io, CommandState::Delivered, Some(cursor));
            }
            Input::Receipt { .. }
            | Input::Failed(EffectFailure::Unavailable | EffectFailure::Unknown) => {
                self.retry(now_ms);
            }
            Input::Failed(_) => self.settle(io, CommandState::Refused, None),
            _ => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn receipt(
        &mut self,
        io: &mut Io<Purpose, DeliveryUpdate>,
        input: Input,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let mut probe = self.probe.take().ok_or(CloudDeviceError::Protocol)?;
        match probe.answered(self.session.keys(), input, now_ms) {
            Ok(Some(HeadValue::CommandReceipt(ReceiptOutcome::NotFound))) => {
                self.phase = Phase::Waiting(now_ms);
            }
            Ok(Some(HeadValue::CommandReceipt(ReceiptOutcome::Accepted { .. }))) => {
                self.settle(io, CommandState::Accepted, None);
            }
            Ok(Some(HeadValue::CommandReceipt(ReceiptOutcome::Conflict))) => {
                self.settle(io, CommandState::Refused, None);
            }
            // An unknown outcome, no answer, or a witness that does not verify: keep trying
            // the same bytes until the admission window ends.
            _ => self.retry(now_ms),
        }
        Ok(())
    }
}
impl Machine for Delivery {
    type Purpose = Purpose;
    type Output = DeliveryUpdate;
    fn handle(
        &mut self,
        io: &mut Io<Purpose, DeliveryUpdate>,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let Arrival::Input(input) = arrival else {
            return Err(CloudDeviceError::Protocol);
        };
        match purpose {
            Purpose::Wake => self.sign(io),
            Purpose::Sign => {
                let Input::Signature(signature) = input else {
                    return Err(CloudDeviceError::Protocol);
                };
                let command = self.command.take().ok_or(CloudDeviceError::Protocol)?;
                self.sealed = Some(command.seal(
                    self.session.keys().pair(),
                    &signature,
                    self.session.capabilities(),
                )?);
                self.publish(io)
            }
            Purpose::Publish => self.published(io, input, now_ms),
            Purpose::ReceiptSign => {
                let probe = self.probe.as_mut().ok_or(CloudDeviceError::Protocol)?;
                let request = probe.signed(self.session.keys(), input)?;
                io.issue(Purpose::Receipt, Effect::Probe(request));
                Ok(())
            }
            Purpose::Receipt => self.receipt(io, input, now_ms),
        }
    }
    fn tick(
        &mut self,
        io: &mut Io<Purpose, DeliveryUpdate>,
        now_ms: i64,
    ) -> Result<Wait, CloudDeviceError> {
        match self.phase {
            Phase::Start => {
                if let Some(agent_id) = self.wake.take() {
                    io.issue(
                        Purpose::Wake,
                        Effect::StartInstance {
                            agent_id,
                            chat_id: Some(hex::encode(self.selector.chat_id())),
                        },
                    );
                    self.phase = Phase::Busy;
                } else {
                    self.sign(io)?;
                }
                Ok(Wait::Busy)
            }
            Phase::Waiting(_) if now_ms >= self.sealed()?.accept_before_ms() => {
                self.settle(io, CommandState::Unreachable, None);
                Ok(Wait::Busy)
            }
            Phase::Waiting(until) if now_ms >= until => {
                if self.attempts > 0 && self.attempts.is_multiple_of(RECEIPT_PROBE_EVERY) {
                    self.attempts += 1;
                    self.receipt_probe(io, now_ms)?;
                } else {
                    self.publish(io)?;
                }
                Ok(Wait::Busy)
            }
            Phase::Waiting(until) => Ok(Wait::Idle(Some(until))),
            Phase::Busy => Ok(Wait::Idle(None)),
            Phase::Finished => Ok(Wait::Done),
        }
    }
}

#[cfg(test)]
mod tests;
