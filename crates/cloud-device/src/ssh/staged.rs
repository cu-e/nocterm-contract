//! A flow in two stages: a preparation machine that ends with one update and a command, then
//! the [`Deliver`] flow of that command. Effect ids of the second stage follow those of the
//! first, so the client sees one flow with unique ids.
use super::{Preparing, SshUpdate};
use crate::{
    CloudDeviceError, DeviceIdentity,
    command::{Deliver, UnsignedCommand},
    context::CloudSession,
    flow::{Driven, EffectId, Flow, Frame, Input, Step},
    records::ChatSelector,
};
use std::sync::Arc;

/// What a preparation hands to delivery.
pub(super) type Prepared = (SshUpdate, UnsignedCommand);

#[derive(Debug)]
pub(super) struct Staged {
    prepare: Driven<Preparing>,
    /// The highest effect id the preparation issued.
    last_id: EffectId,
    deliver: Option<Deliver>,
    route: Option<Route>,
    protocol: bool,
}

/// Where the command goes once it is prepared.
#[derive(Debug)]
pub(super) struct Route {
    pub(super) session: Arc<CloudSession>,
    pub(super) device: DeviceIdentity,
    pub(super) selector: ChatSelector,
    pub(super) wake: Option<String>,
}

impl Staged {
    pub(super) fn new(machine: Preparing, route: Route) -> Self {
        Self {
            prepare: Driven::new(machine),
            last_id: 0,
            deliver: None,
            route: Some(route),
            protocol: false,
        }
    }
}

impl Flow for Staged {
    type Output = SshUpdate;
    fn next(&mut self, now_ms: i64) -> Step<SshUpdate> {
        if std::mem::take(&mut self.protocol) {
            self.deliver = None;
            self.route = None;
            return Step::Failed(CloudDeviceError::Protocol);
        }
        if let Some(deliver) = &mut self.deliver {
            return match deliver.next(now_ms) {
                Step::Effect(id, effect) => Step::Effect(id + self.last_id, effect),
                Step::Output(update) => Step::Output(SshUpdate::Delivery(update)),
                Step::Idle { until_ms } => Step::Idle { until_ms },
                Step::Done => Step::Done,
                Step::Failed(error) => Step::Failed(error),
            };
        }
        match self.prepare.next(now_ms) {
            Step::Effect(id, effect) => {
                self.last_id = self.last_id.max(id);
                Step::Effect(id, effect)
            }
            Step::Output((update, command)) => {
                let Some(route) = self.route.take() else {
                    return Step::Failed(CloudDeviceError::Protocol);
                };
                self.deliver = Some(Deliver::new(
                    route.session,
                    route.device,
                    route.selector,
                    command,
                    route.wake,
                ));
                Step::Output(update)
            }
            Step::Idle { until_ms } => Step::Idle { until_ms },
            // A preparation ends only by handing over its command.
            Step::Done => Step::Failed(CloudDeviceError::Protocol),
            Step::Failed(error) => Step::Failed(error),
        }
    }
    fn resolve(&mut self, id: EffectId, input: Input) {
        match &mut self.deliver {
            Some(deliver) if id > self.last_id => deliver.resolve(id - self.last_id, input),
            Some(_) => self.protocol = true,
            None => self.prepare.resolve(id, input),
        }
    }
    fn frame(&mut self, id: EffectId, frame: Frame) {
        match &mut self.deliver {
            Some(deliver) if id > self.last_id => deliver.frame(id - self.last_id, frame),
            Some(_) => self.protocol = true,
            None => self.prepare.frame(id, frame),
        }
    }
}
