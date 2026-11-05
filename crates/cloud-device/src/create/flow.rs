//! The `CreateChat` flow (ADR 0122 of the native client, now in the core for every device).
//!
//! 1. A managed agent's enrolled seat is started for the new chat ([`crate::seat`]:
//!    `ListInstances`, then `StartInstance` of that seat's pool with the chat id); an agent
//!    without one is [`CloudDeviceError::NotEnrolled`], and no seat is ever provisioned for a
//!    chat. An own runner is named directly. A runner missing from the
//!    registry makes the flow read the registry again once.
//! 2. The chat material is compare-created (`PutObject` at version 0) in `cloud-chat-material`,
//!    then the sealed grant in `cloud-chat-grant`; a missing personal collection is created
//!    first. Records another device stored (it won, or this is a retry with the same chat id)
//!    are used instead, and no second grant is sealed for a stored one.
//! 3. The stored grant is published to the runner inbox, always as the same publication.
//! 4. The flow probes the chat every [`CLAIM_RETRY_MS`] until the runner witnesses it,
//!    republishes every [`CLAIM_REPUBLISH_MS`], and gives up after [`CLAIM_PATIENCE_MS`]
//!    ([`CloudDeviceError::NotClaimed`]; the chat appears once the runner takes it).
use super::{NewChat, grant_for_material, grant_publication};
use crate::{
    CloudDeviceError, DeviceIdentity,
    command::Publication,
    context::{ChatRef, CloudSession},
    discover::{open_registry, view},
    flow::{
        Arrival, Driven, Effect, EffectFailure, EffectId, Flow, Frame, Input, InstanceState, Io,
        Machine, Step, Wait,
    },
    probe::{ProbeCall, ProbeTarget},
    records::{
        CHAT_GRANT_KIND, CHAT_MATERIAL_KIND, ChatGrantRecord, ChatMaterialRecord, ChatSelector,
        RUNNER_REGISTRY_OBJECT, RunnerRegistry, TrustedRunner,
    },
};
use nocterm_hub_model::cloud::head::HeadValue;
use nocterm_keys::CollectionKey;
use std::sync::Arc;

/// How long a new chat waits for its runner's claim.
pub const CLAIM_PATIENCE_MS: i64 = 60_000;
/// How often the grant is published again while waiting.
pub const CLAIM_REPUBLISH_MS: i64 = 15_000;
/// How long between two claim probes.
pub const CLAIM_RETRY_MS: i64 = 1_000;

/// Where the new chat runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatHost {
    /// A managed agent: its seat is started for the chat.
    Managed { agent_id: String },
    /// One of the account's own enrolled runners.
    Own { runner: [u8; 16] },
}

/// A chat the runner took.
#[derive(Debug)]
pub struct CreatedChat {
    pub chat: ChatRef,
    /// The seat started for it.
    pub instance_id: Option<String>,
    /// The trusted runners, when the registry had to be read again.
    pub runners: Option<Vec<TrustedRunner>>,
}

/// The `CreateChat` flow.
#[derive(Debug)]
pub struct CreateChat(Driven<Creating>);
impl CreateChat {
    /// `chat_id` repeats an earlier attempt; `None` makes a fresh one.
    pub fn new(
        session: Arc<CloudSession>,
        device: DeviceIdentity,
        host: ChatHost,
        chat_id: Option<[u8; 16]>,
    ) -> Result<Self, CloudDeviceError> {
        let chat_id = match chat_id {
            Some(id) => id,
            None => super::new_chat_id()?,
        };
        let runner = match &host {
            ChatHost::Own { runner } => Some(*runner),
            ChatHost::Managed { .. } => None,
        };
        Ok(Self(Driven::new(Creating {
            session,
            device,
            host,
            chat_id,
            runner,
            instance_id: None,
            reloaded: None,
            records: Records::default(),
            publication: None,
            claim: Claim::default(),
            finished: false,
        })))
    }
    pub fn chat_id(&self) -> [u8; 16] {
        self.0.machine().chat_id
    }
}
impl Flow for CreateChat {
    type Output = CreatedChat;
    fn next(&mut self, now_ms: i64) -> Step<CreatedChat> {
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
pub(crate) enum Kind {
    Material,
    Grant,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Material => CHAT_MATERIAL_KIND,
            Self::Grant => CHAT_GRANT_KIND,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Purpose {
    Seats,
    Seat,
    RegistryKey,
    RegistryObject(Vec<u8>),
    Key(Kind),
    CreateCollection(Kind),
    Object(Kind),
    PutMaterial(Box<ChatMaterialRecord>),
    PutGrant(Box<ChatGrantRecord>),
    Publish,
    ClaimSign,
    Claim,
}

#[derive(Debug, Default)]
struct Records {
    material_key: Option<CollectionKey>,
    grant_key: Option<CollectionKey>,
    material: Option<ChatMaterialRecord>,
    /// The grant sealed with a fresh chat key, stored after its material.
    fresh_grant: Option<ChatGrantRecord>,
    grant: Option<ChatGrantRecord>,
}

#[derive(Debug, Default)]
struct Claim {
    first_published_at: Option<i64>,
    last_published_at: i64,
    next_probe_at: i64,
    retry_publish_at: Option<i64>,
    probe: Option<ProbeCall>,
}

#[derive(Debug)]
pub(crate) struct Creating {
    session: Arc<CloudSession>,
    device: DeviceIdentity,
    host: ChatHost,
    chat_id: [u8; 16],
    runner: Option<[u8; 16]>,
    instance_id: Option<String>,
    reloaded: Option<Vec<TrustedRunner>>,
    records: Records,
    publication: Option<Publication>,
    claim: Claim,
    finished: bool,
}
type CreateIo = Io<Purpose, CreatedChat>;

impl Creating {
    fn runner(&self) -> Result<&TrustedRunner, CloudDeviceError> {
        self.session
            .runner(&self.runner.ok_or(CloudDeviceError::Protocol)?)
    }
    fn selector(&self) -> Result<ChatSelector, CloudDeviceError> {
        let runner = self.runner()?;
        ChatSelector::new(
            self.session.scope().clone(),
            runner.runner(),
            self.chat_id,
            super::FIRST_KEY_EPOCH,
            runner.pins(),
        )
    }
    fn collection(&self, kind: Kind) -> Result<String, CloudDeviceError> {
        crate::records::account_collection_id(self.session.scope(), kind.name())
    }
    fn key(&self, kind: Kind) -> Option<&CollectionKey> {
        match kind {
            Kind::Material => self.records.material_key.as_ref(),
            Kind::Grant => self.records.grant_key.as_ref(),
        }
    }
    fn get_object(&self, io: &mut CreateIo, kind: Kind) -> Result<(), CloudDeviceError> {
        io.issue(
            Purpose::Object(kind),
            Effect::GetObject {
                collection_id: self.collection(kind)?,
                object_id: self.selector()?.object_id()?,
            },
        );
        Ok(())
    }
    fn put(
        &self,
        io: &mut CreateIo,
        kind: Kind,
        ciphertext: Vec<u8>,
        purpose: Purpose,
    ) -> Result<(), CloudDeviceError> {
        io.issue(
            purpose,
            Effect::PutObject {
                collection_id: self.collection(kind)?,
                object_id: self.selector()?.object_id()?,
                kind: kind.name().to_owned(),
                expected_version: 0,
                ciphertext,
            },
        );
        Ok(())
    }
    /// A collection key arrived, or the collection is missing and is created.
    fn keyed(
        &mut self,
        io: &mut CreateIo,
        kind: Kind,
        input: Input,
    ) -> Result<(), CloudDeviceError> {
        let collection = self.collection(kind)?;
        match input {
            Input::CollectionKey {
                wrapped_key,
                granted_by,
            } if granted_by.is_empty() => {
                let key =
                    CollectionKey::open(self.session.keys().account(), &collection, &wrapped_key)?;
                match kind {
                    Kind::Material => self.records.material_key = Some(key),
                    Kind::Grant => self.records.grant_key = Some(key),
                }
            }
            Input::CollectionKey { .. } => return Err(CloudDeviceError::Binding),
            Input::Failed(EffectFailure::NotFound) => {
                let key = CollectionKey::generate()?;
                io.issue(
                    Purpose::CreateCollection(kind),
                    Effect::CreateCollection {
                        wrapped_key: key.seal_for(self.session.keys().account(), &collection)?,
                        sealed_name: key.seal_name(&collection, kind.name())?,
                        collection_id: collection,
                        kind: kind.name().to_owned(),
                    },
                );
            }
            Input::Failed(failure) => return Err(CloudDeviceError::Effect(failure)),
            _ => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn material(&mut self, io: &mut CreateIo, input: Input) -> Result<(), CloudDeviceError> {
        let keys = self.session.keys().clone();
        let key = self.key(Kind::Material).ok_or(CloudDeviceError::Protocol)?;
        match input {
            Input::Object(object) => {
                let record = ChatMaterialRecord::open(
                    key,
                    self.selector()?,
                    &view(&object),
                    keys.account(),
                )?;
                self.records.material = Some(record);
            }
            Input::Failed(EffectFailure::NotFound) => {
                let fresh = NewChat::create(
                    self.session.scope(),
                    self.runner()?,
                    self.chat_id,
                    keys.account(),
                    keys.pair(),
                )?;
                let sealed = fresh.material().seal(key)?;
                self.records.fresh_grant = Some(fresh.grant().clone());
                let purpose = Purpose::PutMaterial(Box::new(fresh.material().clone()));
                self.put(io, Kind::Material, sealed, purpose)?;
            }
            Input::Failed(failure) => return Err(CloudDeviceError::Effect(failure)),
            _ => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn grant(&mut self, io: &mut CreateIo, input: Input) -> Result<(), CloudDeviceError> {
        let selector = self.selector()?;
        match input {
            Input::Object(object) => {
                let key = self.key(Kind::Grant).ok_or(CloudDeviceError::Protocol)?;
                self.records.grant = Some(ChatGrantRecord::open(key, &selector, &view(&object))?);
            }
            Input::Failed(EffectFailure::NotFound) => {
                let grant = if let Some(grant) = self.records.fresh_grant.take() {
                    grant
                } else {
                    let material = self
                        .records
                        .material
                        .as_ref()
                        .ok_or(CloudDeviceError::Protocol)?;
                    let keys = self.session.keys();
                    grant_for_material(material, self.runner()?, keys.account(), keys.pair())?
                };
                let key = self.key(Kind::Grant).ok_or(CloudDeviceError::Protocol)?;
                let sealed = grant.seal(key, &selector)?;
                self.put(io, Kind::Grant, sealed, Purpose::PutGrant(Box::new(grant)))?;
            }
            Input::Failed(failure) => return Err(CloudDeviceError::Effect(failure)),
            _ => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn stored(
        &mut self,
        io: &mut CreateIo,
        purpose: Purpose,
        input: Input,
    ) -> Result<(), CloudDeviceError> {
        match (purpose, input) {
            (Purpose::PutMaterial(record), Input::Stored { .. }) => {
                self.records.material = Some(*record);
            }
            (Purpose::PutGrant(record), Input::Stored { .. }) => self.records.grant = Some(*record),
            // Another device stored its record first: read and use that one.
            (
                Purpose::PutMaterial(_),
                Input::Failed(EffectFailure::Conflict | EffectFailure::AlreadyExists),
            ) => {
                self.records.fresh_grant = None;
                self.get_object(io, Kind::Material)?;
            }
            (
                Purpose::PutGrant(_),
                Input::Failed(EffectFailure::Conflict | EffectFailure::AlreadyExists),
            ) => {
                self.get_object(io, Kind::Grant)?;
            }
            (_, Input::Failed(failure)) => return Err(CloudDeviceError::Effect(failure)),
            _ => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn seat(&mut self, input: Input) -> Result<(), CloudDeviceError> {
        let Input::Instance(seat) = input else {
            return Err(match input {
                Input::Failed(failure) => CloudDeviceError::Effect(failure),
                _ => CloudDeviceError::Protocol,
            });
        };
        match (seat.state, seat.runner_id) {
            (InstanceState::AwaitingEnrolment | InstanceState::Failed, _) | (_, None) => {
                Err(CloudDeviceError::NotEnrolled)
            }
            (_, Some(runner)) => {
                self.runner = Some(runner);
                self.instance_id = Some(seat.instance_id);
                Ok(())
            }
        }
    }
    fn registry(
        &mut self,
        io: &mut CreateIo,
        purpose: Purpose,
        input: Input,
    ) -> Result<(), CloudDeviceError> {
        let runners = match (purpose, input) {
            (Purpose::RegistryKey, Input::CollectionKey { wrapped_key, .. }) => {
                io.issue(
                    Purpose::RegistryObject(wrapped_key),
                    Effect::GetObject {
                        collection_id: RunnerRegistry::collection_id(self.session.scope())?,
                        object_id: RUNNER_REGISTRY_OBJECT.to_owned(),
                    },
                );
                return Ok(());
            }
            (Purpose::RegistryObject(wrapped), Input::Object(object)) => {
                open_registry(self.session.keys(), self.session.hub(), &wrapped, &object)?
            }
            (_, Input::Failed(EffectFailure::NotFound)) => Vec::new(),
            (_, Input::Failed(failure)) => return Err(CloudDeviceError::Effect(failure)),
            _ => return Err(CloudDeviceError::Protocol),
        };
        self.session = Arc::new(self.session.with_runners(runners.clone()));
        self.reloaded = Some(runners);
        Ok(())
    }
    fn claim_probe(&mut self, io: &mut CreateIo, now_ms: i64) -> Result<(), CloudDeviceError> {
        let target = ProbeTarget::Chat {
            chat_id: self.chat_id,
            key_epoch: super::FIRST_KEY_EPOCH,
        };
        let (probe, request) =
            ProbeCall::start(&self.session, &self.device, self.runner()?, target, now_ms)?;
        self.claim.probe = Some(probe);
        io.issue(Purpose::ClaimSign, Effect::Sign(request));
        Ok(())
    }
    fn claimed(
        &mut self,
        io: &mut CreateIo,
        input: Input,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let mut probe = self.claim.probe.take().ok_or(CloudDeviceError::Protocol)?;
        self.claim.next_probe_at = now_ms.saturating_add(CLAIM_RETRY_MS);
        if let Ok(Some(HeadValue::Chat(_))) = probe.answered(self.session.keys(), input, now_ms) {
            let chat = ChatRef::of(&self.selector()?);
            io.output(CreatedChat {
                chat,
                instance_id: self.instance_id.take(),
                runners: self.reloaded.take(),
            });
            self.finished = true;
        }
        Ok(())
    }
    fn publish(&mut self, io: &mut CreateIo, now_ms: i64) -> Result<(), CloudDeviceError> {
        if self.publication.is_none() {
            let grant = self
                .records
                .grant
                .as_ref()
                .ok_or(CloudDeviceError::Protocol)?;
            let publication =
                grant_publication(&self.selector()?, grant, self.session.capabilities())?;
            self.publication = Some(publication);
        }
        let publication = self.publication.clone().ok_or(CloudDeviceError::Protocol)?;
        self.claim.first_published_at.get_or_insert(now_ms);
        self.claim.last_published_at = now_ms;
        self.claim.retry_publish_at = None;
        io.issue(Purpose::Publish, Effect::Publish(publication));
        Ok(())
    }
    /// The next step towards a claimed chat, once nothing is outstanding.
    fn advance(&mut self, io: &mut CreateIo, now_ms: i64) -> Result<Wait, CloudDeviceError> {
        let Some(runner) = self.runner else {
            let ChatHost::Managed { .. } = &self.host else {
                return Err(CloudDeviceError::Protocol);
            };
            io.issue(Purpose::Seats, Effect::ListInstances);
            return Ok(Wait::Busy);
        };
        if self.session.runner(&runner).is_err() {
            if self.reloaded.is_some() {
                return Err(CloudDeviceError::NoRunner);
            }
            let collection_id = RunnerRegistry::collection_id(self.session.scope())?;
            io.issue(
                Purpose::RegistryKey,
                Effect::GetCollectionKey { collection_id },
            );
            return Ok(Wait::Busy);
        }
        for kind in [Kind::Material, Kind::Grant] {
            let missing = match kind {
                Kind::Material => self.records.material.is_none(),
                Kind::Grant => self.records.grant.is_none(),
            };
            if !missing {
                continue;
            }
            if self.key(kind).is_none() {
                let collection_id = self.collection(kind)?;
                io.issue(
                    Purpose::Key(kind),
                    Effect::GetCollectionKey { collection_id },
                );
            } else {
                self.get_object(io, kind)?;
            }
            return Ok(Wait::Busy);
        }
        let Some(first) = self.claim.first_published_at else {
            self.publish(io, now_ms)?;
            return Ok(Wait::Busy);
        };
        if now_ms.saturating_sub(first) >= CLAIM_PATIENCE_MS {
            return Err(CloudDeviceError::NotClaimed);
        }
        let republish_at = self.claim.retry_publish_at.unwrap_or(
            self.claim
                .last_published_at
                .saturating_add(CLAIM_REPUBLISH_MS),
        );
        if now_ms >= republish_at {
            self.publish(io, now_ms)?;
            return Ok(Wait::Busy);
        }
        if now_ms >= self.claim.next_probe_at {
            self.claim_probe(io, now_ms)?;
            return Ok(Wait::Busy);
        }
        let until = republish_at
            .min(self.claim.next_probe_at)
            .min(first.saturating_add(CLAIM_PATIENCE_MS));
        Ok(Wait::Idle(Some(until)))
    }
}

impl Machine for Creating {
    type Purpose = Purpose;
    type Output = CreatedChat;
    fn handle(
        &mut self,
        io: &mut CreateIo,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let Arrival::Input(input) = arrival else {
            return Err(CloudDeviceError::Protocol);
        };
        match purpose {
            Purpose::Seats => {
                let ChatHost::Managed { agent_id } = &self.host else {
                    return Err(CloudDeviceError::Protocol);
                };
                let seats = crate::seat::listed(input)?;
                let start = crate::seat::start(&seats, agent_id, Some(self.chat_id))?;
                io.issue(Purpose::Seat, start);
                Ok(())
            }
            Purpose::Seat => self.seat(input),
            purpose @ (Purpose::RegistryKey | Purpose::RegistryObject(_)) => {
                self.registry(io, purpose, input)
            }
            Purpose::Key(kind) => self.keyed(io, kind, input),
            Purpose::CreateCollection(kind) => match input {
                // Created, or another device created it meanwhile: read the stored key.
                Input::Done | Input::Failed(EffectFailure::AlreadyExists) => {
                    let collection_id = self.collection(kind)?;
                    io.issue(
                        Purpose::Key(kind),
                        Effect::GetCollectionKey { collection_id },
                    );
                    Ok(())
                }
                Input::Failed(failure) => Err(CloudDeviceError::Effect(failure)),
                _ => Err(CloudDeviceError::Protocol),
            },
            Purpose::Object(Kind::Material) => self.material(io, input),
            Purpose::Object(Kind::Grant) => self.grant(io, input),
            purpose @ (Purpose::PutMaterial(_) | Purpose::PutGrant(_)) => {
                self.stored(io, purpose, input)
            }
            Purpose::Publish => match input {
                Input::Receipt { .. } => Ok(()),
                Input::Failed(EffectFailure::Unavailable | EffectFailure::Unknown) => {
                    self.claim.retry_publish_at = Some(now_ms.saturating_add(CLAIM_RETRY_MS));
                    Ok(())
                }
                Input::Failed(failure) => Err(CloudDeviceError::Effect(failure)),
                _ => Err(CloudDeviceError::Protocol),
            },
            Purpose::ClaimSign => {
                let probe = self
                    .claim
                    .probe
                    .as_mut()
                    .ok_or(CloudDeviceError::Protocol)?;
                let request = probe.signed(self.session.keys(), input)?;
                io.issue(Purpose::Claim, Effect::Probe(request));
                Ok(())
            }
            Purpose::Claim => self.claimed(io, input, now_ms),
        }
    }
    fn tick(&mut self, io: &mut CreateIo, now_ms: i64) -> Result<Wait, CloudDeviceError> {
        if self.finished {
            return Ok(Wait::Done);
        }
        if io.waiting(|_| true) {
            return Ok(Wait::Idle(None));
        }
        self.advance(io, now_ms)
    }
}

#[cfg(test)]
mod tests;
