//! The `Discover` flow: from an unlocked account to its [`CloudSession`] on this hub.
//!
//! It lists the account's `cloud-hub-trust` collections, opens `hub-authority-v1` in each and
//! keeps the records made for this raw hub id, account and account key (ADR 0006). None means
//! Cloud was never set up from a native device; several are the person's choice by origin. The
//! chosen pin then checks the hub's fresh capability proof, and the trusted runner registry is
//! read (an account without an enrolled runner has none). Trust is never created here.
use crate::nonces::Nonces;
use crate::{
    CloudDeviceError,
    context::{AccountKeys, CloudSession},
    flow::{
        Arrival, Driven, Effect, EffectFailure, EffectId, Flow, Frame, Input, Io, Machine, Step,
        Wait,
    },
    records::{
        HUB_TRUST_KIND, HUB_TRUST_OBJECT, HubTrustRecord, RUNNER_REGISTRY_OBJECT, RunnerRegistry,
        StoredObject, TrustedRunner,
    },
    trust::{HubCapabilities, TrustedHub},
};
use nocterm_keys::CollectionKey;
use std::sync::Arc;

/// Hub-trust collections looked at.
pub const MAX_HUB_TRUST_COLLECTIONS: usize = 16;

/// Where the account stands on this hub.
#[derive(Debug)]
pub enum Discovery {
    /// No hub-trust record names this hub and account: set Cloud up on a native device.
    NotSetUp,
    /// Several native origins set Cloud up; call again with one of them.
    ChooseOrigin(Vec<String>),
    /// The hub does not offer what reading chats needs.
    Unsupported,
    Ready(Arc<CloudSession>),
}

/// The `Discover` flow.
#[derive(Debug)]
pub struct Discover(Driven<Discovering>);
impl Discover {
    /// `raw_hub` is the hub id the hub reports (`GetHubInfo.hub_id`); `origin` the one the
    /// person chose earlier, when several match.
    pub fn new(keys: Arc<AccountKeys>, raw_hub: &str, origin: Option<String>) -> Self {
        Self::with_nonces(keys, raw_hub, origin, Nonces::os())
    }
    /// As [`Self::new`]; the session draws its nonces from `nonces`.
    pub fn with_nonces(
        keys: Arc<AccountKeys>,
        raw_hub: &str,
        origin: Option<String>,
        nonces: Nonces,
    ) -> Self {
        Self(Driven::new(Discovering {
            nonces,
            keys,
            raw_hub: raw_hub.to_owned(),
            origin,
            started: false,
            trusts: Vec::new(),
            hub: None,
            capabilities: None,
            finished: false,
        }))
    }
}
impl Flow for Discover {
    type Output = Discovery;
    fn next(&mut self, now_ms: i64) -> Step<Discovery> {
        self.0.next(now_ms)
    }
    fn resolve(&mut self, id: EffectId, input: Input) {
        self.0.resolve(id, input);
    }
    fn frame(&mut self, id: EffectId, frame: Frame) {
        self.0.frame(id, frame);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    List,
    TrustKey(String),
    TrustObject(String, Vec<u8>),
    Capabilities([u8; 16]),
    RegistryKey,
    RegistryObject(Vec<u8>),
}

#[derive(Debug)]
pub(crate) struct Discovering {
    nonces: Nonces,
    keys: Arc<AccountKeys>,
    raw_hub: String,
    origin: Option<String>,
    started: bool,
    trusts: Vec<HubTrustRecord>,
    hub: Option<TrustedHub>,
    capabilities: Option<HubCapabilities>,
    finished: bool,
}
type DiscoverIo = Io<Purpose, Discovery>;

impl Discovering {
    fn finish(&mut self, io: &mut DiscoverIo, outcome: Discovery) {
        io.output(outcome);
        self.finished = true;
    }
    /// Every trust record is read: choose one and ask for the capability proof.
    fn choose(&mut self, io: &mut DiscoverIo) -> Result<(), CloudDeviceError> {
        let preferred = |record: &&HubTrustRecord| Some(record.origin()) == self.origin.as_deref();
        let chosen = match self.trusts.as_slice() {
            [] => {
                self.finish(io, Discovery::NotSetUp);
                return Ok(());
            }
            [only] => only.clone(),
            many => {
                if let Some(record) = many.iter().find(preferred) {
                    record.clone()
                } else {
                    let mut origins: Vec<String> = many
                        .iter()
                        .map(|record| record.origin().to_owned())
                        .collect();
                    origins.sort();
                    origins.dedup();
                    self.finish(io, Discovery::ChooseOrigin(origins));
                    return Ok(());
                }
            }
        };
        self.hub = Some(TrustedHub::new(
            chosen,
            &self.raw_hub,
            self.keys.account_id(),
            &self.keys.public_key(),
        )?);
        let nonce = self.nonces.fill()?;
        io.issue(Purpose::Capabilities(nonce), Effect::Capabilities { nonce });
        Ok(())
    }
    fn ready(
        &mut self,
        io: &mut DiscoverIo,
        runners: Vec<TrustedRunner>,
    ) -> Result<(), CloudDeviceError> {
        let hub = self.hub.take().ok_or(CloudDeviceError::Protocol)?;
        let capabilities = self.capabilities.ok_or(CloudDeviceError::Protocol)?;
        let session = CloudSession::new(self.keys.clone(), hub, capabilities, runners)?
            .with_nonces(self.nonces.clone());
        self.finish(io, Discovery::Ready(Arc::new(session)));
        Ok(())
    }
    fn hub(&self) -> Result<&TrustedHub, CloudDeviceError> {
        self.hub.as_ref().ok_or(CloudDeviceError::Protocol)
    }
    fn trust_object(&mut self, collection: &str, wrapped: &[u8], input: Input) {
        let Input::Object(object) = input else {
            return;
        };
        let Ok(key) = CollectionKey::open(self.keys.account(), collection, wrapped) else {
            return;
        };
        let view = view(&object);
        if let Ok(record) = HubTrustRecord::open(&key, &view)
            && record.matches(
                &self.raw_hub,
                self.keys.account_id(),
                &self.keys.public_key(),
            )
        {
            self.trusts.push(record);
        }
    }
}

pub(crate) fn view(object: &crate::flow::ObjectEntry) -> StoredObject<'_> {
    StoredObject {
        collection_id: &object.collection_id,
        object_id: &object.object_id,
        kind: &object.kind,
        version: object.version,
        deleted: object.deleted,
        ciphertext: &object.ciphertext,
    }
}

impl Machine for Discovering {
    type Purpose = Purpose;
    type Output = Discovery;
    fn handle(
        &mut self,
        io: &mut DiscoverIo,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let Arrival::Input(input) = arrival else {
            return Err(CloudDeviceError::Protocol);
        };
        match (purpose, input) {
            (Purpose::List, Input::Collections(collections)) => {
                for entry in collections
                    .into_iter()
                    .filter(|c| c.personal && !c.deleted && c.kind == HUB_TRUST_KIND)
                    .take(MAX_HUB_TRUST_COLLECTIONS)
                {
                    io.issue(
                        Purpose::TrustKey(entry.collection_id.clone()),
                        Effect::GetCollectionKey {
                            collection_id: entry.collection_id,
                        },
                    );
                }
            }
            (
                Purpose::TrustKey(collection),
                Input::CollectionKey {
                    wrapped_key,
                    granted_by,
                },
            ) => {
                if granted_by.is_empty() {
                    io.issue(
                        Purpose::TrustObject(collection.clone(), wrapped_key),
                        Effect::GetObject {
                            collection_id: collection,
                            object_id: HUB_TRUST_OBJECT.to_owned(),
                        },
                    );
                }
            }
            (Purpose::TrustKey(_) | Purpose::TrustObject(..), Input::Failed(_)) => {}
            (Purpose::TrustObject(collection, wrapped), input) => {
                self.trust_object(&collection, &wrapped, input);
            }
            (Purpose::Capabilities(nonce), Input::Capabilities { claim, signature }) => {
                let capabilities = self
                    .hub()?
                    .verify_capabilities(&claim, &signature, &nonce, now_ms)?;
                if capabilities.require_reading().is_err() {
                    self.finish(io, Discovery::Unsupported);
                    return Ok(());
                }
                self.capabilities = Some(capabilities);
                let collection_id = RunnerRegistry::collection_id(self.hub()?.scope())?;
                io.issue(
                    Purpose::RegistryKey,
                    Effect::GetCollectionKey { collection_id },
                );
            }
            (
                Purpose::RegistryKey,
                Input::CollectionKey {
                    wrapped_key,
                    granted_by,
                },
            ) => {
                if !granted_by.is_empty() {
                    return Err(CloudDeviceError::Binding);
                }
                io.issue(
                    Purpose::RegistryObject(wrapped_key),
                    Effect::GetObject {
                        collection_id: RunnerRegistry::collection_id(self.hub()?.scope())?,
                        object_id: RUNNER_REGISTRY_OBJECT.to_owned(),
                    },
                );
            }
            (
                Purpose::RegistryKey | Purpose::RegistryObject(_),
                Input::Failed(EffectFailure::NotFound),
            ) => {
                self.ready(io, Vec::new())?;
            }
            (Purpose::RegistryObject(wrapped), Input::Object(object)) => {
                let runners = open_registry(&self.keys, self.hub()?, &wrapped, &object)?;
                self.ready(io, runners)?;
            }
            (_, Input::Failed(failure)) => return Err(CloudDeviceError::Effect(failure)),
            _ => return Err(CloudDeviceError::Protocol),
        }
        Ok(())
    }
    fn tick(&mut self, io: &mut DiscoverIo, _now_ms: i64) -> Result<Wait, CloudDeviceError> {
        if self.finished {
            return Ok(Wait::Done);
        }
        if !self.started {
            self.started = true;
            io.issue(
                Purpose::List,
                Effect::ListCollections {
                    kind: HUB_TRUST_KIND.to_owned(),
                },
            );
            return Ok(Wait::Busy);
        }
        let reading_trust = io.waiting(|purpose| {
            matches!(
                purpose,
                Purpose::List | Purpose::TrustKey(_) | Purpose::TrustObject(..)
            )
        });
        if !reading_trust && self.hub.is_none() {
            self.choose(io)?;
            return Ok(Wait::Busy);
        }
        Ok(Wait::Idle(None))
    }
}

/// Opens `trusted-runners-v1` of the hub's scope from its collection.
pub(crate) fn open_registry(
    keys: &AccountKeys,
    hub: &TrustedHub,
    wrapped: &[u8],
    object: &crate::flow::ObjectEntry,
) -> Result<Vec<TrustedRunner>, CloudDeviceError> {
    let collection = RunnerRegistry::collection_id(hub.scope())?;
    let key = CollectionKey::open(keys.account(), &collection, wrapped)?;
    let registry = RunnerRegistry::open(&key, hub.scope(), &view(object))?;
    Ok(registry.runners().to_vec())
}

#[cfg(test)]
mod tests;
