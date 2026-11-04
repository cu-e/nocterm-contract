//! The `ProviderLease` flow: an own runner's chat gets the agent's provider key as a short lease
//! sealed to the runner's verified boot (ADR 0126 of the native client), renewed at half term
//! while the flow runs.
//!
//! 1. `RunnerStatus` gives the runner's signed boot descriptor; it is verified under the pinned
//!    runner signing key for this account and runner, and must be current.
//! 2. The agent's key is read from the account's `agent_provider_keys` collection
//!    (`key-<agent>`), sealed to the boot's one-time recipient key ([`LEASE_TERM_MS`], never
//!    beyond the boot) and dropped; the plaintext exists only while sealing.
//! 3. `IssueGrant(Provider)` carries the capsule under one grant id for the flow's life, with the
//!    lease expiry as its epoch, so each renewal replaces the previous capsule. It is published
//!    with `PublishOne`; an unknown outcome is retried with the same bytes.
//! 4. After the receipt the flow reports [`Lease`] and waits until half the term has passed.
use crate::{
    CloudDeviceError, DeviceIdentity,
    command::{CommandAction, SealedCommand, UnsignedCommand},
    context::{ChatRef, CloudSession},
    discover::view,
    flow::{
        Arrival, Driven, Effect, EffectFailure, EffectId, Flow, Frame, Input, Io, Machine, Step,
        Wait,
    },
    records::{ChatSelector, PROVIDER_KEYS_KIND, ProviderKeyRecord, provider_key_object},
};
use nocterm_hub_model::cloud::{
    CloudTextId,
    payload::GrantReference,
    provider::{ProviderLeaseContext, SignedBootDescriptor, VerifiedBootDescriptor},
};
use nocterm_keys::{CollectionKey, cloud::seal_provider_lease, random_bytes};
use std::sync::Arc;

/// How long one lease lasts.
pub const LEASE_TERM_MS: i64 = 10 * 60 * 1000;
/// How long between two attempts of a publication that did not come back.
pub const LEASE_RETRY_MS: i64 = 2_000;
const MAX_BOOT_BYTES: usize = 580;

/// A lease the hub delivered to the runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub grant: [u8; 16],
    pub expires_at_ms: i64,
    /// When the flow renews it.
    pub renew_at_ms: i64,
}

/// The `ProviderLease` flow of one own-runner chat.
#[derive(Debug)]
pub struct ProviderLease(Driven<Leasing>);
impl ProviderLease {
    /// `control_revision` is the chat's latest control revision (0 for a new chat).
    pub fn new(
        session: Arc<CloudSession>,
        device: DeviceIdentity,
        chat: &ChatRef,
        agent_id: &str,
        control_revision: u64,
    ) -> Result<Self, CloudDeviceError> {
        let selector = session.selector(chat)?;
        if !session.capabilities().unary_publish() {
            return Err(CloudDeviceError::Unsupported);
        }
        Ok(Self(Driven::new(Leasing {
            session,
            device,
            selector,
            agent_id: agent_id.to_owned(),
            control_revision,
            grant: random_bytes()?,
            boot: None,
            collection: None,
            renewal: None,
            due_at: Some(i64::MIN),
        })))
    }
    /// The chat's control revision for the next renewal.
    pub fn set_control_revision(&mut self, revision: u64) {
        self.0.with(|leasing, _| {
            leasing.control_revision = leasing.control_revision.max(revision);
        });
    }
}
impl Flow for ProviderLease {
    type Output = Lease;
    fn next(&mut self, now_ms: i64) -> Step<Lease> {
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
    Status,
    Collections,
    Key,
    Object(Vec<u8>),
    Sign,
    Publish(i64),
}

#[derive(Debug)]
pub(crate) struct Leasing {
    session: Arc<CloudSession>,
    device: DeviceIdentity,
    selector: ChatSelector,
    agent_id: String,
    control_revision: u64,
    grant: [u8; 16],
    boot: Option<VerifiedBootDescriptor>,
    collection: Option<String>,
    renewal: Option<Renewal>,
    due_at: Option<i64>,
}

/// The renewal in progress and the lease expiry it carries.
#[derive(Debug)]
enum Renewal {
    Unsigned {
        command: Box<UnsignedCommand>,
        expires_at_ms: i64,
    },
    Sealed {
        sealed: Box<SealedCommand>,
        expires_at_ms: i64,
    },
}
type LeaseIo = Io<Purpose, Lease>;

impl Leasing {
    fn boot(&mut self, input: Input, now_ms: i64) -> Result<(), CloudDeviceError> {
        let Input::RunnerStatus { signed_status } = input else {
            return Err(failed(&input));
        };
        if signed_status.is_empty() || signed_status.len() > MAX_BOOT_BYTES {
            return Err(CloudDeviceError::Capacity);
        }
        let signed = SignedBootDescriptor::from_canonical_bytes(&signed_status)?;
        let pins = self.selector.pins();
        self.boot = Some(signed.verify(
            &pins.signing,
            &self.selector.scope().namespace(),
            self.selector.runner(),
            now_ms,
        )?);
        Ok(())
    }
    fn read_key(&self, io: &mut LeaseIo) {
        match &self.collection {
            Some(collection_id) => {
                io.issue(
                    Purpose::Key,
                    Effect::GetCollectionKey {
                        collection_id: collection_id.clone(),
                    },
                );
            }
            None => {
                io.issue(
                    Purpose::Collections,
                    Effect::ListCollections {
                        kind: PROVIDER_KEYS_KIND.to_owned(),
                    },
                );
            }
        }
    }
    /// Opens the key, seals the lease capsule and asks for the command signature.
    fn seal(
        &mut self,
        io: &mut LeaseIo,
        wrapped: &[u8],
        input: Input,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let object = match input {
            Input::Object(object) => object,
            Input::Failed(EffectFailure::NotFound) => return Err(CloudDeviceError::NoProviderKey),
            input => return Err(failed(&input)),
        };
        let collection = self
            .collection
            .as_deref()
            .ok_or(CloudDeviceError::Protocol)?;
        let keys = self.session.keys();
        let key = CollectionKey::open(keys.account(), collection, wrapped)?;
        let record = ProviderKeyRecord::open(&key, &self.agent_id, &view(&object))?;
        let boot = self.boot.as_ref().ok_or(CloudDeviceError::Protocol)?;
        boot.descriptor().require_current(now_ms)?;
        let expires_at_ms = now_ms
            .saturating_add(LEASE_TERM_MS)
            .min(boot.descriptor().window().expires_at_ms);
        let context = ProviderLeaseContext::new(
            boot.descriptor().clone(),
            CloudTextId::new(record.provider())?,
            self.grant,
            expires_at_ms,
        )?;
        let capsule = seal_provider_lease(keys.pair(), boot, &context, record.expose(), now_ms)?;
        let models = [CloudTextId::new(record.model())?];
        drop(record);
        let command = UnsignedCommand::prepare(
            &self.selector,
            keys.public_key(),
            &self.device,
            CommandAction::Provider {
                grant: GrantReference {
                    id: self.grant,
                    epoch: u64::try_from(expires_at_ms).map_err(|_| CloudDeviceError::Time)?,
                },
                context: &context,
                models: &models,
                capsule: &capsule,
            },
            self.control_revision,
            now_ms,
        )?;
        io.issue(Purpose::Sign, Effect::Sign(command.sign_request()?));
        self.renewal = Some(Renewal::Unsigned {
            command: Box::new(command),
            expires_at_ms,
        });
        Ok(())
    }
    fn signed(&mut self, io: &mut LeaseIo, input: Input) -> Result<(), CloudDeviceError> {
        let Input::Signature(signature) = input else {
            return Err(failed(&input));
        };
        let Some(Renewal::Unsigned {
            command,
            expires_at_ms,
        }) = self.renewal.take()
        else {
            return Err(CloudDeviceError::Protocol);
        };
        let sealed = command.seal(
            self.session.keys().pair(),
            &signature,
            self.session.capabilities(),
        )?;
        io.issue(
            Purpose::Publish(expires_at_ms),
            Effect::Publish(sealed.publication().clone()),
        );
        self.renewal = Some(Renewal::Sealed {
            sealed: Box::new(sealed),
            expires_at_ms,
        });
        Ok(())
    }
    fn published(
        &mut self,
        io: &mut LeaseIo,
        expires_at_ms: i64,
        input: Input,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let Some(Renewal::Sealed { sealed, .. }) = &self.renewal else {
            return Err(CloudDeviceError::Protocol);
        };
        let deadline = sealed.accept_before_ms().min(expires_at_ms);
        match input {
            Input::Receipt {
                publication_id,
                cursor,
                ciphertext_sha256,
            } if sealed
                .publication()
                .is_receipt(&publication_id, cursor, &ciphertext_sha256) =>
            {
                let renew_at_ms = now_ms.saturating_add((expires_at_ms - now_ms).max(0) / 2);
                self.renewal = None;
                self.due_at = Some(renew_at_ms);
                io.output(Lease {
                    grant: self.grant,
                    expires_at_ms,
                    renew_at_ms,
                });
            }
            // Nothing came back: the same bytes again while the lease can still arrive in time,
            // otherwise a new lease.
            Input::Receipt { .. }
            | Input::Failed(EffectFailure::Unavailable | EffectFailure::Unknown) => {
                let retry = now_ms.saturating_add(LEASE_RETRY_MS);
                if retry >= deadline {
                    self.renewal = None;
                }
                self.due_at = Some(if retry >= deadline { now_ms } else { retry });
            }
            input => return Err(failed(&input)),
        }
        Ok(())
    }
}

fn failed(input: &Input) -> CloudDeviceError {
    match input {
        Input::Failed(failure) => CloudDeviceError::Effect(*failure),
        _ => CloudDeviceError::Protocol,
    }
}

impl Machine for Leasing {
    type Purpose = Purpose;
    type Output = Lease;
    fn handle(
        &mut self,
        io: &mut LeaseIo,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let Arrival::Input(input) = arrival else {
            return Err(CloudDeviceError::Protocol);
        };
        match purpose {
            Purpose::Status => {
                self.boot(input, now_ms)?;
                self.read_key(io);
            }
            Purpose::Collections => {
                let Input::Collections(collections) = input else {
                    return Err(failed(&input));
                };
                let collection = collections
                    .into_iter()
                    .find(|c| c.personal && !c.deleted && c.kind == PROVIDER_KEYS_KIND)
                    .ok_or(CloudDeviceError::NoProviderKey)?;
                self.collection = Some(collection.collection_id);
                self.read_key(io);
            }
            Purpose::Key => match input {
                Input::CollectionKey {
                    wrapped_key,
                    granted_by,
                } if granted_by.is_empty() => {
                    let collection_id =
                        self.collection.clone().ok_or(CloudDeviceError::Protocol)?;
                    io.issue(
                        Purpose::Object(wrapped_key),
                        Effect::GetObject {
                            collection_id,
                            object_id: provider_key_object(&self.agent_id),
                        },
                    );
                }
                Input::CollectionKey { .. } => return Err(CloudDeviceError::Binding),
                Input::Failed(EffectFailure::NotFound) => {
                    return Err(CloudDeviceError::NoProviderKey);
                }
                input => return Err(failed(&input)),
            },
            Purpose::Object(wrapped) => self.seal(io, &wrapped, input, now_ms)?,
            Purpose::Sign => self.signed(io, input)?,
            Purpose::Publish(expires) => self.published(io, expires, input, now_ms)?,
        }
        Ok(())
    }
    fn tick(&mut self, io: &mut LeaseIo, now_ms: i64) -> Result<Wait, CloudDeviceError> {
        let Some(due) = self.due_at else {
            return Ok(Wait::Idle(None));
        };
        if now_ms < due {
            return Ok(Wait::Idle(Some(due)));
        }
        self.due_at = None;
        // A renewal whose outcome is unknown is retried with the same bytes.
        if let Some(Renewal::Sealed {
            sealed,
            expires_at_ms,
        }) = &self.renewal
        {
            io.issue(
                Purpose::Publish(*expires_at_ms),
                Effect::Publish(sealed.publication().clone()),
            );
        } else {
            self.renewal = None;
            io.issue(
                Purpose::Status,
                Effect::RunnerStatus {
                    runner_id: self.selector.runner().id,
                },
            );
        }
        Ok(Wait::Busy)
    }
}

#[cfg(test)]
mod tests;
