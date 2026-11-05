//! The `BindServers` and `SshAnswer` flows: a chat bound to the person's CA-trusted servers,
//! and short certificates for the runner's per-chat key inside that binding (contract ADR
//! 0009).
//!
//! Both read the account's `agent_ssh_trust` collection first: the CA document (`ca`) and the
//! trust record of every server involved (`srv-<hex>`). Then:
//! - `BindServers` admits only servers whose record is trusted under the current CA, takes host,
//!   user and host key from that record (the person's choice supplies only the port), signs the
//!   [`SshBinding`] with the CA and delivers `IssueGrant(SshBinding)`. It reports which servers
//!   still hold the shared `authorized_keys` line and need a CA update.
//! - `SshAnswer` answers one request the verified transcript holds and still allows
//!   ([`crate::transcript::ChatSsh::answerable`]): the binding must be signed by the account's
//!   current CA, the time inside the binding window; only requested servers that are still
//!   trusted under that CA, with the bound host, user and host key, are certified. The
//!   certificate lasts until the request's end, at most 24 hours and never past the binding,
//!   names only those servers' principals, the runner's stated source addresses and `permit-pty`.
//!   It is delivered as `IssueGrant(SshCertificate)`.
//!
//! A device that cannot verify all of this refuses with a typed [`SshRefusal`]; no hub or runner
//! statement replaces a check. Delivery is [`crate::command::Deliver`]'s: identical bytes on
//! retry and a receipt probe on an unknown outcome. Unbinding is a plain delivery of
//! `RevokeGrant(SshBinding)` ([`crate::open::OpenChat::unbind_servers`]).
mod staged;

use crate::{
    CloudDeviceError, DeviceIdentity,
    command::{CommandAction, Deliver, DeliveryUpdate, UnsignedCommand},
    context::CloudSession,
    discover::view,
    error::SshRefusal,
    flow::{Arrival, Effect, EffectFailure, EffectId, Flow, Frame, Input, Io, Machine, Step, Wait},
    records::{ChatSelector, SSH_TRUST_KIND, open_ca, open_trust},
    transcript::{BindingState, CommandState, PendingCommand, PendingKind, Transcript},
};
use nocterm_hub_model::cloud::{
    CloudTextId,
    payload::GrantReference,
    ssh::{
        BindingWindow, DEFAULT_BINDING_WINDOW_MS, MAX_BINDING_TARGETS, MAX_BINDING_WINDOW_MS,
        MAX_CERTIFICATE_VALIDITY_MS, SshBinding, SshCertificateRequest, SshServerId, SshTarget,
    },
};
use nocterm_keys::{
    CollectionKey,
    agents::{
        CaLineForm, SshTrustRecord, TrustState,
        ssh_ca::{CA_OBJECT, CaDocument, CertificateSpec, principal_for, sha256_of_fingerprint},
    },
    random_bytes,
};
use staged::{Prepared, Route, Staged};
use std::sync::Arc;

/// A server the person chose for a chat: a CA-trusted server and the port of its profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshServerChoice {
    pub server: SshServerId,
    pub port: u16,
}

/// What an SSH flow reports: one `Bound` or `Certified`, then the delivery's settled state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshUpdate {
    /// This device signed the binding `grant`; `needs_ca_update` still hold the shared line.
    Bound {
        grant: GrantReference,
        needs_ca_update: Vec<SshServerId>,
    },
    /// This device signed a certificate for `request`, for `servers`, until `valid_before_ms`.
    Certified {
        request: [u8; 16],
        servers: Vec<SshServerId>,
        valid_before_ms: i64,
    },
    Delivery(DeliveryUpdate),
}

/// What an open chat lends a new SSH flow.
pub(crate) struct ChatParts<'a> {
    pub(crate) session: &'a Arc<CloudSession>,
    pub(crate) device: &'a DeviceIdentity,
    pub(crate) selector: &'a ChatSelector,
    pub(crate) transcript: &'a mut Transcript,
}
impl ChatParts<'_> {
    fn route(&self, wake: Option<String>) -> Route {
        Route {
            session: self.session.clone(),
            device: self.device.clone(),
            selector: self.selector.clone(),
            wake,
        }
    }
    fn track(&mut self, command_id: [u8; 16], kind: PendingKind, now_ms: i64) {
        self.transcript.track(PendingCommand {
            command_id,
            kind,
            text: String::new(),
            run: None,
            state: CommandState::Sending,
            at_ms: now_ms,
        });
    }
}

/// The `BindServers` flow of one chat.
#[derive(Debug)]
pub struct BindServers(Staged);
impl BindServers {
    /// `window_ms` defaults to seven days and may not exceed thirty.
    pub(crate) fn for_chat(
        mut parts: ChatParts<'_>,
        choices: &[SshServerChoice],
        window_ms: Option<i64>,
        wake: Option<String>,
        now_ms: i64,
    ) -> Result<Self, CloudDeviceError> {
        if choices.is_empty()
            || choices.len() > MAX_BINDING_TARGETS
            || choices.iter().any(|choice| choice.port == 0)
            || choices
                .iter()
                .enumerate()
                .any(|(i, c)| choices[..i].iter().any(|k| k.server == c.server))
        {
            return Err(SshRefusal::Servers.into());
        }
        let window_ms = window_ms.unwrap_or(DEFAULT_BINDING_WINDOW_MS);
        if window_ms <= 0 || window_ms > MAX_BINDING_WINDOW_MS {
            return Err(SshRefusal::Window.into());
        }
        // One binding per chat: a new choice replaces the latest binding at a higher epoch.
        let latest = parts
            .transcript
            .ssh()
            .bindings()
            .last()
            .map(BindingState::grant);
        let now = u64::try_from(now_ms).map_err(|_| CloudDeviceError::Time)?;
        let grant = GrantReference {
            id: latest.map_or_else(random_bytes, |grant| Ok(grant.id))?,
            epoch: latest.map_or(now, |grant| now.max(grant.epoch.saturating_add(1))),
        };
        let window = BindingWindow {
            issued_at_ms: now_ms,
            expires_at_ms: now_ms
                .checked_add(window_ms)
                .ok_or(CloudDeviceError::Time)?,
        };
        let ids = (random_bytes()?, random_bytes()?, random_bytes()?);
        parts.track(ids.0, PendingKind::Bind, now_ms);
        let goal = Goal::Bind {
            choices: choices.to_vec(),
            grant,
            window,
        };
        Ok(Self(Staged::new(
            Preparing::new(&parts, goal, ids),
            parts.route(wake),
        )))
    }
}

/// The `SshAnswer` flow of one certificate request.
#[derive(Debug)]
pub struct SshAnswer(Staged);
impl SshAnswer {
    pub(crate) fn for_chat(
        mut parts: ChatParts<'_>,
        request: &[u8; 16],
        now_ms: i64,
    ) -> Result<Self, CloudDeviceError> {
        let asked = parts.transcript.ssh().answerable(request, now_ms)?.clone();
        if asked.binding.binding().chat != parts.selector.coordinate()? {
            return Err(CloudDeviceError::Binding);
        }
        let ids = (random_bytes()?, random_bytes()?, random_bytes()?);
        parts.track(ids.0, PendingKind::Certificate, now_ms);
        let goal = Goal::Answer(Box::new(asked));
        Ok(Self(Staged::new(
            Preparing::new(&parts, goal, ids),
            parts.route(None),
        )))
    }
}

/// Revokes the chat's current binding: this device stops answering it at once.
pub(crate) fn unbind(
    mut parts: ChatParts<'_>,
    wake: Option<String>,
    now_ms: i64,
) -> Result<Deliver, CloudDeviceError> {
    let grant = parts
        .transcript
        .ssh()
        .current()
        .map(BindingState::grant)
        .ok_or(SshRefusal::NotBound)?;
    let command = UnsignedCommand::prepare(
        parts.selector,
        parts.session.keys().public_key(),
        parts.device,
        CommandAction::RevokeSshBinding { grant },
        parts.transcript.control_revision(),
        now_ms,
    )?;
    parts.transcript.withdraw_ssh(&grant.id);
    parts.track(command.command_id(), PendingKind::Unbind, now_ms);
    Ok(Deliver::new(
        parts.session.clone(),
        parts.device.clone(),
        parts.selector.clone(),
        command,
        wake,
    ))
}

macro_rules! flow_of {
    ($flow:ty) => {
        impl Flow for $flow {
            type Output = SshUpdate;
            fn next(&mut self, now_ms: i64) -> Step<SshUpdate> {
                self.0.next(now_ms)
            }
            fn resolve(&mut self, id: EffectId, input: Input) {
                self.0.resolve(id, input);
            }
            fn frame(&mut self, id: EffectId, frame: Frame) {
                self.0.frame(id, frame);
            }
        }
    };
}
flow_of!(BindServers);
flow_of!(SshAnswer);

#[derive(Debug)]
enum Goal {
    Bind {
        choices: Vec<SshServerChoice>,
        grant: GrantReference,
        window: BindingWindow,
    },
    Answer(Box<SshCertificateRequest>),
}
impl Goal {
    fn servers(&self) -> Vec<SshServerId> {
        match self {
            Self::Bind { choices, .. } => choices.iter().map(|choice| choice.server).collect(),
            Self::Answer(request) => request.servers.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    Collections,
    Key(String),
    Ca,
    Server(SshServerId),
}

/// Reads the CA and the trust records, then builds the command of the goal.
#[derive(Debug)]
pub(crate) struct Preparing {
    session: Arc<CloudSession>,
    device: DeviceIdentity,
    selector: ChatSelector,
    control_revision: u64,
    ids: ([u8; 16], [u8; 16], [u8; 16]),
    goal: Goal,
    started: bool,
    key: Option<(String, CollectionKey)>,
    ca: Option<CaDocument>,
    records: Vec<(SshServerId, Option<SshTrustRecord>)>,
    waiting: usize,
}
type PrepareIo = Io<Purpose, Prepared>;

impl Preparing {
    fn new(parts: &ChatParts<'_>, goal: Goal, ids: ([u8; 16], [u8; 16], [u8; 16])) -> Self {
        Self {
            session: parts.session.clone(),
            device: parts.device.clone(),
            selector: parts.selector.clone(),
            control_revision: parts.transcript.control_revision(),
            ids,
            goal,
            started: false,
            key: None,
            ca: None,
            records: Vec::new(),
            waiting: 0,
        }
    }
    fn key(
        &mut self,
        io: &mut PrepareIo,
        collection: String,
        input: Input,
    ) -> Result<(), CloudDeviceError> {
        let wrapped = match input {
            Input::CollectionKey {
                wrapped_key,
                granted_by,
            } if granted_by.is_empty() => wrapped_key,
            Input::CollectionKey { .. } => return Err(CloudDeviceError::Binding),
            Input::Failed(EffectFailure::NotFound) => return Err(SshRefusal::NoCa.into()),
            input => return Err(failed(&input)),
        };
        let key = CollectionKey::open(self.session.keys().account(), &collection, &wrapped)?;
        io.issue(
            Purpose::Ca,
            Effect::GetObject {
                collection_id: collection.clone(),
                object_id: CA_OBJECT.to_owned(),
            },
        );
        for server in self.goal.servers() {
            io.issue(
                Purpose::Server(server),
                Effect::GetObject {
                    collection_id: collection.clone(),
                    object_id: server.object_id(),
                },
            );
        }
        self.waiting = 1 + self.goal.servers().len();
        self.key = Some((collection, key));
        Ok(())
    }
    fn object(&mut self, purpose: Purpose, input: Input) -> Result<(), CloudDeviceError> {
        let (_, key) = self.key.as_ref().ok_or(CloudDeviceError::Protocol)?;
        self.waiting = self
            .waiting
            .checked_sub(1)
            .ok_or(CloudDeviceError::Protocol)?;
        match (purpose, input) {
            (Purpose::Ca, Input::Object(object)) => self.ca = Some(open_ca(key, &view(&object))?),
            (Purpose::Ca, Input::Failed(EffectFailure::NotFound)) => {
                return Err(SshRefusal::NoCa.into());
            }
            (Purpose::Server(server), Input::Object(object)) => {
                let record = match open_trust(key, &server, &view(&object)) {
                    Ok(record) => Some(record),
                    Err(CloudDeviceError::Ssh(SshRefusal::UntrustedServer)) => None,
                    Err(error) => return Err(error),
                };
                self.records.push((server, record));
            }
            (Purpose::Server(server), Input::Failed(EffectFailure::NotFound)) => {
                self.records.push((server, None));
            }
            (_, input) => return Err(failed(&input)),
        }
        Ok(())
    }
    /// The trust record of `server` when it is trusted under `ca`.
    fn trusted(&self, server: &SshServerId, ca: &CaDocument) -> Option<&SshTrustRecord> {
        self.records
            .iter()
            .find(|(known, _)| known == server)
            .and_then(|(_, record)| record.as_ref())
            .filter(|record| {
                record.state() == TrustState::Trusted
                    && record.ca_fingerprint == ca.ca().fingerprint()
            })
    }
    fn prepare(
        &self,
        action: CommandAction<'_>,
        now_ms: i64,
    ) -> Result<UnsignedCommand, CloudDeviceError> {
        UnsignedCommand::prepare_with_ids(
            &self.selector,
            self.session.keys().public_key(),
            &self.device,
            action,
            self.control_revision,
            now_ms,
            self.ids,
        )
    }
    fn bind(
        &self,
        ca: &CaDocument,
        choices: &[SshServerChoice],
        grant: GrantReference,
        window: BindingWindow,
        now_ms: i64,
    ) -> Result<Prepared, CloudDeviceError> {
        let mut targets = Vec::with_capacity(choices.len());
        let mut needs_ca_update = Vec::new();
        for choice in choices {
            let record = self
                .trusted(&choice.server, ca)
                .ok_or(SshRefusal::UntrustedServer)?;
            targets.push(SshTarget {
                server: choice.server,
                host: CloudTextId::new(&record.host)?,
                port: choice.port,
                user: CloudTextId::new(&record.user)?,
                host_key_sha256: sha256_of_fingerprint(&record.host_key_fingerprint)
                    .ok_or(SshRefusal::HostKeyUnknown)?,
            });
            if record.line() == CaLineForm::Shared {
                needs_ca_update.push(choice.server);
            }
        }
        let binding = ca.ca().sign_binding(SshBinding {
            chat: self.selector.coordinate()?,
            grant,
            window,
            ca_key: ca.ca().public_key(),
            targets,
        })?;
        let command = self.prepare(CommandAction::SshBinding { binding: &binding }, now_ms)?;
        Ok((
            SshUpdate::Bound {
                grant,
                needs_ca_update,
            },
            command,
        ))
    }
    fn answer(
        &self,
        ca: &CaDocument,
        request: &SshCertificateRequest,
        now_ms: i64,
    ) -> Result<Prepared, CloudDeviceError> {
        let ca_key = ca.ca().public_key();
        request
            .binding
            .require_ca(&ca_key)
            .map_err(|_| SshRefusal::OtherCa)?;
        let binding = request.binding.binding();
        let valid_before_ms = request
            .not_after_ms
            .min(now_ms.saturating_add(MAX_CERTIFICATE_VALIDITY_MS))
            .min(binding.window.expires_at_ms);
        if !binding.window.contains(now_ms) || valid_before_ms <= now_ms {
            return Err(SshRefusal::OutsideBinding.into());
        }
        // Certify only what is still true now: trusted under this CA, as it was bound.
        let servers: Vec<SshServerId> = request
            .servers
            .iter()
            .filter(|server| {
                let (Some(record), Some(target)) =
                    (self.trusted(server, ca), binding.target(server))
                else {
                    return false;
                };
                record.host == target.host.as_str()
                    && record.user == target.user.as_str()
                    && sha256_of_fingerprint(&record.host_key_fingerprint)
                        == Some(target.host_key_sha256)
            })
            .copied()
            .collect();
        if servers.is_empty() {
            return Err(SshRefusal::NoTrustedServer.into());
        }
        let spec = CertificateSpec {
            principals: servers.iter().map(|s| principal_for(&ca_key, s)).collect(),
            key_id: format!(
                "nocterm-chat-{}-{}",
                hex::encode(self.selector.chat_id()),
                hex::encode(request.request)
            ),
            subject_key: request.subject_key,
            serial: u64::from_be_bytes(random_bytes()?),
            valid_after_ms: now_ms,
            valid_before_ms,
            source_addresses: request.source_addresses.clone(),
        };
        let certificate = ca.ca().issue(&spec, random_bytes()?)?;
        let command = self.prepare(
            CommandAction::SshCertificate {
                grant: binding.grant,
                request: request.request,
                certificate: certificate.as_bytes(),
            },
            now_ms,
        )?;
        Ok((
            SshUpdate::Certified {
                request: request.request,
                servers,
                valid_before_ms,
            },
            command,
        ))
    }
    fn finish(&self, now_ms: i64) -> Result<Prepared, CloudDeviceError> {
        let ca = self.ca.as_ref().ok_or(CloudDeviceError::Protocol)?;
        match &self.goal {
            Goal::Bind {
                choices,
                grant,
                window,
            } => self.bind(ca, choices, *grant, *window, now_ms),
            Goal::Answer(request) => self.answer(ca, request, now_ms),
        }
    }
}

fn failed(input: &Input) -> CloudDeviceError {
    match input {
        Input::Failed(failure) => CloudDeviceError::Effect(*failure),
        _ => CloudDeviceError::Protocol,
    }
}

impl Machine for Preparing {
    type Purpose = Purpose;
    type Output = Prepared;
    fn handle(
        &mut self,
        io: &mut PrepareIo,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        let Arrival::Input(input) = arrival else {
            return Err(CloudDeviceError::Protocol);
        };
        match purpose {
            Purpose::Collections => {
                let Input::Collections(collections) = input else {
                    return Err(failed(&input));
                };
                let collection = collections
                    .into_iter()
                    .find(|c| c.personal && !c.deleted && c.kind == SSH_TRUST_KIND)
                    .ok_or(SshRefusal::NoCa)?;
                io.issue(
                    Purpose::Key(collection.collection_id.clone()),
                    Effect::GetCollectionKey {
                        collection_id: collection.collection_id,
                    },
                );
            }
            Purpose::Key(collection) => self.key(io, collection, input)?,
            purpose => {
                self.object(purpose, input)?;
                if self.waiting == 0 {
                    io.output(self.finish(now_ms)?);
                }
            }
        }
        Ok(())
    }
    fn tick(&mut self, io: &mut PrepareIo, _now_ms: i64) -> Result<Wait, CloudDeviceError> {
        if !self.started {
            self.started = true;
            io.issue(
                Purpose::Collections,
                Effect::ListCollections {
                    kind: SSH_TRUST_KIND.to_owned(),
                },
            );
            return Ok(Wait::Busy);
        }
        Ok(Wait::Idle(None))
    }
}

#[cfg(test)]
mod tests;
