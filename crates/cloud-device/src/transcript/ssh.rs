//! The SSH binding of one chat as its verified history shows it (contract ADR 0009): the
//! bindings the runner's certificate requests carry, what the runner reported about each, and
//! the requests no device answered yet.
//!
//! A binding is known from the CA-signed copy a request echoes; an access state names only its
//! grant. Per grant id only the highest epoch counts. The first request of an epoch fixes the
//! subject key: a later request with another key is never answerable. Requests leave when the
//! runner reports a certificate for them, a newer request of the same binding arrives, or the
//! binding is revoked, refused or expires. This is display and answer-eligibility data; the
//! answering device still checks the CA, the trusted servers and the time itself.
//!
//! The servers of the current binding that the runner admitted are the chat's selectable session
//! targets ([`ChatSsh::session_targets`], contract ADR 0011): a prompt names one with its
//! [`TargetAccess`], which the runner matches against the binding it admitted.
use super::codec::{Reader, Writer};
use crate::{CloudDeviceError, error::SshRefusal};
use nocterm_hub_model::cloud::{
    events::CloudEventPayload,
    payload::{GrantReference, TargetAccess},
    ssh::{
        SignedSshBinding, SshAccess, SshAccessUpdate, SshCertificateRequest, SshServerId,
        SshServerReach,
    },
};

/// Bindings remembered per chat; the oldest goes first.
pub const MAX_CHAT_BINDINGS: usize = 4;
/// Unanswered requests remembered per chat; the oldest goes first.
pub const MAX_SSH_REQUESTS: usize = 8;

/// One binding of the chat at its highest known epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingState {
    grant: GrantReference,
    binding: Option<SignedSshBinding>,
    update: Option<SshAccessUpdate>,
    subject_key: Option<[u8; 32]>,
    withdrawn: bool,
}
impl BindingState {
    fn new(grant: GrantReference) -> Self {
        Self {
            grant,
            binding: None,
            update: None,
            subject_key: None,
            withdrawn: false,
        }
    }
    pub fn grant(&self) -> GrantReference {
        self.grant
    }
    /// The CA-signed binding, once a request of this epoch carried it.
    pub fn binding(&self) -> Option<&SignedSshBinding> {
        self.binding.as_ref()
    }
    /// The runner's latest report for this epoch.
    pub fn update(&self) -> Option<&SshAccessUpdate> {
        self.update.as_ref()
    }
    /// The runner's per-chat key, fixed by the first request of this epoch.
    pub fn subject_key(&self) -> Option<[u8; 32]> {
        self.subject_key
    }
    /// This device asked to revoke it.
    pub fn withdrawn(&self) -> bool {
        self.withdrawn
    }
    /// Revoked, refused or expired: no certificate is answered for it any more.
    pub fn closed(&self) -> bool {
        self.withdrawn
            || self.update.as_ref().is_some_and(|update| {
                matches!(
                    update.access,
                    SshAccess::Revoked | SshAccess::Expired | SshAccess::Refused(_)
                )
            })
    }
}

/// A runner's request no device answered yet, with its publication time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSshRequest {
    pub request: SshCertificateRequest,
    pub at_ms: u64,
}

/// A bound server a prompt may run against: its binding entry, the session access that names
/// it, and whether a certificate is active now (otherwise the runner waits for an account
/// device to answer its request before it signs in).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionTarget {
    pub server: SshServerId,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub access: TargetAccess,
    pub active: bool,
}

/// The chat's SSH bindings and open requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChatSsh {
    bindings: Vec<BindingState>,
    requests: Vec<PendingSshRequest>,
}
impl ChatSsh {
    pub fn bindings(&self) -> &[BindingState] {
        &self.bindings
    }
    /// The binding a device shows for the chat: the newest one that is not closed.
    pub fn current(&self) -> Option<&BindingState> {
        self.bindings.iter().rev().find(|state| !state.closed())
    }
    pub fn requests(&self) -> &[PendingSshRequest] {
        &self.requests
    }
    /// The open request `request` if the verified history still allows answering it at `now_ms`.
    pub fn answerable(
        &self,
        request: &[u8; 16],
        now_ms: i64,
    ) -> Result<&SshCertificateRequest, SshRefusal> {
        let asked = self.eligible(request)?;
        let binding = asked.binding.binding();
        if !binding.window.contains(now_ms) || asked.not_after_ms <= now_ms {
            return Err(SshRefusal::OutsideBinding);
        }
        Ok(asked)
    }
    /// As [`Self::answerable`] without the time: the request is open, of the binding's current
    /// epoch, not revoked and names the binding's subject key.
    pub fn eligible(&self, request: &[u8; 16]) -> Result<&SshCertificateRequest, SshRefusal> {
        let pending = self
            .requests
            .iter()
            .find(|pending| &pending.request.request == request)
            .ok_or(SshRefusal::UnknownRequest)?;
        let asked = &pending.request;
        let binding = asked.binding.binding();
        let state = self
            .state(&binding.grant.id)
            .ok_or(SshRefusal::UnknownRequest)?;
        if state.grant.epoch != binding.grant.epoch {
            return Err(SshRefusal::Superseded);
        }
        if state.closed() {
            return Err(SshRefusal::Revoked);
        }
        if state.subject_key != Some(asked.subject_key) {
            return Err(SshRefusal::SubjectKeyChanged);
        }
        Ok(asked)
    }
    /// The bound servers a prompt may name at `now_ms`, in binding order: those of the current
    /// binding, inside its window, that the runner admitted (its latest report names them
    /// admitted, or before a report, its open request asks for them).
    pub fn session_targets(&self, now_ms: i64) -> Vec<SessionTarget> {
        let Some(state) = self.current() else {
            return Vec::new();
        };
        let Some(binding) = state.binding().map(SignedSshBinding::binding) else {
            return Vec::new();
        };
        if !binding.window.contains(now_ms) {
            return Vec::new();
        }
        let active = state.update.as_ref().is_some_and(|update| {
            matches!(update.access, SshAccess::Active { valid_before_ms, .. } if valid_before_ms > now_ms)
        });
        let admitted = |server: &SshServerId| match &state.update {
            Some(update) => update
                .servers
                .iter()
                .any(|status| &status.server == server && status.reach == SshServerReach::Admitted),
            None => self.requests.iter().any(|pending| {
                pending.request.binding.binding().grant == state.grant
                    && pending.request.servers.contains(server)
            }),
        };
        binding
            .targets
            .iter()
            .filter(|target| admitted(&target.server))
            .filter_map(|target| {
                Some(SessionTarget {
                    server: target.server,
                    host: target.host.as_str().to_owned(),
                    port: target.port,
                    user: target.user.as_str().to_owned(),
                    access: binding.target_access(&target.server)?,
                    active,
                })
            })
            .collect()
    }
    /// The session target of bound server `server` at `now_ms`.
    pub fn session_target(
        &self,
        server: &SshServerId,
        now_ms: i64,
    ) -> Result<SessionTarget, SshRefusal> {
        if self.current().and_then(BindingState::binding).is_none() {
            return Err(SshRefusal::NotBound);
        }
        self.session_targets(now_ms)
            .into_iter()
            .find(|target| &target.server == server)
            .ok_or(SshRefusal::NotSelectable)
    }
    fn state(&self, grant: &[u8; 16]) -> Option<&BindingState> {
        self.bindings.iter().find(|state| &state.grant.id == grant)
    }
    /// The state of `grant` at its epoch or newer; `None` when an older epoch arrives late.
    fn at_epoch(&mut self, grant: GrantReference) -> Option<&mut BindingState> {
        let index = match self.bindings.iter().position(|s| s.grant.id == grant.id) {
            Some(index) if self.bindings[index].grant.epoch > grant.epoch => return None,
            Some(index) if self.bindings[index].grant.epoch < grant.epoch => {
                self.drop_requests(&grant.id, |_| false);
                self.bindings[index] = BindingState::new(grant);
                index
            }
            Some(index) => index,
            None => {
                if self.bindings.len() == MAX_CHAT_BINDINGS {
                    let gone = self.bindings.remove(0).grant.id;
                    self.requests
                        .retain(|pending| pending.request.binding.binding().grant.id != gone);
                }
                self.bindings.push(BindingState::new(grant));
                self.bindings.len() - 1
            }
        };
        Some(&mut self.bindings[index])
    }
    fn drop_requests(&mut self, grant: &[u8; 16], keep: impl Fn(&PendingSshRequest) -> bool) {
        self.requests.retain(|pending| {
            &pending.request.binding.binding().grant.id != grant || keep(pending)
        });
    }
    /// Applies a verified SSH event; other events change nothing.
    pub(super) fn apply(&mut self, payload: &CloudEventPayload<'_>, at_ms: u64) {
        match payload {
            CloudEventPayload::SshCertificateRequested(request) => self.requested(request, at_ms),
            CloudEventPayload::SshAccessState(update) => self.reported(update),
            _ => {}
        }
    }
    /// Applies a verified `SshCertificateRequested`.
    fn requested(&mut self, request: &SshCertificateRequest, at_ms: u64) {
        let grant = request.binding.binding().grant;
        let Some(state) = self.at_epoch(grant) else {
            return;
        };
        if state.binding.is_none() {
            state.binding = Some(request.binding.clone());
        }
        state.subject_key.get_or_insert(request.subject_key);
        if state.closed() {
            return;
        }
        self.drop_requests(&grant.id, |_| false);
        if self.requests.len() == MAX_SSH_REQUESTS {
            self.requests.remove(0);
        }
        self.requests.push(PendingSshRequest {
            request: request.clone(),
            at_ms,
        });
    }
    /// Applies a verified `SshAccessState`.
    fn reported(&mut self, update: &SshAccessUpdate) {
        let Some(state) = self.at_epoch(update.grant) else {
            return;
        };
        state.update = Some(update.clone());
        let closed = state.closed();
        match update.access {
            SshAccess::Active { request, .. } => {
                self.drop_requests(&update.grant.id, |p| p.request.request != request);
            }
            _ if closed => self.drop_requests(&update.grant.id, |_| false),
            _ => {}
        }
    }
    /// This device revokes `grant`: it answers no request of it from now on.
    pub(crate) fn withdraw(&mut self, grant: &[u8; 16]) {
        if let Some(state) = self.bindings.iter_mut().find(|s| &s.grant.id == grant) {
            state.withdrawn = true;
        }
        self.drop_requests(grant, |_| false);
    }

    pub(super) fn encode(&self, out: &mut Writer) -> Result<(), CloudDeviceError> {
        out.len(self.bindings.len())?;
        for state in &self.bindings {
            out.bytes(&state.grant.id);
            out.u64(state.grant.epoch);
            let binding = state
                .binding
                .as_ref()
                .map(SignedSshBinding::canonical_bytes)
                .transpose()?;
            out.optional(binding.as_ref(), |out, bytes| {
                out.len(bytes.len())?;
                out.bytes(bytes);
                Ok(())
            })?;
            let update = state
                .update
                .as_ref()
                .map(SshAccessUpdate::canonical_bytes)
                .transpose()?;
            out.optional(update.as_ref(), |out, bytes| {
                out.len(bytes.len())?;
                out.bytes(bytes);
                Ok(())
            })?;
            out.optional(state.subject_key.as_ref(), |out, key| {
                out.bytes(key);
                Ok(())
            })?;
            out.bool(state.withdrawn);
        }
        out.len(self.requests.len())?;
        for pending in &self.requests {
            let bytes = pending.request.canonical_bytes()?;
            out.len(bytes.len())?;
            out.bytes(&bytes);
            out.u64(pending.at_ms);
        }
        Ok(())
    }
    pub(super) fn decode(input: &mut Reader<'_>) -> Result<Self, CloudDeviceError> {
        let blob = |input: &mut Reader<'_>| -> Result<Vec<u8>, CloudDeviceError> {
            let length = input.len(usize::MAX)?;
            Ok(input.take(length)?.to_vec())
        };
        let bad = |_| CloudDeviceError::Checkpoint;
        let mut bindings = Vec::new();
        for _ in 0..input.len(MAX_CHAT_BINDINGS)? {
            let grant = GrantReference {
                id: input.array()?,
                epoch: input.u64()?,
            };
            let binding = input.optional(|input| {
                SignedSshBinding::from_canonical_bytes(&blob(input)?).map_err(bad)
            })?;
            let update = input.optional(|input| {
                SshAccessUpdate::from_canonical_bytes(&blob(input)?).map_err(bad)
            })?;
            bindings.push(BindingState {
                grant,
                binding,
                update,
                subject_key: input.optional(Reader::array)?,
                withdrawn: input.bool()?,
            });
        }
        let mut requests = Vec::new();
        for _ in 0..input.len(MAX_SSH_REQUESTS)? {
            let request =
                SshCertificateRequest::from_canonical_bytes(&blob(input)?).map_err(bad)?;
            requests.push(PendingSshRequest {
                request,
                at_ms: input.u64()?,
            });
        }
        Ok(Self { bindings, requests })
    }
}

#[cfg(test)]
mod tests;
