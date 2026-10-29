use super::{MAX_RELAY_BINDING_BYTES, RelayFormatError};
use crate::cloud::{
    ChatCoordinate, CloudNamespace, CloudRoute, RecordContext, RunnerCoordinate,
    codec::{self, Reader},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayKind {
    Command = 1,
    Event = 2,
    Snapshot = 3,
    /// Account-authenticated key material only; never a command or task grant.
    ChatKeyGrant = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BindingBody {
    Command(CloudRoute),
    Record(RecordContext),
    Material(ChatCoordinate),
}

/// Routing only. No title, model, target, plaintext digest or authorization facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayBinding {
    kind: RelayKind,
    body: BindingBody,
}
impl RelayBinding {
    pub fn command(route: CloudRoute) -> Result<Self, RelayFormatError> {
        if route.runner.key_epoch == 0 {
            return Err(RelayFormatError::ZeroEpoch);
        }
        Ok(Self {
            kind: RelayKind::Command,
            body: BindingBody::Command(route),
        })
    }
    pub fn event(context: RecordContext) -> Self {
        Self {
            kind: RelayKind::Event,
            body: BindingBody::Record(context),
        }
    }
    pub fn snapshot(context: RecordContext) -> Self {
        Self {
            kind: RelayKind::Snapshot,
            body: BindingBody::Record(context),
        }
    }
    /// Routes a purpose10 chat-key envelope to the runner inbox. The routing is
    /// descriptive: the receiver must authenticate the account pin and exact
    /// coordinates before installing material, without admitting any execution.
    pub fn chat_key_grant(chat: ChatCoordinate) -> Self {
        Self {
            kind: RelayKind::ChatKeyGrant,
            body: BindingBody::Material(chat),
        }
    }
    pub fn kind(&self) -> RelayKind {
        self.kind
    }
    pub fn namespace(&self) -> &CloudNamespace {
        match &self.body {
            BindingBody::Command(r) => &r.namespace,
            BindingBody::Record(r) => r.chat().namespace(),
            BindingBody::Material(c) => c.namespace(),
        }
    }
    pub fn runner(&self) -> RunnerCoordinate {
        match &self.body {
            BindingBody::Command(r) => r.runner,
            BindingBody::Record(r) => r.chat().runner(),
            BindingBody::Material(c) => c.runner(),
        }
    }
    pub fn chat_id(&self) -> [u8; 16] {
        match &self.body {
            BindingBody::Command(r) => r.chat_id,
            BindingBody::Record(r) => r.chat().chat_id(),
            BindingBody::Material(c) => c.chat_id(),
        }
    }
    pub fn object_id(&self) -> [u8; 16] {
        match &self.body {
            BindingBody::Command(r) => r.command_id,
            BindingBody::Record(r) => r.id(),
            BindingBody::Material(c) => c.chat_id(),
        }
    }
    /// Exact key generation for material; no account/runner pin ownership implied.
    pub fn material_coordinate(&self) -> Option<&ChatCoordinate> {
        match &self.body {
            BindingBody::Material(chat) => Some(chat),
            _ => None,
        }
    }
    pub fn command_route(&self) -> Option<&CloudRoute> {
        match &self.body {
            BindingBody::Command(r) => Some(r),
            BindingBody::Record(_) | BindingBody::Material(_) => None,
        }
    }
    pub fn record_context(&self) -> Option<&RecordContext> {
        match &self.body {
            BindingBody::Command(_) | BindingBody::Material(_) => None,
            BindingBody::Record(r) => Some(r),
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RelayFormatError> {
        let mut bytes = Vec::with_capacity(640);
        codec::field(&mut bytes, b"nocterm/cloud-relay-binding/v1")?;
        bytes.push(self.kind as u8);
        let body = match &self.body {
            BindingBody::Command(route) => route.canonical_bytes()?,
            BindingBody::Record(context) => context.canonical_bytes()?,
            BindingBody::Material(chat) => {
                chat.canonical_bytes().map_err(RelayFormatError::Material)?
            }
        };
        codec::field(&mut bytes, &body)?;
        if bytes.len() > MAX_RELAY_BINDING_BYTES {
            return Err(RelayFormatError::Capacity);
        }
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RelayFormatError> {
        if bytes.len() > MAX_RELAY_BINDING_BYTES {
            return Err(RelayFormatError::Capacity);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-relay-binding/v1" {
            return Err(RelayFormatError::Malformed);
        }
        let kind = reader.array::<1>()?;
        let body = reader.field(MAX_RELAY_BINDING_BYTES)?;
        let binding = match kind {
            [1] => {
                let mut route = Reader::new(body);
                let binding = Self::command(CloudRoute::read(&mut route)?)?;
                route.finish()?;
                binding
            }
            [2] => Self::event(RecordContext::from_canonical_bytes(body)?),
            [3] => Self::snapshot(RecordContext::from_canonical_bytes(body)?),
            [4] => Self::chat_key_grant(
                ChatCoordinate::from_canonical_bytes(body).map_err(RelayFormatError::Material)?,
            ),
            _ => return Err(RelayFormatError::Malformed),
        };
        reader.finish()?;
        Ok(binding)
    }
}
