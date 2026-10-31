//! The plaintext of an agent: what the owner configures and only the pool host may read.
use std::fmt;

use nocterm_hub_model::agents::limits::{
    MAX_ENDPOINT_BYTES, MAX_MODEL_ID_BYTES, MAX_MODELS, MAX_NAME_BYTES, MAX_SECRET_BYTES,
    MAX_SYSTEM_PROMPT_BYTES,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Longest serialized definition. Bounds what the host allocates for one open.
pub const MAX_DEFINITION_BYTES: usize = 128 * 1024 - 1024;
/// Entries of each list inside a definition.
pub const MAX_DEFINITION_ENTRIES: usize = 32;

/// A definition that cannot be encoded or decoded.
#[derive(Debug, thiserror::Error)]
pub enum DefinitionError {
    /// A field or the whole definition exceeds its limit.
    #[error("the agent definition exceeds the limit of {0}")]
    TooLarge(&'static str),
    /// A required field is empty.
    #[error("the agent definition lacks {0}")]
    Missing(&'static str),
    /// A field holds a value its version does not allow (a zero limit, a duplicate, a price
    /// for a model the provider does not list).
    #[error("the agent definition has an invalid {0}")]
    Invalid(&'static str),
    /// The bytes are not a definition of the expected version.
    #[error("the bytes are not an agent definition of the expected version")]
    Malformed(#[source] postcard::Error),
    /// The definition could not be serialized.
    #[error("the agent definition could not be serialized")]
    Encode(#[source] postcard::Error),
}

/// Where the agent reaches its model provider.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct ProviderBlock {
    /// Provider family, for example `openai_chat`.
    pub kind: String,
    /// Base URL; empty means the family default.
    pub endpoint: String,
    /// Model ids the agent may use.
    pub models: Vec<String>,
    /// The real API key. Never leaves the broker in a lease: sealed to it separately.
    pub api_key: Option<String>,
}

/// An SSH target the agent may be given a certificate for.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SshTarget {
    /// Host name or address.
    pub host: String,
    /// Remote user.
    pub user: String,
    /// TCP port.
    pub port: u16,
}

/// Version 1 of the plaintext of an agent. Field order is the wire format: append only in a
/// new version, never reorder.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct AgentDefinitionV1 {
    /// Agent name shown to people.
    pub name: String,
    /// The system prompt.
    pub instructions: String,
    /// Model provider.
    pub provider: ProviderBlock,
    /// Named secrets exposed to tools through the broker.
    pub secrets: Vec<(String, String)>,
    /// Hosts the agent's network tools may reach.
    pub allowed_hosts: Vec<String>,
    /// SSH targets.
    pub ssh_targets: Vec<SshTarget>,
}

impl fmt::Debug for ProviderBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderBlock")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SshTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshTarget")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AgentDefinitionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentDefinitionV1")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl AgentDefinitionV1 {
    /// Checks the limits that bound memory and the fields without which an agent cannot run.
    pub fn validate(&self) -> Result<(), DefinitionError> {
        validate_base(&BaseFields {
            name: &self.name,
            instructions: &self.instructions,
            provider: &self.provider,
            secrets: &self.secrets,
            allowed_hosts: &self.allowed_hosts,
            ssh_targets: &self.ssh_targets,
        })
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DefinitionError> {
        self.validate()?;
        encode_bounded(self)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DefinitionError> {
        let definition: Self = decode_bounded(bytes)?;
        definition.validate()?;
        Ok(definition)
    }
}

/// Serializes a validated definition of any version and checks the total size.
pub(super) fn encode_bounded<T: Serialize>(
    definition: &T,
) -> Result<Zeroizing<Vec<u8>>, DefinitionError> {
    let bytes = Zeroizing::new(postcard::to_stdvec(definition).map_err(DefinitionError::Encode)?);
    if bytes.len() > MAX_DEFINITION_BYTES {
        return Err(DefinitionError::TooLarge("definition"));
    }
    Ok(bytes)
}

/// Deserializes a definition of any version after checking the total size and refuses bytes
/// after its last field, so the bytes of one version never read as another. The caller
/// validates the result.
pub(super) fn decode_bounded<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, DefinitionError> {
    if bytes.len() > MAX_DEFINITION_BYTES {
        return Err(DefinitionError::TooLarge("definition"));
    }
    let (definition, rest) =
        postcard::take_from_bytes(bytes).map_err(DefinitionError::Malformed)?;
    if !rest.is_empty() {
        return Err(DefinitionError::Invalid(
            "length (bytes after the last field)",
        ));
    }
    Ok(definition)
}

/// The fields every definition version starts with, in their wire order.
pub(super) struct BaseFields<'a> {
    pub(super) name: &'a str,
    pub(super) instructions: &'a str,
    pub(super) provider: &'a ProviderBlock,
    pub(super) secrets: &'a [(String, String)],
    pub(super) allowed_hosts: &'a [String],
    pub(super) ssh_targets: &'a [SshTarget],
}

/// The checks of version 1, shared by every later version.
pub(super) fn validate_base(base: &BaseFields<'_>) -> Result<(), DefinitionError> {
    if base.name.is_empty() {
        return Err(DefinitionError::Missing("a name"));
    }
    if base.provider.kind.is_empty() || base.provider.models.is_empty() {
        return Err(DefinitionError::Missing("a provider and a model"));
    }
    fits(base.name.len() <= MAX_NAME_BYTES, "name")?;
    fits(
        base.instructions.len() <= MAX_SYSTEM_PROMPT_BYTES,
        "instructions",
    )?;
    fits(
        base.provider.endpoint.len() <= MAX_ENDPOINT_BYTES,
        "endpoint",
    )?;
    fits(base.provider.models.len() <= MAX_MODELS, "models")?;
    fits(
        base.provider
            .models
            .iter()
            .all(|m| m.len() <= MAX_MODEL_ID_BYTES),
        "model id",
    )?;
    fits(
        base.provider
            .api_key
            .as_ref()
            .is_none_or(|k| k.len() <= MAX_SECRET_BYTES),
        "api key",
    )?;
    fits(base.secrets.len() <= MAX_DEFINITION_ENTRIES, "secrets")?;
    fits(
        base.secrets
            .iter()
            .all(|(n, v)| n.len() <= MAX_NAME_BYTES && v.len() <= MAX_SECRET_BYTES),
        "secret",
    )?;
    fits(
        base.allowed_hosts.len() <= MAX_DEFINITION_ENTRIES,
        "allowed hosts",
    )?;
    fits(
        base.allowed_hosts
            .iter()
            .all(|h| h.len() <= MAX_ENDPOINT_BYTES),
        "allowed host",
    )?;
    fits(
        base.ssh_targets.len() <= MAX_DEFINITION_ENTRIES,
        "ssh targets",
    )
}

/// `Ok` when `ok`, otherwise the limit named `what` was exceeded.
pub(super) fn fits(ok: bool, what: &'static str) -> Result<(), DefinitionError> {
    ok.then_some(()).ok_or(DefinitionError::TooLarge(what))
}

#[cfg(test)]
pub(crate) fn sample() -> AgentDefinitionV1 {
    AgentDefinitionV1 {
        name: "Deploy helper".into(),
        instructions: "Be careful.".into(),
        provider: ProviderBlock {
            kind: "openai_chat".into(),
            endpoint: String::new(),
            models: vec!["gpt".into()],
            api_key: Some("sk-secret".into()),
        },
        secrets: vec![("TOKEN".into(), "t".into())],
        allowed_hosts: vec!["example.com".into()],
        ssh_targets: vec![SshTarget {
            host: "prod-1".into(),
            user: "deploy".into(),
            port: 22,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_definition_round_trips_and_debug_hides_secrets() {
        let definition = sample();
        let bytes = definition.encode().unwrap();
        assert_eq!(AgentDefinitionV1::decode(&bytes).unwrap(), definition);
        assert!(!format!("{definition:?}").contains("sk-secret"));
    }

    #[test]
    fn limits_and_required_fields_are_enforced_in_both_directions() {
        let mut definition = sample();
        definition.name.clear();
        assert!(matches!(
            definition.encode(),
            Err(DefinitionError::Missing(_))
        ));
        let mut definition = sample();
        definition.instructions = "x".repeat(MAX_SYSTEM_PROMPT_BYTES + 1);
        assert!(matches!(
            definition.encode(),
            Err(DefinitionError::TooLarge("instructions"))
        ));
        assert!(matches!(
            AgentDefinitionV1::decode(&vec![0; MAX_DEFINITION_BYTES + 1]),
            Err(DefinitionError::TooLarge(_))
        ));
        assert!(matches!(
            AgentDefinitionV1::decode(&[0xff, 0xff]),
            Err(DefinitionError::Malformed(_))
        ));
    }
}
