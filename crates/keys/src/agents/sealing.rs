//! Sealing a definition from its owner to the pool's encryption key.
use nocterm_hub_model::agents::AgentScope;
use nocterm_hub_model::{AgentId, PoolId};

use super::boxed::{box_open, box_open_versioned, box_seal, box_seal_versioned};
use super::definition::{AgentDefinitionV1, DefinitionError};
use super::definition_v2::AgentDefinitionV2;
use crate::seal::{FORMAT_VERSION, Purpose};
use crate::{AccountKeyPair, OpenError, PublicKey, SealError};

const INFO: &[u8] = b"nocterm-agent-definition-v1/auth";
/// A label of its own, so an envelope whose version byte was changed does not open.
const INFO_V2: &[u8] = b"nocterm-agent-definition-v2/auth";

/// What a sealed definition is bound to. Opening under any other value fails, so the hub
/// cannot move an envelope to another agent, scope, pool or version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefinitionContext {
    /// The agent the definition belongs to.
    pub agent: AgentId,
    /// The scope that owns the agent.
    pub scope: AgentScope,
    /// The pool the envelope is addressed to.
    pub pool: PoolId,
    /// The version of the agent the envelope is written for.
    pub version: u64,
}

impl DefinitionContext {
    fn parts(&self) -> [String; 4] {
        [
            self.agent.to_string(),
            self.scope.canonical_text(),
            self.pool.to_string(),
            self.version.to_string(),
        ]
    }

    fn with_sender<R>(&self, sender: &PublicKey, f: impl FnOnce(&[&str]) -> R) -> R {
        let [agent, scope, pool, version] = self.parts();
        let fingerprint = sender.fingerprint();
        f(&[&agent, &scope, &pool, &version, &fingerprint])
    }
}

/// A definition could not be sealed.
#[derive(Debug, thiserror::Error)]
pub enum SealDefinitionError {
    /// The definition is invalid or too large.
    #[error(transparent)]
    Definition(#[from] DefinitionError),
    /// The box could not be made.
    #[error(transparent)]
    Seal(#[from] SealError),
}

/// A sealed definition could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenDefinitionError {
    /// The envelope is not an agent definition, or does not open under this context and keys.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// The plaintext is not a valid definition of the envelope's version.
    #[error(transparent)]
    Definition(#[from] DefinitionError),
}

/// A definition of any version this crate reads, as [`open_definition_any`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDefinition {
    /// Format version [`DEFINITION_FORMAT_VERSION`].
    V1(AgentDefinitionV1),
    /// Format version [`DEFINITION_FORMAT_VERSION_V2`].
    V2(AgentDefinitionV2),
}

impl AgentDefinition {
    /// The format version byte of the envelope it came from.
    pub fn format_version(&self) -> u8 {
        match self {
            Self::V1(_) => DEFINITION_FORMAT_VERSION,
            Self::V2(_) => DEFINITION_FORMAT_VERSION_V2,
        }
    }

    /// The definition as version 2; a version 1 definition gets the meaning it always had
    /// (see `From<AgentDefinitionV1> for AgentDefinitionV2`).
    pub fn into_v2(self) -> AgentDefinitionV2 {
        match self {
            Self::V1(v1) => v1.into(),
            Self::V2(v2) => v2,
        }
    }
}

/// Seals `definition` from the owner's pair to the pool's encryption key.
pub fn seal_definition(
    owner: &AccountKeyPair,
    pool_encryption: &PublicKey,
    context: &DefinitionContext,
    definition: &AgentDefinitionV1,
) -> Result<Vec<u8>, SealDefinitionError> {
    let plaintext = definition.encode()?;
    let sealed = context.with_sender(&owner.public_key(), |parts| {
        box_seal(
            Purpose::AgentDefinition,
            INFO,
            owner,
            pool_encryption,
            parts,
            &plaintext,
        )
    })?;
    Ok(sealed)
}

/// Opens an envelope with the pool's encryption pair, for an owner whose public key the pool
/// host pinned.
pub fn open_definition(
    pool_encryption: &AccountKeyPair,
    owner: &PublicKey,
    context: &DefinitionContext,
    sealed: &[u8],
) -> Result<AgentDefinitionV1, OpenDefinitionError> {
    let plaintext = context.with_sender(owner, |parts| {
        box_open(
            Purpose::AgentDefinition,
            INFO,
            pool_encryption,
            owner,
            parts,
            sealed,
        )
    })?;
    Ok(AgentDefinitionV1::decode(&plaintext)?)
}

/// Seals a version 2 `definition` from the owner's pair to the pool's encryption key. The
/// envelope carries [`DEFINITION_FORMAT_VERSION_V2`]; only a host that reads version 2 opens it.
pub fn seal_definition_v2(
    owner: &AccountKeyPair,
    pool_encryption: &PublicKey,
    context: &DefinitionContext,
    definition: &AgentDefinitionV2,
) -> Result<Vec<u8>, SealDefinitionError> {
    let plaintext = definition.encode()?;
    let sealed = context.with_sender(&owner.public_key(), |parts| {
        box_seal_versioned(
            DEFINITION_FORMAT_VERSION_V2,
            Purpose::AgentDefinition,
            INFO_V2,
            owner,
            pool_encryption,
            parts,
            &plaintext,
        )
    })?;
    Ok(sealed)
}

/// Opens an envelope of any version this crate reads, chosen by its version byte, with the
/// pool's encryption pair, for an owner whose public key the pool host pinned. An unknown
/// version is [`OpenError::Malformed`].
pub fn open_definition_any(
    pool_encryption: &AccountKeyPair,
    owner: &PublicKey,
    context: &DefinitionContext,
    sealed: &[u8],
) -> Result<AgentDefinition, OpenDefinitionError> {
    match sealed_definition_version(sealed) {
        Some(DEFINITION_FORMAT_VERSION) => Ok(AgentDefinition::V1(open_definition(
            pool_encryption,
            owner,
            context,
            sealed,
        )?)),
        Some(DEFINITION_FORMAT_VERSION_V2) => {
            let plaintext = context.with_sender(owner, |parts| {
                box_open_versioned(
                    DEFINITION_FORMAT_VERSION_V2,
                    Purpose::AgentDefinition,
                    INFO_V2,
                    pool_encryption,
                    owner,
                    parts,
                    sealed,
                )
            })?;
            Ok(AgentDefinition::V2(AgentDefinitionV2::decode(&plaintext)?))
        }
        _ => Err(OpenError::Malformed.into()),
    }
}

/// The format version byte of a sealed definition, or `None` for something that is not one.
/// A host reads it to choose the decoder before it opens; the hub may read it to route an
/// envelope only to hosts that read its version.
pub fn sealed_definition_version(sealed: &[u8]) -> Option<u8> {
    match sealed {
        [version, purpose, ..] if *purpose == Purpose::AgentDefinition as u8 => Some(*version),
        _ => None,
    }
}

/// Format version 1 ([`AgentDefinitionV1`]), written by [`seal_definition`] and read by
/// [`open_definition`].
pub const DEFINITION_FORMAT_VERSION: u8 = FORMAT_VERSION;

/// Format version 2 ([`AgentDefinitionV2`]), written by [`seal_definition_v2`].
pub const DEFINITION_FORMAT_VERSION_V2: u8 = 2;

/// Every format version [`open_definition_any`] reads, oldest first.
pub const DEFINITION_FORMAT_VERSIONS: [u8; 2] =
    [DEFINITION_FORMAT_VERSION, DEFINITION_FORMAT_VERSION_V2];

#[cfg(test)]
mod tests {
    use super::super::definition::sample;
    use super::super::definition_v2::sample_v2;
    use super::*;

    struct World {
        owner: AccountKeyPair,
        pool: AccountKeyPair,
        context: DefinitionContext,
    }

    fn world() -> World {
        World {
            owner: AccountKeyPair::generate().unwrap(),
            pool: AccountKeyPair::generate().unwrap(),
            context: DefinitionContext {
                agent: AgentId::new(),
                scope: AgentScope::Account,
                pool: PoolId::new(),
                version: 3,
            },
        }
    }

    fn seal(w: &World) -> Vec<u8> {
        seal_definition(&w.owner, &w.pool.public_key(), &w.context, &sample()).unwrap()
    }

    #[test]
    fn the_pool_opens_what_the_owner_sealed() {
        let w = world();
        let sealed = seal(&w);
        assert_eq!(
            sealed_definition_version(&sealed),
            Some(DEFINITION_FORMAT_VERSION)
        );
        let opened = open_definition(&w.pool, &w.owner.public_key(), &w.context, &sealed).unwrap();
        assert_eq!(opened, sample());
    }

    #[test]
    fn every_bound_value_is_checked() {
        let w = world();
        let sealed = seal(&w);
        let open = |pool: &AccountKeyPair, owner: &PublicKey, c: &DefinitionContext| {
            open_definition(pool, owner, c, &sealed).is_err()
        };
        let mut moved = w.context;
        moved.agent = AgentId::new();
        assert!(open(&w.pool, &w.owner.public_key(), &moved));
        let mut moved = w.context;
        moved.scope = AgentScope::Instance;
        assert!(open(&w.pool, &w.owner.public_key(), &moved));
        let mut moved = w.context;
        moved.pool = PoolId::new();
        assert!(open(&w.pool, &w.owner.public_key(), &moved));
        let mut moved = w.context;
        moved.version += 1;
        assert!(open(&w.pool, &w.owner.public_key(), &moved));
        let stranger = AccountKeyPair::generate().unwrap();
        assert!(open(&w.pool, &stranger.public_key(), &w.context));
        assert!(open(&stranger, &w.owner.public_key(), &w.context));
    }

    #[test]
    fn damage_and_foreign_formats_are_malformed_or_rejected() {
        let w = world();
        let mut sealed = seal(&w);
        assert_eq!(sealed_definition_version(&[1, 7]), None);
        assert!(
            open_definition(&w.pool, &w.owner.public_key(), &w.context, &sealed[..10]).is_err()
        );
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open_definition(&w.pool, &w.owner.public_key(), &w.context, &sealed).is_err());
    }

    #[test]
    fn an_invalid_definition_is_not_sealed() {
        let w = world();
        let mut definition = sample();
        definition.name.clear();
        assert!(seal_definition(&w.owner, &w.pool.public_key(), &w.context, &definition).is_err());
    }

    #[test]
    fn a_version_two_envelope_opens_with_its_policy_and_version_one_still_opens() {
        let w = world();
        let v2 =
            seal_definition_v2(&w.owner, &w.pool.public_key(), &w.context, &sample_v2()).unwrap();
        assert_eq!(
            sealed_definition_version(&v2),
            Some(DEFINITION_FORMAT_VERSION_V2)
        );
        let opened = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &v2).unwrap();
        assert_eq!(opened.format_version(), DEFINITION_FORMAT_VERSION_V2);
        assert_eq!(opened, AgentDefinition::V2(sample_v2()));
        assert!(open_definition(&w.pool, &w.owner.public_key(), &w.context, &v2).is_err());

        let v1 = seal(&w);
        let opened = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &v1).unwrap();
        assert_eq!(opened, AgentDefinition::V1(sample()));
        assert_eq!(opened.into_v2(), AgentDefinitionV2::from(sample()));
    }

    #[test]
    fn a_changed_version_byte_or_context_does_not_open_a_version_two_envelope() {
        let w = world();
        let v2 =
            seal_definition_v2(&w.owner, &w.pool.public_key(), &w.context, &sample_v2()).unwrap();
        let mut relabelled = v2.clone();
        relabelled[0] = DEFINITION_FORMAT_VERSION;
        assert!(
            open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &relabelled).is_err()
        );
        let mut unknown = v2.clone();
        unknown[0] = 9;
        assert!(matches!(
            open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &unknown),
            Err(OpenDefinitionError::Open(OpenError::Malformed))
        ));
        let mut moved = w.context;
        moved.version += 1;
        assert!(open_definition_any(&w.pool, &w.owner.public_key(), &moved, &v2).is_err());
        let stranger = AccountKeyPair::generate().unwrap();
        assert!(open_definition_any(&w.pool, &stranger.public_key(), &w.context, &v2).is_err());
    }

    #[test]
    fn an_invalid_version_two_definition_is_not_sealed() {
        let w = world();
        let mut definition = sample_v2();
        definition.limits.max_turns = Some(0);
        assert!(
            seal_definition_v2(&w.owner, &w.pool.public_key(), &w.context, &definition).is_err()
        );
    }

    #[test]
    fn sealing_twice_gives_different_envelopes() {
        let w = world();
        assert_ne!(seal(&w), seal(&w));
    }
}
