//! Model edits preserve the rest of a definition inside its original authenticated envelope.
//! A verified flat manifest retains one base and the latest model set, across repeated edits.
use std::collections::BTreeSet;

use nocterm_hub_model::agents::limits::{MAX_ENVELOPE_BYTES, MAX_MODEL_ID_BYTES, MAX_MODELS};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::boxed::{box_open_versioned, box_seal_versioned};
use super::definition::{DefinitionError, decode_bounded, encode_bounded};
use super::sealing::{
    AgentDefinition, DefinitionContext, OpenDefinitionError, SealDefinitionError,
    open_definition_any, sealed_definition_version,
};
use crate::seal::Purpose;
use crate::{AccountKeyPair, PublicKey};

mod manifest;

/// An encrypted, authenticated edit of the model list of an existing definition.
pub const DEFINITION_FORMAT_VERSION_PATCH: u8 = 3;
const INFO: &[u8] = b"nocterm-agent-definition-model-patch-v3/auth";

/// A model-only edit. Every other field, including keys and surviving prices, is retained.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentModelPatch {
    /// The complete nonempty set of allowed model ids, in display order.
    pub models: Vec<String>,
}

impl AgentModelPatch {
    fn validate(&self) -> Result<(), DefinitionError> {
        if self.models.is_empty() {
            return Err(DefinitionError::Missing("a model"));
        }
        if self.models.len() > MAX_MODELS {
            return Err(DefinitionError::TooLarge("models"));
        }
        let unique: BTreeSet<_> = self.models.iter().collect();
        if unique.len() != self.models.len() || self.models.iter().any(String::is_empty) {
            return Err(DefinitionError::Invalid("model ids"));
        }
        if self.models.iter().any(|id| id.len() > MAX_MODEL_ID_BYTES) {
            return Err(DefinitionError::TooLarge("model id"));
        }
        Ok(())
    }

    fn apply(&self, definition: &mut super::AgentDefinitionV2) -> Result<(), DefinitionError> {
        self.validate()?;
        definition.provider.models.clone_from(&self.models);
        definition
            .pricing
            .retain(|price| self.models.contains(&price.model));
        definition.validate()
    }
}

/// The exact existing envelope the current authorized writer chooses to retain.
#[derive(Debug)]
pub struct DefinitionBase<'a> {
    /// Its original sealing version, which may precede the listing's current version.
    pub version: u64,
    /// Its bytes, unchanged. It must name the same agent, scope, pool and owner.
    pub envelope: &'a [u8],
}

/// Seals a model edit without opening or discarding any private setting. Editing another
/// model edit verifies its original manifest, then retains the same complete base once.
pub fn seal_definition_patch(
    owner: &AccountKeyPair,
    pool_encryption: &PublicKey,
    context: &DefinitionContext,
    base: &DefinitionBase<'_>,
    patch: &AgentModelPatch,
) -> Result<Vec<u8>, SealDefinitionError> {
    patch.validate()?;
    check_version(base.version, context.version)?;
    let stable = stable_base(owner, pool_encryption, context, base)?;
    let plaintext = encode_bounded(patch)?;
    let sealed_patch = with_base(context, &owner.public_key(), &stable, |parts| {
        box_seal_versioned(
            DEFINITION_FORMAT_VERSION_PATCH,
            Purpose::AgentDefinition,
            INFO,
            owner,
            pool_encryption,
            parts,
            &plaintext,
        )
    })?;
    manifest::seal(owner, pool_encryption, context, &stable, &sealed_patch)
}

fn stable_base<'a>(
    owner: &AccountKeyPair,
    pool: &PublicKey,
    context: &DefinitionContext,
    base: &DefinitionBase<'a>,
) -> Result<DefinitionBase<'a>, SealDefinitionError> {
    if base.envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(DefinitionError::TooLarge("model edit base").into());
    }
    match sealed_definition_version(base.envelope) {
        Some(1 | 2) => Ok(DefinitionBase {
            version: base.version,
            envelope: base.envelope,
        }),
        Some(DEFINITION_FORMAT_VERSION_PATCH) => {
            let previous_context = DefinitionContext {
                version: base.version,
                ..*context
            };
            let parsed = manifest::parse(base.envelope).map_err(SealDefinitionError::Base)?;
            manifest::verify_owner(owner, pool, &previous_context, &parsed)
                .map_err(SealDefinitionError::Base)?;
            Ok(parsed.base)
        }
        _ => Err(DefinitionError::Invalid("model edit base format").into()),
    }
}

fn check_version(base: u64, version: u64) -> Result<(), DefinitionError> {
    if base == 0 || base >= version {
        return Err(DefinitionError::Invalid("model edit base version"));
    }
    Ok(())
}

fn with_base<R>(
    context: &DefinitionContext,
    owner: &PublicKey,
    base: &DefinitionBase<'_>,
    f: impl FnOnce(&[&str]) -> R,
) -> R {
    let version = base.version.to_string();
    let digest = hex::encode(Sha256::digest(base.envelope));
    context.with_sender(owner, |parts| {
        let mut parts = parts.to_vec();
        parts.extend([version.as_str(), digest.as_str()]);
        f(&parts)
    })
}

pub(super) fn open(
    pool: &AccountKeyPair,
    owner: &PublicKey,
    context: &DefinitionContext,
    sealed: &[u8],
) -> Result<AgentDefinition, OpenDefinitionError> {
    let parsed = manifest::parse(sealed)?;
    manifest::verify_pool(pool, owner, context, &parsed)?;
    check_version(parsed.base.version, context.version)?;
    let plaintext = with_base(context, owner, &parsed.base, |parts| {
        box_open_versioned(
            DEFINITION_FORMAT_VERSION_PATCH,
            Purpose::AgentDefinition,
            INFO,
            pool,
            owner,
            parts,
            parsed.patch,
        )
    })?;
    let patch: AgentModelPatch = decode_bounded(&plaintext)?;
    patch.validate()?;
    let base_context = DefinitionContext {
        version: parsed.base.version,
        ..*context
    };
    // parse() permits a complete format 1/2 base only: opening never recurses into an edit.
    let mut definition =
        open_definition_any(pool, owner, &base_context, parsed.base.envelope)?.into_v2();
    patch.apply(&mut definition)?;
    Ok(AgentDefinition::V3(definition))
}

#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;
