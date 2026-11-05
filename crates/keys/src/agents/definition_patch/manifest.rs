//! A public flat base can be reused only after its owner authenticates the prior context.
//! The manifest MAC uses the existing static account/pool DH with a distinct HKDF purpose.
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{DEFINITION_FORMAT_VERSION_PATCH, DefinitionBase, MAX_ENVELOPE_BYTES};
use crate::agents::{
    DefinitionContext, DefinitionError, SealDefinitionError, sealed_definition_version,
};
use crate::seal::{Purpose, aad};
use crate::{AccountKeyPair, KeyError, OpenError, PublicKey, SealError};

const HEADER: usize = 18;
const TAG: usize = 32;
const INFO: &[u8] = b"nocterm-agent-definition-model-patch-v3/manifest";

pub(super) struct Parsed<'a> {
    pub(super) base: DefinitionBase<'a>,
    pub(super) patch: &'a [u8],
    tagged: &'a [u8],
    tag: &'a [u8],
}

pub(super) fn parse(sealed: &[u8]) -> Result<Parsed<'_>, OpenError> {
    if sealed.len() < HEADER + TAG
        || sealed.len() > MAX_ENVELOPE_BYTES
        || sealed_definition_version(sealed) != Some(DEFINITION_FORMAT_VERSION_PATCH)
    {
        return Err(OpenError::Malformed);
    }
    let version = u64::from_be_bytes(sealed[2..10].try_into().map_err(|_| OpenError::Malformed)?);
    let base_len = usize::try_from(u32::from_be_bytes(
        sealed[10..14]
            .try_into()
            .map_err(|_| OpenError::Malformed)?,
    ))
    .map_err(|_| OpenError::Malformed)?;
    let patch_len = usize::try_from(u32::from_be_bytes(
        sealed[14..18]
            .try_into()
            .map_err(|_| OpenError::Malformed)?,
    ))
    .map_err(|_| OpenError::Malformed)?;
    let base_end = HEADER.checked_add(base_len).ok_or(OpenError::Malformed)?;
    let patch_end = base_end
        .checked_add(patch_len)
        .ok_or(OpenError::Malformed)?;
    if patch_end.checked_add(TAG) != Some(sealed.len()) {
        return Err(OpenError::Malformed);
    }
    let base = &sealed[HEADER..base_end];
    let patch = &sealed[base_end..patch_end];
    if !matches!(sealed_definition_version(base), Some(1 | 2))
        || sealed_definition_version(patch) != Some(DEFINITION_FORMAT_VERSION_PATCH)
    {
        return Err(OpenError::Malformed);
    }
    Ok(Parsed {
        base: DefinitionBase {
            version,
            envelope: base,
        },
        patch,
        tagged: &sealed[..patch_end],
        tag: &sealed[patch_end..],
    })
}

pub(super) fn seal(
    owner: &AccountKeyPair,
    pool: &PublicKey,
    context: &DefinitionContext,
    base: &DefinitionBase<'_>,
    patch: &[u8],
) -> Result<Vec<u8>, SealDefinitionError> {
    if HEADER + base.envelope.len() + patch.len() + TAG > MAX_ENVELOPE_BYTES {
        return Err(
            DefinitionError::TooLarge("model edit; replace the complete definition").into(),
        );
    }
    let base_len = u32::try_from(base.envelope.len())
        .map_err(|_| DefinitionError::TooLarge("model edit base"))?;
    let patch_len =
        u32::try_from(patch.len()).map_err(|_| DefinitionError::TooLarge("model edit patch"))?;
    let mut sealed = Vec::with_capacity(HEADER + base.envelope.len() + patch.len() + TAG);
    sealed.extend([
        DEFINITION_FORMAT_VERSION_PATCH,
        Purpose::AgentDefinition as u8,
    ]);
    sealed.extend(base.version.to_be_bytes());
    sealed.extend(base_len.to_be_bytes());
    sealed.extend(patch_len.to_be_bytes());
    sealed.extend(base.envelope);
    sealed.extend(patch);
    let owner_public = owner.public_key();
    let key = key(owner, pool, &owner_public, pool)?;
    let tag = mac(&key, context, &owner_public, &sealed)?
        .finalize()
        .into_bytes();
    sealed.extend(tag);
    Ok(sealed)
}

fn key(
    local: &AccountKeyPair,
    peer: &PublicKey,
    owner: &PublicKey,
    pool: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let shared = local.agree(peer.as_bytes());
    if !shared.was_contributory() {
        return Err(SealError::UnusableRecipientKey);
    }
    let mut salt = [0; 64];
    salt[..32].copy_from_slice(owner.as_bytes());
    salt[32..].copy_from_slice(pool.as_bytes());
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(INFO, key.as_mut())
        .map_err(KeyError::Expand)?;
    Ok(key)
}

fn mac(
    key: &[u8; 32],
    context: &DefinitionContext,
    owner: &PublicKey,
    tagged: &[u8],
) -> Result<Hmac<Sha256>, SealError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| SealError::Encrypt)?;
    context.with_sender(owner, |parts| {
        mac.update(&aad(Purpose::AgentDefinition, parts));
    });
    mac.update(tagged);
    Ok(mac)
}

pub(super) fn verify_owner(
    owner: &AccountKeyPair,
    pool: &PublicKey,
    context: &DefinitionContext,
    parsed: &Parsed<'_>,
) -> Result<(), OpenError> {
    let owner_public = owner.public_key();
    let key = key(owner, pool, &owner_public, pool).map_err(|_| OpenError::Rejected)?;
    verify(&key, context, &owner_public, parsed)
}

pub(super) fn verify_pool(
    pool: &AccountKeyPair,
    owner: &PublicKey,
    context: &DefinitionContext,
    parsed: &Parsed<'_>,
) -> Result<(), OpenError> {
    let key = key(pool, owner, owner, &pool.public_key()).map_err(|_| OpenError::Rejected)?;
    verify(&key, context, owner, parsed)
}

fn verify(
    key: &[u8; 32],
    context: &DefinitionContext,
    owner: &PublicKey,
    parsed: &Parsed<'_>,
) -> Result<(), OpenError> {
    if parsed.base.version == 0 || parsed.base.version >= context.version {
        return Err(OpenError::Malformed);
    }
    mac(key, context, owner, parsed.tagged)
        .map_err(|_| OpenError::Rejected)?
        .verify_slice(parsed.tag)
        .map_err(|_| OpenError::Rejected)
}
