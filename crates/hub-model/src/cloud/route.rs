use super::{
    CommandError, MAX_ID_BYTES,
    codec::{self, Reader},
};
use sha2::{Digest, Sha256};

/// Opaque UTF-8 identity: checked byte length, with no normalization or trimming.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CloudTextId(String);

impl CloudTextId {
    pub fn new(text: impl AsRef<str>) -> Result<Self, CommandError> {
        let text = text.as_ref();
        if text.is_empty() || text.len() > MAX_ID_BYTES {
            return Err(CommandError::IdentityLength);
        }
        Ok(Self(text.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Derives the wire namespace from a retained authenticated hub identity.
/// The fingerprint must come from the caller's existing trust pin, never a hub directory.
/// Addresses and aliases do not enter the hash; rotation requires explicit scoped handling.
pub fn hub_namespace_id(
    raw_instance_id: &str,
    trusted_authority: [u8; 32],
) -> Result<CloudTextId, CommandError> {
    let raw = CloudTextId::new(raw_instance_id)?;
    let mut bytes = Vec::with_capacity(192);
    codec::field(&mut bytes, b"nocterm/cloud-hub-namespace/v1")?;
    codec::field(&mut bytes, raw.as_str().as_bytes())?;
    bytes.extend_from_slice(&trusted_authority);
    CloudTextId::new(hex::encode(Sha256::digest(bytes)))
}

/// Captured hub/account coordinates; identifiers are descriptive, not authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudNamespace {
    /// Wire namespace derived with hub_namespace_id, pinned during runner setup.
    pub hub_instance_id: CloudTextId,
    pub account_id: CloudTextId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunnerCoordinate {
    pub id: [u8; 16],
    pub key_epoch: u64,
}

/// The public routing tuple. It contains no prompt, model, title or target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudRoute {
    pub namespace: CloudNamespace,
    pub runner: RunnerCoordinate,
    pub chat_id: [u8; 16],
    pub command_id: [u8; 16],
}

impl CloudRoute {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CommandError> {
        let mut bytes = Vec::with_capacity(320);
        self.write(&mut bytes)?;
        Ok(bytes)
    }

    pub(super) fn write(&self, bytes: &mut Vec<u8>) -> Result<(), CommandError> {
        codec::field(bytes, self.namespace.hub_instance_id.as_str().as_bytes())?;
        codec::field(bytes, self.namespace.account_id.as_str().as_bytes())?;
        bytes.extend_from_slice(&self.runner.id);
        bytes.extend_from_slice(&self.runner.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.chat_id);
        bytes.extend_from_slice(&self.command_id);
        Ok(())
    }

    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Self, CommandError> {
        Ok(Self {
            namespace: CloudNamespace {
                hub_instance_id: reader.text()?,
                account_id: reader.text()?,
            },
            runner: RunnerCoordinate {
                id: reader.array()?,
                key_epoch: u64::from_be_bytes(reader.array()?),
            },
            chat_id: reader.array()?,
            command_id: reader.array()?,
        })
    }
}
