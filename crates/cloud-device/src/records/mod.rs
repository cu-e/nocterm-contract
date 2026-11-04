//! The account's private Cloud records in personal Store collections.
//!
//! These layouts were defined by the native client and are specified here from the format
//! (ADR 0006); the fixtures in `fixtures/cloud-device-v1/desktop-*.txt` are bytes produced by the
//! native encoder and must stay identical. Each object is sealed by its collection key with
//! [`nocterm_keys::CollectionKey::seal_object`], which binds collection id, object id and kind.
mod hub_trust;
mod material;
mod provider_key;
mod registry;

pub use hub_trust::{HUB_TRUST_KIND, HUB_TRUST_OBJECT, HubTrustRecord};
pub use material::{
    CHAT_GRANT_KIND, CHAT_MATERIAL_KIND, ChatGrantRecord, ChatMaterialRecord, ChatSelector,
    account_collection_id,
};
pub use provider_key::{PROVIDER_KEYS_KIND, ProviderKeyRecord, provider_key_object};
pub use registry::{
    MAX_TRUSTED_RUNNERS, RUNNER_REGISTRY_KIND, RUNNER_REGISTRY_OBJECT, RunnerPins, RunnerRegistry,
    TrustedRunner,
};

use crate::CloudDeviceError;
use nocterm_keys::CollectionKey;
use zeroize::Zeroizing;

/// Authentication tag and framing a sealed object adds to its plaintext.
const SEAL_OVERHEAD: usize = 42;

/// One object as `StoreService.GetObject` returned it. Plain data; its `open` checks
/// it names the expected selector, is live and has the expected version before opening.
#[derive(Clone, Copy, Debug)]
pub struct StoredObject<'a> {
    pub collection_id: &'a str,
    pub object_id: &'a str,
    pub kind: &'a str,
    pub version: u64,
    pub deleted: bool,
    pub ciphertext: &'a [u8],
}
impl StoredObject<'_> {
    /// Opens the object under its collection key after checking its selector.
    /// `version` is `None` when the layout itself carries the version (the registry).
    pub(crate) fn open(
        &self,
        key: &CollectionKey,
        expected: (&str, &str, &str),
        version: Option<u64>,
        max_plaintext: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CloudDeviceError> {
        let (collection, object, kind) = expected;
        if self.collection_id != collection || self.object_id != object || self.kind != kind {
            return Err(CloudDeviceError::Binding);
        }
        if self.deleted {
            return Err(CloudDeviceError::Deleted);
        }
        if version.is_some_and(|expected| expected != self.version) || self.version == 0 {
            return Err(CloudDeviceError::ObjectVersion(self.version));
        }
        if self.ciphertext.len() > max_plaintext + SEAL_OVERHEAD
            || self.ciphertext.len() < SEAL_OVERHEAD
        {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(key.open_object(collection, object, kind, self.ciphertext)?)
    }
}

/// The Store collection identifier for a digest: its first 16 bytes as a version 8 UUID.
fn collection_uuid(digest: &[u8]) -> String {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Strict reader over a record body; every error is [`CloudDeviceError::Format`].
struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], CloudDeviceError> {
        let (value, rest) = self
            .bytes
            .split_at_checked(count)
            .ok_or(CloudDeviceError::Format)?;
        self.bytes = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CloudDeviceError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CloudDeviceError::Format)
    }
    fn u8(&mut self) -> Result<u8, CloudDeviceError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, CloudDeviceError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, CloudDeviceError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn text(&mut self, length: usize) -> Result<&'a str, CloudDeviceError> {
        std::str::from_utf8(self.take(length)?).map_err(|_| CloudDeviceError::Format)
    }
    fn finish(&self) -> Result<(), CloudDeviceError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(CloudDeviceError::Format)
        }
    }
}

/// Appends a text with a big-endian u16 length; the caller bounds the length.
fn push_u16_text(bytes: &mut Vec<u8>, text: &str) -> Result<(), CloudDeviceError> {
    let length = u16::try_from(text.len()).map_err(|_| CloudDeviceError::Capacity)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(text.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests;
