//! `agent_provider_keys` / `key-<agent>`: the provider key of an agent that runs on the person's
//! own runner (ADR 0126 of the native client). It never goes to a pool; a device of the account
//! opens it only to seal a short lease to the runner's verified boot.
//!
//! Layout (format 1, written by the native client): UTF-8 JSON
//! `{"format":1,"provider":<text>,"model":<text>,"key":<standard base64 of the key's UTF-8>}`.
//! The record lives in a personal collection of kind `agent_provider_keys`, sealed by its
//! collection key with object id `key-<agent id>` and that kind. `Debug` never shows the key.
use super::{SEAL_OVERHEAD, StoredObject};
use crate::CloudDeviceError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use core::fmt;
use nocterm_keys::CollectionKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const PROVIDER_KEYS_KIND: &str = "agent_provider_keys";
const FORMAT: u8 = 1;
const MAX_PLAINTEXT: usize = 32 * 1024;
const MAX_NAME: usize = 128;

#[derive(Serialize, Deserialize)]
struct Stored {
    format: u8,
    provider: String,
    model: String,
    key: String,
}
impl Drop for Stored {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

/// The object id of an agent's key.
pub fn provider_key_object(agent_id: &str) -> String {
    format!("key-{agent_id}")
}

/// One agent's provider key.
pub struct ProviderKeyRecord {
    provider: String,
    model: String,
    key: Zeroizing<Vec<u8>>,
}
impl ProviderKeyRecord {
    pub fn new(provider: &str, model: &str, key: &[u8]) -> Result<Self, CloudDeviceError> {
        let name = |text: &str| !text.is_empty() && text.len() <= MAX_NAME;
        if !name(provider)
            || !name(model)
            || key.is_empty()
            || key.len() > nocterm_keys::cloud::MAX_PROVIDER_SECRET_BYTES
            || std::str::from_utf8(key).is_err()
        {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(Self {
            provider: provider.to_owned(),
            model: model.to_owned(),
            key: Zeroizing::new(key.to_vec()),
        })
    }
    /// The provider family the runner's configuration names.
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn model(&self) -> &str {
        &self.model
    }
    /// The key; hand it to the lease sealer and nothing else.
    pub fn expose(&self) -> &[u8] {
        &self.key
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CloudDeviceError> {
        let stored = Stored {
            format: FORMAT,
            provider: self.provider.clone(),
            model: self.model.clone(),
            key: STANDARD.encode(self.key.as_slice()),
        };
        serde_json::to_vec(&stored)
            .map(Zeroizing::new)
            .map_err(|_| CloudDeviceError::Format)
    }
    pub fn decode(plaintext: &[u8]) -> Result<Self, CloudDeviceError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        let stored: Stored =
            serde_json::from_slice(plaintext).map_err(|_| CloudDeviceError::Format)?;
        if stored.format != FORMAT {
            return Err(CloudDeviceError::Format);
        }
        let key = Zeroizing::new(
            STANDARD
                .decode(stored.key.as_bytes())
                .map_err(|_| CloudDeviceError::Format)?,
        );
        Self::new(&stored.provider, &stored.model, &key)
    }
    /// Opens `key-<agent>` from the account's `agent_provider_keys` collection.
    pub fn open(
        key: &CollectionKey,
        agent_id: &str,
        object: &StoredObject<'_>,
    ) -> Result<Self, CloudDeviceError> {
        let id = provider_key_object(agent_id);
        if object.object_id != id || object.kind != PROVIDER_KEYS_KIND {
            return Err(CloudDeviceError::Binding);
        }
        if object.deleted {
            return Err(CloudDeviceError::NoProviderKey);
        }
        if object.ciphertext.len() > MAX_PLAINTEXT + SEAL_OVERHEAD {
            return Err(CloudDeviceError::Capacity);
        }
        let plaintext = key.open_object(
            object.collection_id,
            &id,
            PROVIDER_KEYS_KIND,
            object.ciphertext,
        )?;
        Self::decode(&plaintext)
    }
}
impl fmt::Debug for ProviderKeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderKeyRecord")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}
