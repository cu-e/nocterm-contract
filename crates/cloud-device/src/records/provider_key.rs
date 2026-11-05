//! `agent_provider_keys` / `key-<agent>`: the provider key of an agent that runs on the person's
//! own runner (ADR 0126 of the native client). It never goes to a pool; a device of the account
//! opens it only to seal a short lease to the runner's verified boot.
//!
//! Layout (format 1 for a single model): UTF-8 JSON
//! `{"format":1,"provider":<text>,"model":<text>,"key":<standard base64 of the key's UTF-8>}`.
//! Format 2 carries `models` (one to 32 ids, first is the default) instead of `model`.
//! Readers accept both; writers retain format 1 for single-model records. Older clients
//! reject format 2, so they cannot silently lease only the first of a multi-model record.
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
const SINGLE_FORMAT: u8 = 1;
const MULTI_FORMAT: u8 = 2;
const MAX_PLAINTEXT: usize = 32 * 1024;
const MAX_NAME: usize = 128;

#[derive(Serialize, Deserialize)]
struct Stored {
    format: u8,
    provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    models: Vec<String>,
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
    models: Vec<String>,
    key: Zeroizing<String>,
}
impl ProviderKeyRecord {
    pub fn new(provider: &str, model: &str, key: &[u8]) -> Result<Self, CloudDeviceError> {
        Self::new_models(provider, vec![model.to_owned()], key)
    }
    /// A key whose lease permits the complete model list; the first is the default.
    pub fn new_models(
        provider: &str,
        models: Vec<String>,
        key: &[u8],
    ) -> Result<Self, CloudDeviceError> {
        if provider.is_empty()
            || provider.len() > MAX_NAME
            || key.is_empty()
            || key.len() > nocterm_keys::cloud::MAX_PROVIDER_SECRET_BYTES
        {
            return Err(CloudDeviceError::Capacity);
        }
        let models = bounded_models(models)?;
        let key = std::str::from_utf8(key).map_err(|_| CloudDeviceError::Capacity)?;
        Ok(Self {
            provider: provider.to_owned(),
            models,
            key: Zeroizing::new(key.to_owned()),
        })
    }
    /// Changes only the allowed models, retaining the provider and secret.
    pub fn with_models(mut self, models: Vec<String>) -> Result<Self, CloudDeviceError> {
        self.models = bounded_models(models)?;
        Ok(self)
    }
    /// The provider family the runner's configuration names.
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn model(&self) -> &str {
        &self.models[0]
    }
    pub fn models(&self) -> &[String] {
        &self.models
    }
    /// The key; hand it to the lease sealer and nothing else.
    pub fn expose(&self) -> &[u8] {
        self.key.as_bytes()
    }
    /// The same UTF-8 secret for native callers; constructors validate this invariant.
    pub fn expose_text(&self) -> &str {
        &self.key
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CloudDeviceError> {
        let stored = Stored {
            format: if self.models.len() == 1 {
                SINGLE_FORMAT
            } else {
                MULTI_FORMAT
            },
            provider: self.provider.clone(),
            model: (self.models.len() == 1).then(|| self.model().to_owned()),
            models: if self.models.len() == 1 {
                Vec::new()
            } else {
                self.models.clone()
            },
            key: STANDARD.encode(self.key.as_bytes()),
        };
        let encoded = serde_json::to_vec(&stored)
            .map(Zeroizing::new)
            .map_err(|_| CloudDeviceError::Format)?;
        if encoded.len() > MAX_PLAINTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(encoded)
    }
    pub fn decode(plaintext: &[u8]) -> Result<Self, CloudDeviceError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        let stored: Stored =
            serde_json::from_slice(plaintext).map_err(|_| CloudDeviceError::Format)?;
        let models = match stored.format {
            SINGLE_FORMAT if stored.models.is_empty() => {
                vec![stored.model.clone().ok_or(CloudDeviceError::Format)?]
            }
            MULTI_FORMAT if stored.model.is_none() => stored.models.clone(),
            _ => return Err(CloudDeviceError::Format),
        };
        let key = Zeroizing::new(
            STANDARD
                .decode(stored.key.as_bytes())
                .map_err(|_| CloudDeviceError::Format)?,
        );
        Self::new_models(&stored.provider, models, &key)
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
            .field("models", &self.models)
            .finish_non_exhaustive()
    }
}

fn check_models(models: &[String]) -> Result<(), CloudDeviceError> {
    if models.is_empty()
        || models.len() > nocterm_hub_model::agents::limits::MAX_MODELS
        || models
            .iter()
            .any(|model| model.is_empty() || model.len() > MAX_NAME)
    {
        return Err(CloudDeviceError::Capacity);
    }
    let unique: std::collections::BTreeSet<_> = models.iter().collect();
    if unique.len() != models.len() {
        return Err(CloudDeviceError::Format);
    }
    Ok(())
}

fn bounded_models(models: Vec<String>) -> Result<Vec<String>, CloudDeviceError> {
    check_models(&models)?;
    let mut models = models.into_boxed_slice().into_vec();
    for model in &mut models {
        if model.capacity() > MAX_NAME {
            *model = std::mem::take(model).into_boxed_str().into_string();
        }
    }
    Ok(models)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
    use super::*;
    #[test]
    fn single_model_records_keep_the_original_format_and_bytes() {
        let record = ProviderKeyRecord::new("openai_chat", "first", b"secret").unwrap();
        assert_eq!(
            record.encode().unwrap().as_slice(),
            br#"{"format":1,"provider":"openai_chat","model":"first","key":"c2VjcmV0"}"#
        );
        let decoded = ProviderKeyRecord::decode(&record.encode().unwrap()).unwrap();
        assert_eq!(decoded.models(), ["first"]);
    }
    #[test]
    fn a_multi_model_record_round_trips_every_model_and_preserves_the_secret_on_edit() {
        let record = ProviderKeyRecord::new_models(
            "openai_chat",
            vec!["first".into(), "second".into()],
            b"secret",
        )
        .unwrap();
        let encoded = record.encode().unwrap();
        assert!(encoded.starts_with(br#"{"format":2,"#));
        let changed = ProviderKeyRecord::decode(&encoded)
            .unwrap()
            .with_models(vec!["second".into(), "third".into()])
            .unwrap();
        assert_eq!(changed.model(), "second");
        assert_eq!(changed.models(), ["second", "third"]);
        assert_eq!(changed.expose(), b"secret");
        assert!(!format!("{changed:?}").contains("secret"));
        assert!(changed.with_models(Vec::new()).is_err());
    }
    #[test]
    fn json_escaping_cannot_publish_a_record_above_its_plaintext_bound() {
        let models = (0..32)
            .map(|index| format!("{}{:02}", "\0".repeat(126), index))
            .collect();
        let key = vec![b'k'; nocterm_keys::cloud::MAX_PROVIDER_SECRET_BYTES];
        let record = ProviderKeyRecord::new_models("own-provider", models, &key).unwrap();
        assert!(matches!(record.encode(), Err(CloudDeviceError::Capacity)));
    }
}
