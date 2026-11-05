//! Model-only edits of an own agent's canonical encrypted provider record. The collection
//! key, provider and credential stay inside WASM; JavaScript receives models or ciphertext.
use crate::WebCollectionKey;
use nocterm_cloud_device::{
    CloudDeviceError,
    records::{PROVIDER_KEYS_KIND, ProviderKeyRecord, StoredObject, provider_key_object},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
impl WebCollectionKey {
    #[wasm_bindgen(js_name = providerKeyModels)]
    pub fn provider_key_models(
        &self,
        agent_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<String>, JsError> {
        self.provider_record(agent_id, ciphertext)
            .map(|record| record.models().to_vec())
            .map_err(|error| JsError::new(&error.to_string()))
    }
    #[wasm_bindgen(js_name = updateProviderKeyModels)]
    pub fn update_provider_key_models(
        &self,
        agent_id: &str,
        ciphertext: &[u8],
        models: Vec<String>,
    ) -> Result<Vec<u8>, JsError> {
        self.updated_provider_models(agent_id, ciphertext, models)
            .map_err(|error| JsError::new(&error.to_string()))
    }
}
impl WebCollectionKey {
    fn provider_record(
        &self,
        agent_id: &str,
        ciphertext: &[u8],
    ) -> Result<ProviderKeyRecord, CloudDeviceError> {
        if !self.is_own() {
            return Err(CloudDeviceError::Binding);
        }
        if agent_id.is_empty() || agent_id.len() > 128 {
            return Err(CloudDeviceError::Capacity);
        }
        ProviderKeyRecord::open(
            &self.key,
            agent_id,
            &StoredObject {
                collection_id: &self.collection_id,
                object_id: &provider_key_object(agent_id),
                kind: PROVIDER_KEYS_KIND,
                version: 1,
                deleted: false,
                ciphertext,
            },
        )
    }
    fn updated_provider_models(
        &self,
        agent_id: &str,
        ciphertext: &[u8],
        models: Vec<String>,
    ) -> Result<Vec<u8>, CloudDeviceError> {
        let changed = self
            .provider_record(agent_id, ciphertext)?
            .with_models(models)?;
        Ok(self.key.seal_object(
            &self.collection_id,
            &provider_key_object(agent_id),
            PROVIDER_KEYS_KIND,
            &changed.encode()?,
        )?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
    use super::*;
    use nocterm_keys::CollectionKey;
    #[test]
    fn updating_models_inside_wasm_preserves_the_provider_and_secret_and_binds_the_agent() {
        let key = CollectionKey::generate().unwrap();
        let record = ProviderKeyRecord::new("own-provider", "first", b"private-key").unwrap();
        let ciphertext = key
            .seal_object(
                "col",
                &provider_key_object("agent-1"),
                PROVIDER_KEYS_KIND,
                &record.encode().unwrap(),
            )
            .unwrap();
        let collection = WebCollectionKey::owned("col".into(), key);
        let updated = collection
            .updated_provider_models(
                "agent-1",
                &ciphertext,
                vec!["first".into(), "second".into()],
            )
            .unwrap();
        let read = collection.provider_record("agent-1", &updated).unwrap();
        assert_eq!(read.provider(), "own-provider");
        assert_eq!(read.expose(), b"private-key");
        assert_eq!(read.models(), ["first", "second"]);
        assert!(collection.provider_record("agent-2", &updated).is_err());
        assert!(
            collection
                .updated_provider_models("agent-1", &ciphertext, Vec::new())
                .is_err()
        );
    }
    #[test]
    fn own_key_helpers_reject_granted_collection_handles_even_for_valid_ciphertext() {
        use nocterm_keys::{AccountKey, AccountKeyPair};
        let recipient = crate::WebAccount {
            account_id: "owner".into(),
            account: AccountKey::generate().unwrap(),
            pair: AccountKeyPair::generate().unwrap(),
        };
        let sender = AccountKeyPair::generate().unwrap();
        let key = CollectionKey::generate().unwrap();
        let record = ProviderKeyRecord::new("own-provider", "first", b"private-key").unwrap();
        let ciphertext = key
            .seal_object(
                "col",
                &provider_key_object("agent-1"),
                PROVIDER_KEYS_KIND,
                &record.encode().unwrap(),
            )
            .unwrap();
        let grant = key
            .seal_to(&sender, &recipient.pair.public_key(), "col", "owner")
            .unwrap();
        let public = sender.public_key().to_bytes();
        let granted = recipient
            .open_granted_collection("col", &grant, "admin", &public, &public)
            .unwrap();
        assert!(matches!(
            granted.provider_record("agent-1", &ciphertext),
            Err(CloudDeviceError::Binding)
        ));
        assert!(matches!(
            granted.updated_provider_models("agent-1", &ciphertext, vec!["next".into()]),
            Err(CloudDeviceError::Binding)
        ));
        let wrapped = key.seal_for(&recipient.account, "col").unwrap();
        let own = recipient.open_collection("col", &wrapped).unwrap();
        assert_eq!(
            own.provider_record("agent-1", &ciphertext)
                .unwrap()
                .models(),
            ["first"]
        );
    }
}
