//! The account's collections as the web panel reads them: collection keys opened inside
//! WebAssembly and the profile objects sealed with them. The collection key never crosses into
//! JavaScript, and only objects of a readable kind are opened.

use nocterm_keys::CollectionKey;
use wasm_bindgen::prelude::*;

use crate::{WebAccount, WebError};

/// Kinds of object the browser opens: saved server profiles, which hold no secrets.
/// Credentials and every other kind stay sealed.
const READABLE_KINDS: &[&str] = &["profile"];

/// The key of one collection, bound to its identifier. It stays inside WebAssembly.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebCollectionKey {
    collection_id: String,
    key: CollectionKey,
}

#[wasm_bindgen]
impl WebAccount {
    /// Opens the key envelope of one of the account's collections (`GetCollectionKey`), sealed
    /// by its account key.
    #[wasm_bindgen(js_name = openCollection)]
    pub fn open_collection(
        &self,
        collection_id: &str,
        wrapped_key: &[u8],
    ) -> Result<WebCollectionKey, JsError> {
        CollectionKey::open(&self.account, collection_id, wrapped_key)
            .map(|key| WebCollectionKey {
                collection_id: collection_id.to_owned(),
                key,
            })
            .map_err(|error| JsError::from(WebError::from(error)))
    }
}

#[wasm_bindgen]
impl WebCollectionKey {
    /// Opens one object of the collection (`StoredObject.ciphertext`), bound to its identifier
    /// and kind. Only profiles (`kind = "profile"`) open; an object that does not authenticate
    /// was altered or moved and is refused.
    #[wasm_bindgen(js_name = openObject)]
    pub fn open_object(
        &self,
        object_id: &str,
        kind: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.object(object_id, kind, ciphertext)
            .map_err(JsError::from)
    }
}

impl WebCollectionKey {
    fn object(&self, object_id: &str, kind: &str, ciphertext: &[u8]) -> Result<Vec<u8>, WebError> {
        if !READABLE_KINDS.contains(&kind) {
            return Err(WebError::SealedKind(kind.to_owned()));
        }
        let plain = self
            .key
            .open_object(&self.collection_id, object_id, kind, ciphertext)?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use nocterm_keys::{AccountKey, CollectionKey};

    use super::*;

    #[test]
    fn profiles_open_and_credentials_stay_sealed() {
        let account = AccountKey::generate().unwrap();
        let key = CollectionKey::generate().unwrap();
        let wrapped = key.seal_for(&account, "col").unwrap();
        let profile = key.seal_object("col", "obj", "profile", b"{}").unwrap();
        let secret = key.seal_object("col", "sec", "credential", b"pw").unwrap();
        let web = WebAccount { account };
        let opened = CollectionKey::open(&web.account, "col", &wrapped).unwrap();
        let collection = WebCollectionKey {
            collection_id: "col".into(),
            key: opened,
        };
        assert_eq!(
            collection.object("obj", "profile", &profile).unwrap(),
            b"{}"
        );
        assert!(matches!(
            collection.object("sec", "credential", &secret),
            Err(WebError::SealedKind(_))
        ));
    }
}
