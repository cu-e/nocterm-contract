//! The account's collections as the web panel uses them: collection keys opened or created
//! inside WebAssembly, the profile objects sealed with them, and new objects the browser seals.
//! The collection key never crosses into JavaScript; only objects of a readable kind are
//! opened, and only objects of a sealable kind are sealed.

use nocterm_keys::CollectionKey;
use wasm_bindgen::prelude::*;

use crate::{WebAccount, WebError};

/// Kinds of object the browser opens: saved server profiles, which hold no secrets.
/// Credentials and every other kind stay sealed.
const READABLE_KINDS: &[&str] = &["profile"];

/// Kinds of object the browser seals: a saved server's profile, and the credential the person
/// typed in this browser for it. A credential is sealed here and never opened here.
const SEALABLE_KINDS: &[&str] = &["profile", "credential"];

/// A collection the browser creates: the values `CreateCollection` stores. Open its key with
/// `WebAccount.openCollection` to seal objects into it.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebNewCollection {
    wrapped_key: Vec<u8>,
    sealed_name: Vec<u8>,
}

#[wasm_bindgen]
impl WebNewCollection {
    /// `wrapped_key`: the new collection key sealed by the account key.
    #[wasm_bindgen(js_name = wrappedKey)]
    pub fn wrapped_key(&self) -> Vec<u8> {
        self.wrapped_key.clone()
    }

    /// `sealed_name`: the collection's name sealed by its key.
    #[wasm_bindgen(js_name = sealedName)]
    pub fn sealed_name(&self) -> Vec<u8> {
        self.sealed_name.clone()
    }
}

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

    /// A fresh collection key for the collection `collection_id` the browser chose, sealed by
    /// the account key, and the collection's `name` (its kind, as native clients name it)
    /// sealed by the new key.
    #[wasm_bindgen(js_name = newCollection)]
    pub fn new_collection(
        &self,
        collection_id: &str,
        name: &str,
    ) -> Result<WebNewCollection, JsError> {
        self.collection(collection_id, name).map_err(JsError::from)
    }
}

impl WebAccount {
    fn collection(&self, collection_id: &str, name: &str) -> Result<WebNewCollection, WebError> {
        let key = CollectionKey::generate()?;
        Ok(WebNewCollection {
            wrapped_key: key.seal_for(&self.account, collection_id)?,
            sealed_name: key.seal_name(collection_id, name)?,
        })
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

    /// Seals a new version of one object of the collection, bound to its identifier and kind,
    /// for `PutObject`. Only profiles and credentials (`kind = "credential"`) are sealed.
    #[wasm_bindgen(js_name = sealObject)]
    pub fn seal_object(
        &self,
        object_id: &str,
        kind: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.sealed(object_id, kind, plaintext)
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

    fn sealed(&self, object_id: &str, kind: &str, plaintext: &[u8]) -> Result<Vec<u8>, WebError> {
        if !SEALABLE_KINDS.contains(&kind) {
            return Err(WebError::UnsealableKind(kind.to_owned()));
        }
        Ok(self
            .key
            .seal_object(&self.collection_id, object_id, kind, plaintext)?)
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

    #[test]
    fn a_collection_and_objects_the_browser_creates_open_natively() {
        let account = AccountKey::generate().unwrap();
        let web = WebAccount {
            account: account.clone(),
        };
        let created = web.collection("col", "vault").unwrap();
        let native = CollectionKey::open(&account, "col", &created.wrapped_key).unwrap();
        assert_eq!(
            native.open_name("col", &created.sealed_name).unwrap(),
            "vault"
        );

        let collection = WebCollectionKey {
            collection_id: "col".into(),
            key: CollectionKey::open(&web.account, "col", &created.wrapped_key).unwrap(),
        };
        let sealed = collection.sealed("sec", "credential", b"pw").unwrap();
        let opened = native
            .open_object("col", "sec", "credential", &sealed)
            .unwrap();
        assert_eq!(opened.as_slice(), b"pw");
        // The browser still never opens the credential it sealed.
        assert!(matches!(
            collection.object("sec", "credential", &sealed),
            Err(WebError::SealedKind(_))
        ));
        assert!(matches!(
            collection.sealed("x", "device", b"{}"),
            Err(WebError::UnsealableKind(_))
        ));
    }
}
