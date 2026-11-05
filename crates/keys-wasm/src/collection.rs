//! The account's collections as the web panel reads them: collection keys opened inside
//! WebAssembly and the profile objects sealed with them.
//!
//! A personal collection's key envelope is sealed by the account key. An organization's is a
//! grant, which opens only under the public key of the account that made it; the caller passes
//! the key it pinned for that account (trust on first use, as `PinnedKeys` decides) and the
//! key the hub offers now, and a grant opens only when both are the same key. The collection
//! key itself never crosses into JavaScript, and only objects of a readable kind are opened.

use nocterm_keys::{CollectionKey, PinnedKeys, PublicKey};
use wasm_bindgen::prelude::*;

use crate::{WebAccount, WebError};

/// Kinds of object the browser opens: saved server profiles, which hold no secrets.
/// Credentials and every other kind stay sealed.
const READABLE_KINDS: &[&str] = &["profile"];

/// The key of one collection, bound to its identifier. It stays inside WebAssembly.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebCollectionKey {
    pub(crate) collection_id: String,
    pub(crate) key: CollectionKey,
    own: bool,
}

#[wasm_bindgen]
impl WebAccount {
    /// Opens the key envelope of one of the account's own collections (`GetCollectionKey`
    /// with an empty `granted_by`), sealed by its account key.
    #[wasm_bindgen(js_name = openCollection)]
    pub fn open_collection(
        &self,
        collection_id: &str,
        wrapped_key: &[u8],
    ) -> Result<WebCollectionKey, JsError> {
        self.own_collection(collection_id, wrapped_key)
            .map_err(JsError::from)
    }

    /// Opens a collection key another account granted to this one (`granted_by` names it).
    /// `pinned_granter_key` is the key this browser pinned for `granter_account_id` after a
    /// person compared its fingerprint; `offered_granter_key` is the one the hub lists now. A
    /// changed key, or a grant made with any other key, is refused.
    #[wasm_bindgen(js_name = openGrantedCollection)]
    pub fn open_granted_collection(
        &self,
        collection_id: &str,
        wrapped_key: &[u8],
        granter_account_id: &str,
        pinned_granter_key: &[u8],
        offered_granter_key: &[u8],
    ) -> Result<WebCollectionKey, JsError> {
        self.granted_collection(
            collection_id,
            wrapped_key,
            granter_account_id,
            pinned_granter_key,
            offered_granter_key,
        )
        .map_err(JsError::from)
    }
}

impl WebAccount {
    pub(crate) fn own_collection(
        &self,
        collection_id: &str,
        wrapped_key: &[u8],
    ) -> Result<WebCollectionKey, WebError> {
        let key = CollectionKey::open(&self.account, collection_id, wrapped_key)?;
        Ok(WebCollectionKey::owned(collection_id.to_owned(), key))
    }

    fn granted_collection(
        &self,
        collection_id: &str,
        wrapped_key: &[u8],
        granter_account_id: &str,
        pinned_granter_key: &[u8],
        offered_granter_key: &[u8],
    ) -> Result<WebCollectionKey, WebError> {
        let pins = PinnedKeys::from_entries([(
            granter_account_id,
            PublicKey::from_bytes(pinned_granter_key)?,
        )]);
        let trusted = pins.trust(
            granter_account_id,
            &PublicKey::from_bytes(offered_granter_key)?,
        )?;
        let key = CollectionKey::open_from(
            &self.pair,
            trusted.public_key(),
            collection_id,
            &self.account_id,
            wrapped_key,
        )?;
        Ok(WebCollectionKey {
            collection_id: collection_id.to_owned(),
            key,
            own: false,
        })
    }
}

#[wasm_bindgen]
impl WebCollectionKey {
    /// Opens one object of the collection (`StoredObject.ciphertext`), bound to its identifier
    /// and kind. Only profiles (`kind = "profile"`, plaintext `{"v":1,"profile":…}`) open; an
    /// object that does not authenticate was altered or moved and is refused.
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
    pub(crate) fn owned(collection_id: String, key: CollectionKey) -> Self {
        Self {
            collection_id,
            key,
            own: true,
        }
    }
    pub(crate) fn is_own(&self) -> bool {
        self.own
    }
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

/// The fingerprint people compare before they pin another account's key (an organization
/// administrator who grants collection keys): SHA-256 in 16 dash-separated groups.
#[wasm_bindgen(js_name = accountKeyFingerprint)]
pub fn account_key_fingerprint(public_key: &[u8]) -> Result<String, JsError> {
    fingerprint(public_key).map_err(JsError::from)
}

fn fingerprint(public_key: &[u8]) -> Result<String, WebError> {
    Ok(PublicKey::from_bytes(public_key)?.fingerprint())
}

#[cfg(test)]
mod tests {
    use nocterm_keys::{AccountKey, AccountKeyPair, OpenError, PinError};

    use super::*;

    const PROFILE: &[u8] = br#"{"v":1,"profile":{"id":"p","name":"db","host":"h","user":"u"}}"#;

    fn account(account_id: &str) -> WebAccount {
        WebAccount {
            account_id: account_id.to_owned(),
            account: AccountKey::generate().unwrap(),
            pair: AccountKeyPair::generate().unwrap(),
        }
    }

    #[test]
    fn an_own_collection_opens_its_profiles_and_nothing_else() {
        let web = account("acc-1");
        let key = CollectionKey::generate().unwrap();
        let wrapped = key.seal_for(&web.account, "col-1").unwrap();
        let sealed = key
            .seal_object("col-1", "obj-1", "profile", PROFILE)
            .unwrap();
        let credential = key
            .seal_object("col-1", "obj-2", "credential", b"secret")
            .unwrap();

        let opened = web.own_collection("col-1", &wrapped).unwrap();
        assert_eq!(opened.object("obj-1", "profile", &sealed).unwrap(), PROFILE);
        assert!(matches!(
            opened.object("obj-2", "credential", &credential),
            Err(WebError::SealedKind(kind)) if kind == "credential"
        ));
        assert!(matches!(
            opened.object("obj-9", "profile", &sealed),
            Err(WebError::Open(OpenError::Rejected))
        ));
        assert!(matches!(
            web.own_collection("col-2", &wrapped),
            Err(WebError::Open(OpenError::Rejected))
        ));
        assert!(account("acc-1").own_collection("col-1", &wrapped).is_err());
    }

    #[test]
    fn a_grant_opens_only_under_the_pinned_granter_key() {
        let (web, admin) = (account("acc-2"), AccountKeyPair::generate().unwrap());
        let key = CollectionKey::generate().unwrap();
        let grant = key
            .seal_to(&admin, &web.pair.public_key(), "col-org", "acc-2")
            .unwrap();
        let admin_key = admin.public_key().to_bytes();

        let opened = web
            .granted_collection("col-org", &grant, "admin", &admin_key, &admin_key)
            .unwrap();
        let sealed = key
            .seal_object("col-org", "obj-1", "profile", PROFILE)
            .unwrap();
        assert_eq!(opened.object("obj-1", "profile", &sealed).unwrap(), PROFILE);

        let other = AccountKeyPair::generate().unwrap().public_key().to_bytes();
        assert!(matches!(
            web.granted_collection("col-org", &grant, "admin", &admin_key, &other),
            Err(WebError::Pin(PinError::Changed { .. }))
        ));
        assert!(matches!(
            web.granted_collection("col-org", &grant, "admin", &other, &other),
            Err(WebError::Open(OpenError::Rejected))
        ));
        assert!(matches!(
            web.granted_collection("col-org", &grant, "admin", &admin_key[..31], &admin_key),
            Err(WebError::PublicKey(_))
        ));
    }

    #[test]
    fn a_new_keyset_opens_the_collections_its_account_key_seals() {
        let created = crate::new_vault_keyset("vault password!", "acc-3").unwrap();
        let unlocked = WebAccount::open_vault(
            "vault password!",
            &created.kdf(),
            &created.salt(),
            "acc-3",
            &created.wrapped_account_key(),
            &created.sealed_private_key(),
            &created.public_key(),
        )
        .unwrap();
        let key = CollectionKey::generate().unwrap();
        let wrapped = key.seal_for(&unlocked.account, "col-3").unwrap();
        assert!(
            created
                .into_account()
                .own_collection("col-3", &wrapped)
                .is_ok()
        );
    }

    #[test]
    fn the_fingerprint_is_the_account_keys() {
        let pair = AccountKeyPair::generate().unwrap();
        assert_eq!(
            fingerprint(&pair.public_key().to_bytes()).unwrap(),
            pair.public_key().fingerprint()
        );
        assert!(matches!(fingerprint(&[0; 31]), Err(WebError::PublicKey(_))));
    }
}
