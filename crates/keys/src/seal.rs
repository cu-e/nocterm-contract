use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{KeyError, UnlockKey, random_bytes};

pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 2 + NONCE_LEN;

/// What a sealed value is, bound into its associated data and header.
///
/// Numbers and labels are part of the stored format: never reuse or change them.
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Purpose {
    AccountKey = 1,
    CollectionKey = 2,
    CollectionName = 3,
    Object = 4,
    AccountPrivateKey = 5,
    RecoveredAccountKey = 6,
    CollectionGrant = 7,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::AccountKey => b"account-key",
            Purpose::CollectionKey => b"collection-key",
            Purpose::CollectionName => b"collection-name",
            Purpose::Object => b"object",
            Purpose::AccountPrivateKey => b"account-private-key",
            Purpose::RecoveredAccountKey => b"recovery-account-key",
            Purpose::CollectionGrant => b"collection-grant",
        }
    }
}

/// A value could not be sealed.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// No randomness for the nonce or key.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// The cipher rejected the input (too large).
    #[error("encryption failed")]
    Encrypt,
    /// The recipient's public key is not a usable X25519 key (a small-order point).
    #[error("the recipient's public key is not usable")]
    UnusableRecipientKey,
}

/// A sealed value could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// Not a sealed value of the expected format or purpose.
    #[error("malformed sealed value")]
    Malformed,
    /// Wrong key, or the value was modified or moved to another owner.
    #[error("sealed value does not open with this key")]
    Rejected,
}

/// `nocterm/v1/<purpose>` followed by each context part with a 4-byte length prefix.
pub(crate) fn aad(purpose: Purpose, context: &[&str]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(b"nocterm/v1/");
    aad.extend_from_slice(purpose.label());
    for part in context {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad
}

/// Encrypts `plaintext` and authenticates `purpose` and `context` along with it.
pub(crate) fn encrypt(
    key: &[u8; 32],
    purpose: Purpose,
    context: &[&str],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let aad = aad(purpose, context);
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SealError::Encrypt)
}

/// Decrypts what [`encrypt`] made; any change to key, nonce, purpose or context is rejected.
pub(crate) fn decrypt(
    key: &[u8; 32],
    purpose: Purpose,
    context: &[&str],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let aad = aad(purpose, context);
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| OpenError::Rejected)
}

/// `version ‖ purpose ‖ nonce ‖ ciphertext` with a fresh random nonce.
pub(crate) fn seal(
    key: &[u8; 32],
    purpose: Purpose,
    context: &[&str],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = encrypt(key, purpose, context, &nonce, plaintext)?;
    let mut sealed = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    sealed.push(FORMAT_VERSION);
    sealed.push(purpose as u8);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

pub(crate) fn open(
    key: &[u8; 32],
    purpose: Purpose,
    context: &[&str],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    if sealed.len() < HEADER_LEN || sealed[0] != FORMAT_VERSION || sealed[1] != purpose as u8 {
        return Err(OpenError::Malformed);
    }
    let nonce: [u8; NONCE_LEN] = sealed[2..HEADER_LEN]
        .try_into()
        .map_err(|_| OpenError::Malformed)?;
    decrypt(key, purpose, context, &nonce, &sealed[HEADER_LEN..])
}

fn key_from(bytes: &[u8]) -> Result<[u8; 32], OpenError> {
    bytes.try_into().map_err(|_| OpenError::Malformed)
}

/// Root key of an account's encrypted data, sealed by the unlock key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccountKey(pub(crate) [u8; 32]);

impl AccountKey {
    /// A fresh random account key.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self(random_bytes::<32>()?))
    }

    /// Seals the account key for storage on the hub.
    pub fn seal(&self, unlock: &UnlockKey, account_id: &str) -> Result<Vec<u8>, SealError> {
        seal(&unlock.0, Purpose::AccountKey, &[account_id], &self.0)
    }

    /// Opens an account key sealed by [`AccountKey::seal`].
    pub fn open(unlock: &UnlockKey, account_id: &str, sealed: &[u8]) -> Result<Self, OpenError> {
        let bytes = open(&unlock.0, Purpose::AccountKey, &[account_id], sealed)?;
        Ok(Self(key_from(&bytes)?))
    }
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountKey(…)")
    }
}

/// Key of one collection: it seals the collection's name and objects.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CollectionKey(pub(crate) [u8; 32]);

impl CollectionKey {
    /// A fresh random collection key.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self(random_bytes::<32>()?))
    }

    /// Seals this key for one account (wrapped by its account key).
    pub fn seal_for(
        &self,
        account: &AccountKey,
        collection_id: &str,
    ) -> Result<Vec<u8>, SealError> {
        seal(
            &account.0,
            Purpose::CollectionKey,
            &[collection_id],
            &self.0,
        )
    }

    /// Opens a collection key sealed by [`CollectionKey::seal_for`].
    pub fn open(
        account: &AccountKey,
        collection_id: &str,
        sealed: &[u8],
    ) -> Result<Self, OpenError> {
        let bytes = open(&account.0, Purpose::CollectionKey, &[collection_id], sealed)?;
        Ok(Self(key_from(&bytes)?))
    }

    /// Seals the collection's display name.
    pub fn seal_name(&self, collection_id: &str, name: &str) -> Result<Vec<u8>, SealError> {
        seal(
            &self.0,
            Purpose::CollectionName,
            &[collection_id],
            name.as_bytes(),
        )
    }

    /// Opens the collection's display name.
    pub fn open_name(&self, collection_id: &str, sealed: &[u8]) -> Result<String, OpenError> {
        let bytes = open(&self.0, Purpose::CollectionName, &[collection_id], sealed)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| OpenError::Malformed)
    }

    /// Seals one object; its identity and kind are bound so it cannot be moved.
    pub fn seal_object(
        &self,
        collection_id: &str,
        object_id: &str,
        kind: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        seal(
            &self.0,
            Purpose::Object,
            &[collection_id, object_id, kind],
            plaintext,
        )
    }

    /// Opens an object sealed by [`CollectionKey::seal_object`].
    pub fn open_object(
        &self,
        collection_id: &str,
        object_id: &str,
        kind: &str,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        open(
            &self.0,
            Purpose::Object,
            &[collection_id, object_id, kind],
            sealed,
        )
    }
}

impl fmt::Debug for CollectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CollectionKey(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlock() -> UnlockKey {
        UnlockKey([3; 32])
    }

    #[test]
    fn the_key_hierarchy_round_trips() {
        let unlock = unlock();
        let account = AccountKey::generate().unwrap();
        let sealed_account = account.seal(&unlock, "acc").unwrap();
        let account = AccountKey::open(&unlock, "acc", &sealed_account).unwrap();

        let collection = CollectionKey::generate().unwrap();
        let sealed_collection = collection.seal_for(&account, "col").unwrap();
        let collection = CollectionKey::open(&account, "col", &sealed_collection).unwrap();

        let name = collection.seal_name("col", "Personal").unwrap();
        assert_eq!(collection.open_name("col", &name).unwrap(), "Personal");
        let object = collection
            .seal_object("col", "obj", "login", b"hunter2")
            .unwrap();
        assert_eq!(
            collection
                .open_object("col", "obj", "login", &object)
                .unwrap()
                .as_slice(),
            b"hunter2"
        );
    }

    #[test]
    fn moved_or_retyped_objects_do_not_open() {
        let collection = CollectionKey::generate().unwrap();
        let object = collection
            .seal_object("col", "obj", "login", b"secret")
            .unwrap();
        assert_eq!(
            collection.open_object("col", "other", "login", &object),
            Err(OpenError::Rejected)
        );
        assert_eq!(
            collection.open_object("other", "obj", "login", &object),
            Err(OpenError::Rejected)
        );
        assert_eq!(
            collection.open_object("col", "obj", "note", &object),
            Err(OpenError::Rejected)
        );
    }

    #[test]
    fn a_sealed_key_is_bound_to_its_purpose() {
        let collection = CollectionKey::generate().unwrap();
        let name = collection.seal_name("col", "x").unwrap();
        assert_eq!(
            collection.open_object("col", "obj", "login", &name),
            Err(OpenError::Malformed)
        );
    }

    #[test]
    fn tampering_is_detected() {
        let collection = CollectionKey::generate().unwrap();
        let mut object = collection.seal_object("c", "o", "k", b"data").unwrap();
        let last = object.len() - 1;
        object[last] ^= 1;
        assert_eq!(
            collection.open_object("c", "o", "k", &object),
            Err(OpenError::Rejected)
        );
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let collection = CollectionKey::generate().unwrap();
        let object = collection
            .seal_object("c", "o", "k", b"plaintext-marker-123")
            .unwrap();
        let needle = b"plaintext-marker-123";
        assert!(!object.windows(needle.len()).any(|w| w == needle));
    }
}
