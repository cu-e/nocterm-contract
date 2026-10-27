//! Keys sealed to a public key: the X25519 pair of an account and collection key grants.
//!
//! A grant hands a collection key to another account without the hub being able to read it
//! or move it. The sender needs only the recipient's public key:
//!
//! ```text
//! shared = X25519(ephemeral secret, recipient public key)       // rejected if non-contributory
//! key    = HKDF-SHA256(salt = ephemeral public ‖ recipient public, ikm = shared,
//!                      info = "nocterm-grant-v1/key")
//! sealed = 0x01 ‖ 0x07 ‖ ephemeral public ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce,
//!          aad = "nocterm/v1/collection-grant" ‖ lp(collection id) ‖ lp(recipient account id))
//! ```
//!
//! The associated data binds the collection and the recipient account, so a hub cannot
//! present a grant for one collection as another or hand it to someone else. A sealed box
//! is anonymous: it proves nothing about the sender, so who may grant is decided by the hub's
//! access rules and by the fingerprint a person confirms before granting.

use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::seal::{FORMAT_VERSION, NONCE_LEN, Purpose, decrypt, encrypt, open, purpose_of, seal};
use crate::{AccountKey, CollectionKey, KeyError, OpenError, SealError, random_bytes};

const KEY_LEN: usize = 32;
const GRANT_HEADER_LEN: usize = 2 + KEY_LEN + NONCE_LEN;
const GRANT_INFO: &[u8] = b"nocterm-grant-v1/key";

/// Bytes that are not an X25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an X25519 public key has 32 bytes")]
pub struct PublicKeyError;

/// The X25519 public key of an account, published on the hub.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// A public key from the 32 bytes the hub stores.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        bytes.try_into().map(Self).map_err(|_| PublicKeyError)
    }

    /// The 32 bytes.
    pub fn to_bytes(self) -> [u8; KEY_LEN] {
        self.0
    }

    /// The 32 bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// SHA-256 of the key as uppercase hexadecimal in groups of four, separated by dashes
    /// (`ABCD-0123-…`, 16 groups). People compare it before they grant a key: show all of it,
    /// it carries 256 bits and any prefix below 128 bits would be too short.
    pub fn fingerprint(&self) -> String {
        let digest = hex::encode_upper(Sha256::digest(self.0));
        digest
            .as_bytes()
            .chunks(4)
            .map(|group| String::from_utf8_lossy(group))
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0))
    }
}

/// The X25519 key pair of an account: its public half is published, its private half is
/// stored on the hub sealed by the account key.
pub struct AccountKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl AccountKeyPair {
    /// A fresh random pair.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self::from_seed(&Zeroizing::new(random_bytes::<KEY_LEN>()?)))
    }

    pub(crate) fn from_seed(seed: &[u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(*seed);
        let public = PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes());
        Self { secret, public }
    }

    /// The public half.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Seals the private half with the account key for storage on the hub.
    pub fn seal(&self, account: &AccountKey, account_id: &str) -> Result<Vec<u8>, SealError> {
        seal(
            &account.0,
            Purpose::AccountPrivateKey,
            &[account_id],
            self.secret.as_bytes(),
        )
    }

    /// Opens a pair sealed by [`AccountKeyPair::seal`]; `public` is the key the hub
    /// published, and a private half that does not belong to it is rejected.
    pub fn open(
        account: &AccountKey,
        account_id: &str,
        sealed: &[u8],
        public: &PublicKey,
    ) -> Result<Self, OpenError> {
        let bytes = open(
            &account.0,
            Purpose::AccountPrivateKey,
            &[account_id],
            sealed,
        )?;
        let seed: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| OpenError::Malformed)?,
        );
        let pair = Self::from_seed(&seed);
        if pair.public != *public {
            return Err(OpenError::Rejected);
        }
        Ok(pair)
    }

    fn agree(&self, peer: &[u8; KEY_LEN]) -> SharedSecret {
        self.secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*peer))
    }
}

impl fmt::Debug for AccountKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

fn grant_key(
    shared: &SharedSecret,
    ephemeral: &[u8; KEY_LEN],
    recipient: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let mut salt = [0u8; 2 * KEY_LEN];
    salt[..KEY_LEN].copy_from_slice(ephemeral);
    salt[KEY_LEN..].copy_from_slice(recipient);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(GRANT_INFO, key.as_mut())
        .map_err(KeyError::Expand)?;
    Ok(key)
}

impl CollectionKey {
    /// Seals this key to `recipient`, bound to the collection and the recipient's account.
    pub fn seal_to(
        &self,
        recipient: &PublicKey,
        collection_id: &str,
        recipient_account_id: &str,
    ) -> Result<Vec<u8>, SealError> {
        let ephemeral = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let nonce = random_bytes::<NONCE_LEN>()?;
        self.seal_to_with(
            recipient,
            collection_id,
            recipient_account_id,
            &ephemeral,
            &nonce,
        )
    }

    fn seal_to_with(
        &self,
        recipient: &PublicKey,
        collection_id: &str,
        recipient_account_id: &str,
        ephemeral_seed: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, SealError> {
        let ephemeral = AccountKeyPair::from_seed(ephemeral_seed);
        let shared = ephemeral.agree(&recipient.0);
        if !shared.was_contributory() {
            return Err(SealError::UnusableRecipientKey);
        }
        let key = grant_key(&shared, &ephemeral.public.0, &recipient.0)?;
        let ciphertext = encrypt(
            &key,
            Purpose::CollectionGrant,
            &[collection_id, recipient_account_id],
            nonce,
            &self.0,
        )?;
        let mut sealed = Vec::with_capacity(GRANT_HEADER_LEN + ciphertext.len());
        sealed.push(FORMAT_VERSION);
        sealed.push(Purpose::CollectionGrant as u8);
        sealed.extend_from_slice(&ephemeral.public.0);
        sealed.extend_from_slice(nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Opens the key envelope the hub returns for this account: a key the account sealed for
    /// itself ([`CollectionKey::seal_for`], the creator's) or a grant made to it
    /// ([`CollectionKey::seal_to`]). The two are told apart by the purpose byte, and anything
    /// else is [`OpenError::Malformed`].
    pub fn open_envelope(
        account: &AccountKey,
        pair: &AccountKeyPair,
        collection_id: &str,
        account_id: &str,
        sealed: &[u8],
    ) -> Result<Self, OpenError> {
        match purpose_of(sealed) {
            Some(p) if p == Purpose::CollectionKey as u8 => {
                Self::open(account, collection_id, sealed)
            }
            Some(p) if p == Purpose::CollectionGrant as u8 => {
                Self::open_from(pair, collection_id, account_id, sealed)
            }
            _ => Err(OpenError::Malformed),
        }
    }

    /// Opens a grant made by [`CollectionKey::seal_to`] for this account.
    ///
    /// Fails with [`OpenError::Rejected`] for another recipient's key, another collection or
    /// another account identifier, and with [`OpenError::Malformed`] for anything that is not
    /// a grant.
    pub fn open_from(
        recipient: &AccountKeyPair,
        collection_id: &str,
        recipient_account_id: &str,
        sealed: &[u8],
    ) -> Result<Self, OpenError> {
        if sealed.len() < GRANT_HEADER_LEN
            || sealed[0] != FORMAT_VERSION
            || sealed[1] != Purpose::CollectionGrant as u8
        {
            return Err(OpenError::Malformed);
        }
        let ephemeral: [u8; KEY_LEN] = sealed[2..2 + KEY_LEN]
            .try_into()
            .map_err(|_| OpenError::Malformed)?;
        let nonce: [u8; NONCE_LEN] = sealed[2 + KEY_LEN..GRANT_HEADER_LEN]
            .try_into()
            .map_err(|_| OpenError::Malformed)?;
        let shared = recipient.agree(&ephemeral);
        if !shared.was_contributory() {
            return Err(OpenError::Malformed);
        }
        let key =
            grant_key(&shared, &ephemeral, &recipient.public.0).map_err(|_| OpenError::Rejected)?;
        let bytes = decrypt(
            &key,
            Purpose::CollectionGrant,
            &[collection_id, recipient_account_id],
            &nonce,
            &sealed[GRANT_HEADER_LEN..],
        )?;
        Ok(Self(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| OpenError::Malformed)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(first: u8) -> [u8; 32] {
        core::array::from_fn(|i| first + u8::try_from(i).unwrap())
    }

    fn recipient() -> AccountKeyPair {
        AccountKeyPair::from_seed(&seed(0x40))
    }

    fn collection() -> CollectionKey {
        CollectionKey(seed(0xA0))
    }

    /// Sealed by an independent implementation (Python `cryptography` for X25519 and HKDF,
    /// PyCryptodome for XChaCha20-Poly1305).
    const GRANT: &str = concat!(
        "0107675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f808182838485",
        "868788898a8b8c8d8e8f9091929394959697f5209cdfa3ee771591111992e8708a7647248ec38727",
        "3135d404e9900332157496209fecce5057bc79be32acf437c8e1"
    );

    #[test]
    fn the_public_key_and_fingerprint_match_the_fixed_vectors() {
        let public = recipient().public_key();
        assert_eq!(
            hex::encode(public.as_bytes()),
            "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
        );
        assert_eq!(
            public.fingerprint(),
            "67CA-2FFD-6FE9-EFAB-3D76-E37C-3499-0A5A-33ED-C520-62F0-ECBD-0938-ACC9-1AF7-A425"
        );
    }

    #[test]
    fn a_grant_made_elsewhere_opens() {
        let sealed = hex::decode(GRANT).unwrap();
        let key = CollectionKey::open_from(&recipient(), "col-1", "acc-2", &sealed).unwrap();
        assert_eq!(key.0, collection().0);
    }

    #[test]
    fn the_same_inputs_seal_to_the_fixed_vector() {
        let sealed = collection()
            .seal_to_with(
                &recipient().public_key(),
                "col-1",
                "acc-2",
                &seed(0x60),
                &seed(0x80)[..24].try_into().unwrap(),
            )
            .unwrap();
        assert_eq!(hex::encode(sealed), GRANT);
    }

    #[test]
    fn a_grant_round_trips() {
        let pair = AccountKeyPair::generate().unwrap();
        let key = CollectionKey::generate().unwrap();
        let sealed = key.seal_to(&pair.public_key(), "col", "acc").unwrap();
        let opened = CollectionKey::open_from(&pair, "col", "acc", &sealed).unwrap();
        assert_eq!(opened.0, key.0);
    }

    #[test]
    fn a_grant_does_not_open_for_another_key() {
        let sealed = hex::decode(GRANT).unwrap();
        let stranger = AccountKeyPair::generate().unwrap();
        assert_eq!(
            CollectionKey::open_from(&stranger, "col-1", "acc-2", &sealed).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_grant_does_not_open_for_another_collection() {
        let sealed = hex::decode(GRANT).unwrap();
        assert_eq!(
            CollectionKey::open_from(&recipient(), "col-2", "acc-2", &sealed).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_grant_does_not_open_for_another_account_identifier() {
        let sealed = hex::decode(GRANT).unwrap();
        assert_eq!(
            CollectionKey::open_from(&recipient(), "col-1", "acc-3", &sealed).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_modified_grant_is_rejected_wherever_it_is_changed() {
        let sealed = hex::decode(GRANT).unwrap();
        for index in [2, 40, 70, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert_eq!(
                CollectionKey::open_from(&recipient(), "col-1", "acc-2", &tampered).unwrap_err(),
                OpenError::Rejected,
                "byte {index}"
            );
        }
    }

    #[test]
    fn what_is_not_a_grant_is_malformed() {
        let sealed = hex::decode(GRANT).unwrap();
        let account = AccountKey(seed(1));
        let wrapped = collection().seal_for(&account, "col-1").unwrap();
        for bad in [&sealed[..40], &wrapped[..], &[][..]] {
            assert_eq!(
                CollectionKey::open_from(&recipient(), "col-1", "acc-2", bad).unwrap_err(),
                OpenError::Malformed
            );
        }
        let mut other_version = sealed;
        other_version[0] = 2;
        assert_eq!(
            CollectionKey::open_from(&recipient(), "col-1", "acc-2", &other_version).unwrap_err(),
            OpenError::Malformed
        );
    }

    #[test]
    fn an_envelope_is_opened_whether_it_was_sealed_by_the_owner_or_granted() {
        let account = AccountKey(seed(1));
        let own = collection().seal_for(&account, "col-1").unwrap();
        let granted = hex::decode(GRANT).unwrap();
        for sealed in [own, granted] {
            let key =
                CollectionKey::open_envelope(&account, &recipient(), "col-1", "acc-2", &sealed)
                    .unwrap();
            assert_eq!(key.0, collection().0);
        }
        assert_eq!(
            CollectionKey::open_envelope(&account, &recipient(), "col-1", "acc-2", b"junk")
                .unwrap_err(),
            OpenError::Malformed
        );
        let name = collection().seal_name("col-1", "x").unwrap();
        assert_eq!(
            CollectionKey::open_envelope(&account, &recipient(), "col-1", "acc-2", &name)
                .unwrap_err(),
            OpenError::Malformed
        );
    }

    #[test]
    fn an_ephemeral_key_of_small_order_is_refused() {
        let mut sealed = hex::decode(GRANT).unwrap();
        sealed[2..34].fill(0);
        assert_eq!(
            CollectionKey::open_from(&recipient(), "col-1", "acc-2", &sealed).unwrap_err(),
            OpenError::Malformed
        );
    }

    #[test]
    fn sealing_to_a_small_order_key_is_refused() {
        let zero = PublicKey([0; 32]);
        let err = collection().seal_to(&zero, "col", "acc").unwrap_err();
        assert!(matches!(err, SealError::UnusableRecipientKey));
    }

    #[test]
    fn two_grants_of_one_key_differ() {
        let public = recipient().public_key();
        let a = collection().seal_to(&public, "col", "acc").unwrap();
        let b = collection().seal_to(&public, "col", "acc").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_private_half_is_stored_sealed_and_bound_to_its_account() {
        let account = AccountKey(seed(1));
        let pair = AccountKeyPair::generate().unwrap();
        let sealed = pair.seal(&account, "acc-1").unwrap();
        let opened = AccountKeyPair::open(&account, "acc-1", &sealed, &pair.public_key()).unwrap();
        assert_eq!(opened.public_key(), pair.public_key());

        assert_eq!(
            AccountKeyPair::open(&account, "acc-2", &sealed, &pair.public_key()).unwrap_err(),
            OpenError::Rejected
        );
        let other = AccountKey(seed(2));
        assert_eq!(
            AccountKeyPair::open(&other, "acc-1", &sealed, &pair.public_key()).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_published_key_that_does_not_match_the_private_half_is_rejected() {
        let account = AccountKey(seed(1));
        let pair = AccountKeyPair::generate().unwrap();
        let sealed = pair.seal(&account, "acc-1").unwrap();
        let swapped = AccountKeyPair::generate().unwrap().public_key();
        assert_eq!(
            AccountKeyPair::open(&account, "acc-1", &sealed, &swapped).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn public_keys_have_32_bytes() {
        assert_eq!(PublicKey::from_bytes(&[1; 31]), Err(PublicKeyError));
        assert_eq!(PublicKey::from_bytes(&[1; 33]), Err(PublicKeyError));
        assert_eq!(PublicKey::from_bytes(&[1; 32]).unwrap().to_bytes(), [1; 32]);
    }

    #[test]
    fn the_private_half_is_not_printed() {
        let debug = format!("{:?}", recipient());
        assert!(debug.contains("public"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("64, 65, 66"));
    }
}
