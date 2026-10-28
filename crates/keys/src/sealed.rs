//! Keys sealed to a public key: the X25519 pair of an account and collection key grants.
//!
//! A grant hands a collection key to another account without the hub being able to read it,
//! move it or make one. It is an authenticated box from the granter's static X25519 pair and
//! a fresh ephemeral pair to the recipient's public key:
//!
//! ```text
//! dh1    = X25519(ephemeral secret, recipient public key)       // rejected if non-contributory
//! dh2    = X25519(sender secret, recipient public key)          // rejected if non-contributory
//! key    = HKDF-SHA256(salt = ephemeral public ‖ sender public ‖ recipient public,
//!                      ikm = dh1 ‖ dh2, info = "nocterm-grant-v1/auth")
//! sealed = 0x01 ‖ 0x07 ‖ ephemeral public ‖ nonce(24) ‖ XChaCha20-Poly1305(key, nonce,
//!          aad = "nocterm/v1/collection-grant" ‖ lp(collection id) ‖ lp(recipient account id)
//!                ‖ lp(sender fingerprint))
//! ```
//!
//! Opening needs the sender's public key (`dh2`), and the fingerprint of that key is in the
//! associated data. A recipient therefore opens a grant only if it names the key of the
//! account it expects to have granted: a grant the hub (or anyone else) made with a key of its
//! own fails to open. The associated data also binds the collection and the recipient account,
//! so a hub cannot present a grant for one collection as another or hand it to someone else.
//!
//! This authenticates the sender to the recipient, not to third parties: the recipient could
//! have produced the same bytes, so a grant is no signature and proves nothing to anyone else.
//! Which key belongs to which account is the client's decision ([`crate::PinnedKeys`]).

use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::seal::{FORMAT_VERSION, NONCE_LEN, Purpose, decrypt, encrypt, open, seal};
use crate::{AccountKey, CollectionKey, KeyError, OpenError, SealError, random_bytes};

const KEY_LEN: usize = 32;
const GRANT_HEADER_LEN: usize = 2 + KEY_LEN + NONCE_LEN;
const GRANT_INFO: &[u8] = b"nocterm-grant-v1/auth";

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

/// The keys of a grant, in the order of the HKDF salt and input.
struct GrantKeys<'a> {
    ephemeral: &'a [u8; KEY_LEN],
    sender: &'a [u8; KEY_LEN],
    recipient: &'a [u8; KEY_LEN],
}

impl GrantKeys<'_> {
    fn key(
        &self,
        dh_ephemeral: &SharedSecret,
        dh_sender: &SharedSecret,
    ) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let mut salt = [0u8; 3 * KEY_LEN];
        salt[..KEY_LEN].copy_from_slice(self.ephemeral);
        salt[KEY_LEN..2 * KEY_LEN].copy_from_slice(self.sender);
        salt[2 * KEY_LEN..].copy_from_slice(self.recipient);
        let mut ikm = Zeroizing::new([0u8; 2 * KEY_LEN]);
        ikm[..KEY_LEN].copy_from_slice(dh_ephemeral.as_bytes());
        ikm[KEY_LEN..].copy_from_slice(dh_sender.as_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&salt), ikm.as_ref())
            .expand(GRANT_INFO, key.as_mut())
            .map_err(KeyError::Expand)?;
        Ok(key)
    }
}

impl CollectionKey {
    /// Seals this key from `sender` to `recipient`, bound to the collection, the recipient's
    /// account and the sender's key.
    pub fn seal_to(
        &self,
        sender: &AccountKeyPair,
        recipient: &PublicKey,
        collection_id: &str,
        recipient_account_id: &str,
    ) -> Result<Vec<u8>, SealError> {
        let ephemeral = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let nonce = random_bytes::<NONCE_LEN>()?;
        self.seal_to_with(
            sender,
            recipient,
            collection_id,
            recipient_account_id,
            &ephemeral,
            &nonce,
        )
    }

    fn seal_to_with(
        &self,
        sender: &AccountKeyPair,
        recipient: &PublicKey,
        collection_id: &str,
        recipient_account_id: &str,
        ephemeral_seed: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, SealError> {
        let ephemeral = AccountKeyPair::from_seed(ephemeral_seed);
        let dh_ephemeral = ephemeral.agree(&recipient.0);
        let dh_sender = sender.agree(&recipient.0);
        if !dh_ephemeral.was_contributory() || !dh_sender.was_contributory() {
            return Err(SealError::UnusableRecipientKey);
        }
        let key = GrantKeys {
            ephemeral: &ephemeral.public.0,
            sender: &sender.public.0,
            recipient: &recipient.0,
        }
        .key(&dh_ephemeral, &dh_sender)?;
        let ciphertext = encrypt(
            &key,
            Purpose::CollectionGrant,
            &[
                collection_id,
                recipient_account_id,
                &sender.public.fingerprint(),
            ],
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

    /// Opens a grant made by [`CollectionKey::seal_to`] for this account by the holder of
    /// `sender`.
    ///
    /// Fails with [`OpenError::Rejected`] for a grant made by another key than `sender`, for
    /// another recipient's key, another collection or another account identifier, and with
    /// [`OpenError::Malformed`] for anything that is not a grant.
    pub fn open_from(
        recipient: &AccountKeyPair,
        sender: &PublicKey,
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
        let dh_ephemeral = recipient.agree(&ephemeral);
        let dh_sender = recipient.agree(&sender.0);
        if !dh_ephemeral.was_contributory() || !dh_sender.was_contributory() {
            return Err(OpenError::Malformed);
        }
        let key = GrantKeys {
            ephemeral: &ephemeral,
            sender: &sender.0,
            recipient: &recipient.public.0,
        }
        .key(&dh_ephemeral, &dh_sender)
        .map_err(|_| OpenError::Rejected)?;
        let bytes = decrypt(
            &key,
            Purpose::CollectionGrant,
            &[collection_id, recipient_account_id, &sender.fingerprint()],
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

    fn sender() -> AccountKeyPair {
        AccountKeyPair::from_seed(&seed(0x10))
    }

    fn collection() -> CollectionKey {
        CollectionKey(seed(0xA0))
    }

    fn open(sealed: &[u8]) -> Result<CollectionKey, OpenError> {
        CollectionKey::open_from(
            &recipient(),
            &sender().public_key(),
            "col-1",
            "acc-2",
            sealed,
        )
    }

    /// Sealed by an independent implementation (Python `cryptography` for X25519 and HKDF,
    /// PyCryptodome for XChaCha20-Poly1305): sender seed 0x10.., recipient 0x40.., ephemeral
    /// 0x60.., nonce 0x80.., collection key 0xA0...
    const GRANT: &str = concat!(
        "0107675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f808182838485",
        "868788898a8b8c8d8e8f909192939495969733f736665ab683a196081a25101cc7819cf52bdffc66",
        "cf2ef9ba24d496d860ff4f1b5ff0219cbda50fef269b9025b7fa"
    );

    #[test]
    fn the_public_keys_and_fingerprints_match_the_fixed_vectors() {
        let public = recipient().public_key();
        assert_eq!(
            hex::encode(public.as_bytes()),
            "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
        );
        assert_eq!(
            public.fingerprint(),
            "67CA-2FFD-6FE9-EFAB-3D76-E37C-3499-0A5A-33ED-C520-62F0-ECBD-0938-ACC9-1AF7-A425"
        );
        let public = sender().public_key();
        assert_eq!(
            hex::encode(public.as_bytes()),
            "d89e3bad79437dbed9f843418304f460ff05c7fe81fe4a9577a804cb9367ff66"
        );
        assert_eq!(
            public.fingerprint(),
            "1AEB-44C4-F0F5-C20C-04E3-E5FD-6BA8-EE4D-F28C-51F0-22B4-E154-FBB9-BB3A-A713-53B0"
        );
    }

    #[test]
    fn a_grant_made_elsewhere_opens() {
        let key = open(&hex::decode(GRANT).unwrap()).unwrap();
        assert_eq!(key.0, collection().0);
    }

    #[test]
    fn the_same_inputs_seal_to_the_fixed_vector() {
        let sealed = collection()
            .seal_to_with(
                &sender(),
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
        let (from, to) = (
            AccountKeyPair::generate().unwrap(),
            AccountKeyPair::generate().unwrap(),
        );
        let key = CollectionKey::generate().unwrap();
        let sealed = key.seal_to(&from, &to.public_key(), "col", "acc").unwrap();
        let opened =
            CollectionKey::open_from(&to, &from.public_key(), "col", "acc", &sealed).unwrap();
        assert_eq!(opened.0, key.0);
    }

    #[test]
    fn a_grant_opens_only_under_the_key_of_the_account_that_made_it() {
        // The hub makes its own grant of a key it chose, to the recipient's public key.
        let hub = AccountKeyPair::generate().unwrap();
        let chosen = CollectionKey::generate().unwrap();
        let forged = chosen
            .seal_to(&hub, &recipient().public_key(), "col-1", "acc-2")
            .unwrap();

        // A recipient that expects the real granter refuses it.
        assert_eq!(open(&forged).unwrap_err(), OpenError::Rejected);
        // Only a recipient that was made to trust the hub's key accepts it.
        let accepted =
            CollectionKey::open_from(&recipient(), &hub.public_key(), "col-1", "acc-2", &forged)
                .unwrap();
        assert_eq!(accepted.0, chosen.0);
        // The real grant does not open under the hub's key either.
        assert_eq!(
            CollectionKey::open_from(
                &recipient(),
                &hub.public_key(),
                "col-1",
                "acc-2",
                &hex::decode(GRANT).unwrap()
            )
            .unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_grant_does_not_open_for_another_key() {
        let stranger = AccountKeyPair::generate().unwrap();
        let sealed = hex::decode(GRANT).unwrap();
        assert_eq!(
            CollectionKey::open_from(&stranger, &sender().public_key(), "col-1", "acc-2", &sealed)
                .unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_grant_does_not_open_for_another_collection_or_account_identifier() {
        let sealed = hex::decode(GRANT).unwrap();
        let sender = sender().public_key();
        for (collection, account) in [("col-2", "acc-2"), ("col-1", "acc-3")] {
            assert_eq!(
                CollectionKey::open_from(&recipient(), &sender, collection, account, &sealed)
                    .unwrap_err(),
                OpenError::Rejected,
                "{collection} {account}"
            );
        }
    }

    #[test]
    fn a_modified_grant_is_rejected_wherever_it_is_changed() {
        let sealed = hex::decode(GRANT).unwrap();
        for index in [2, 40, 70, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert_eq!(
                open(&tampered).unwrap_err(),
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
            assert_eq!(open(bad).unwrap_err(), OpenError::Malformed);
        }
        let mut other_version = sealed;
        other_version[0] = 2;
        assert_eq!(open(&other_version).unwrap_err(), OpenError::Malformed);
    }

    #[test]
    fn an_own_envelope_and_a_grant_each_open_only_by_their_own_method() {
        let account = AccountKey(seed(1));
        let own = collection().seal_for(&account, "col-1").unwrap();
        let granted = hex::decode(GRANT).unwrap();

        assert_eq!(
            CollectionKey::open(&account, "col-1", &own).unwrap().0,
            collection().0
        );
        assert_eq!(open(&granted).unwrap().0, collection().0);
        // The kind is the caller's choice, not the hub's: a value of the other kind is an
        // error whatever its purpose byte says.
        assert_eq!(
            CollectionKey::open(&account, "col-1", &granted).unwrap_err(),
            OpenError::Malformed
        );
        assert_eq!(open(&own).unwrap_err(), OpenError::Malformed);
    }

    #[test]
    fn keys_of_small_order_are_refused_on_both_sides() {
        let mut sealed = hex::decode(GRANT).unwrap();
        sealed[2..34].fill(0);
        assert_eq!(open(&sealed).unwrap_err(), OpenError::Malformed);

        let zero = PublicKey([0; 32]);
        let sealed = hex::decode(GRANT).unwrap();
        assert_eq!(
            CollectionKey::open_from(&recipient(), &zero, "col-1", "acc-2", &sealed).unwrap_err(),
            OpenError::Malformed
        );
        let err = collection()
            .seal_to(&sender(), &zero, "col", "acc")
            .unwrap_err();
        assert!(matches!(err, SealError::UnusableRecipientKey));
    }

    #[test]
    fn two_grants_of_one_key_differ() {
        let public = recipient().public_key();
        let a = collection()
            .seal_to(&sender(), &public, "col", "acc")
            .unwrap();
        let b = collection()
            .seal_to(&sender(), &public, "col", "acc")
            .unwrap();
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
