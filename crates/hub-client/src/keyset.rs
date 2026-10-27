//! The account keyset on the hub: creating it, opening it with the unlock key or the recovery
//! key, and granting collection keys to other members.
//!
//! The hub stores the keyset as sealed values and checks only versions: it never holds a key
//! that opens one. Every value read back is opened here, and one that does not open fails
//! loudly instead of being replaced.

use nocterm_hub_proto::v1;
use nocterm_keys::{
    AccountKey, AccountKeyPair, CollectionKey, KdfParseError, KeyError, OpenError, PublicKey,
    PublicKeyError, RecoveryKey, SealError, UnlockKdf, UnlockKey,
};

use crate::{ClientError, HubClient, StatusCode};

/// The keyset of an account could not be created, opened or used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeysetError {
    /// The hub call failed.
    #[error(transparent)]
    Hub(#[from] ClientError),
    /// The account already has a keyset (another device created it first); open that one.
    #[error("the account already has a keyset")]
    AlreadyExists,
    /// The hub's keyset has no key pair or no recovery key (created by an older version).
    #[error("the keyset on the hub is incomplete")]
    Incomplete,
    /// The unlock key does not open the account key: wrong vault password.
    #[error("the unlock key does not open the account key")]
    WrongUnlockKey,
    /// The recovery key does not open the account key.
    #[error("the recovery key does not open the account key")]
    WrongRecoveryKey,
    /// A value of the keyset does not open although the account key does: the hub altered it.
    #[error("the keyset on the hub is damaged")]
    Damaged(#[source] OpenError),
    /// The KDF description or salt in the keyset is weaker than this client accepts.
    #[error("the keyset names an unacceptable key derivation")]
    Kdf(#[from] KdfParseError),
    /// No randomness for a new key.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A key could not be sealed.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// A public key from the hub is not 32 bytes.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
}

/// The open keys of an account.
#[derive(Debug)]
pub struct Keyset {
    account_id: String,
    version: u64,
    account_key: AccountKey,
    pair: AccountKeyPair,
}

/// A keyset created now, with the recovery key to show the user once.
#[derive(Debug)]
pub struct NewKeyset {
    /// The keys of the new account.
    pub keyset: Keyset,
    /// Shown once and stored nowhere: it is the only way back after a lost password.
    pub recovery: RecoveryKey,
}

impl Keyset {
    /// The account these keys belong to.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The version of the keyset on the hub, for the next conditional write.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The key that wraps collection keys the account creates.
    pub fn account_key(&self) -> &AccountKey {
        &self.account_key
    }

    /// The account's X25519 pair.
    pub fn key_pair(&self) -> &AccountKeyPair {
        &self.pair
    }

    /// The public half, published on the hub.
    pub fn public_key(&self) -> PublicKey {
        self.pair.public_key()
    }

    /// Opens the envelope of a collection this account created and sealed for itself
    /// ([`Keyset::seal_collection_key`]).
    ///
    /// Use it for every personal collection (`org_id` empty) and for any collection the
    /// account itself created. A grant is refused here with [`OpenError::Malformed`]: the hub
    /// chooses what it returns, and a grant can be made by anyone who knows the public key, so
    /// accepting one in place of the account's own envelope would let the hub choose the key
    /// of a personal collection.
    pub fn open_own_collection_key(
        &self,
        collection_id: &str,
        sealed: &[u8],
    ) -> Result<CollectionKey, OpenError> {
        CollectionKey::open(&self.account_key, collection_id, sealed)
    }

    /// Opens a key another member granted to this account for an organization collection.
    ///
    /// An envelope the account sealed for itself is refused with [`OpenError::Malformed`].
    pub fn open_granted_collection_key(
        &self,
        collection_id: &str,
        sealed: &[u8],
    ) -> Result<CollectionKey, OpenError> {
        CollectionKey::open_from(&self.pair, collection_id, &self.account_id, sealed)
    }

    /// Seals a collection key this account created, for `CreateCollection`.
    pub fn seal_collection_key(
        &self,
        key: &CollectionKey,
        collection_id: &str,
    ) -> Result<Vec<u8>, SealError> {
        key.seal_for(&self.account_key, collection_id)
    }

    /// A first keyset: a fresh account key, pair and recovery key, sealed for the hub.
    fn build(
        account_id: &str,
        unlock: &UnlockKey,
        kdf: &UnlockKdf,
    ) -> Result<(NewKeyset, v1::PutAccountKeysetRequest), KeysetError> {
        let account_key = AccountKey::generate()?;
        let pair = AccountKeyPair::generate()?;
        let recovery = RecoveryKey::generate()?;
        let request = Self::request(0, account_id, &account_key, &pair, unlock, kdf, &recovery)?;
        let keyset = Keyset {
            account_id: account_id.to_owned(),
            version: 0,
            account_key,
            pair,
        };
        Ok((NewKeyset { keyset, recovery }, request))
    }

    fn request(
        expected_version: u64,
        account_id: &str,
        account_key: &AccountKey,
        pair: &AccountKeyPair,
        unlock: &UnlockKey,
        kdf: &UnlockKdf,
        recovery: &RecoveryKey,
    ) -> Result<v1::PutAccountKeysetRequest, KeysetError> {
        Ok(v1::PutAccountKeysetRequest {
            expected_version,
            kdf: kdf.description(),
            salt: kdf.salt().to_vec(),
            wrapped_account_key: account_key.seal(unlock, account_id)?,
            public_key: pair.public_key().to_bytes().to_vec(),
            sealed_private_key: pair.seal(account_key, account_id)?,
            recovery_wrapped_account_key: recovery.wrap(account_key, account_id)?,
        })
    }

    /// Opens the key pair of a keyset whose account key is already open.
    fn with_account_key(
        record: &v1::AccountKeyset,
        account_id: &str,
        account_key: AccountKey,
    ) -> Result<Self, KeysetError> {
        if record.public_key.is_empty() || record.sealed_private_key.is_empty() {
            return Err(KeysetError::Incomplete);
        }
        let public = PublicKey::from_bytes(&record.public_key)?;
        let pair = AccountKeyPair::open(
            &account_key,
            account_id,
            &record.sealed_private_key,
            &public,
        )
        .map_err(KeysetError::Damaged)?;
        Ok(Self {
            account_id: account_id.to_owned(),
            version: record.version,
            account_key,
            pair,
        })
    }

    /// Opens a keyset with the unlock key derived from the password.
    pub fn open(
        record: &v1::AccountKeyset,
        account_id: &str,
        unlock: &UnlockKey,
    ) -> Result<Self, KeysetError> {
        let account_key = AccountKey::open(unlock, account_id, &record.wrapped_account_key)
            .map_err(|err| match err {
                OpenError::Rejected => KeysetError::WrongUnlockKey,
                OpenError::Malformed => KeysetError::Damaged(err),
            })?;
        Self::with_account_key(record, account_id, account_key)
    }

    /// Opens a keyset with the recovery key.
    pub fn recover(
        record: &v1::AccountKeyset,
        account_id: &str,
        recovery: &RecoveryKey,
    ) -> Result<Self, KeysetError> {
        if record.recovery_wrapped_account_key.is_empty() {
            return Err(KeysetError::Incomplete);
        }
        let account_key = recovery
            .unwrap(account_id, &record.recovery_wrapped_account_key)
            .map_err(|err| match err {
                OpenError::Rejected => KeysetError::WrongRecoveryKey,
                OpenError::Malformed => KeysetError::Damaged(err),
            })?;
        Self::with_account_key(record, account_id, account_key)
    }
}

impl HubClient {
    /// The account's keyset record as the hub stores it; `None` before the first device
    /// created it.
    pub async fn keyset_record(&self) -> Result<Option<v1::AccountKeyset>, ClientError> {
        match self
            .store()
            .get_account_keyset(v1::GetAccountKeysetRequest {})
            .await
        {
            Ok(record) => Ok(Some(record.into_inner())),
            Err(status) => match ClientError::from(status) {
                ClientError::Status {
                    code: StatusCode::NotFound,
                    ..
                } => Ok(None),
                other => Err(other),
            },
        }
    }

    /// Creates the account's keyset (the first sign-in of the account).
    ///
    /// The write is conditional on there being no keyset: when two devices race, the second
    /// gets [`KeysetError::AlreadyExists`] and must open the one that exists with
    /// [`HubClient::open_keyset`], never overwrite it.
    pub async fn create_keyset(
        &self,
        account_id: &str,
        unlock: &UnlockKey,
        kdf: &UnlockKdf,
    ) -> Result<NewKeyset, KeysetError> {
        let (mut created, request) = Keyset::build(account_id, unlock, kdf)?;
        let stored = self
            .store()
            .put_account_keyset(request)
            .await
            .map_err(ClientError::from)
            .map_err(|err| {
                if err.is_conflict() {
                    KeysetError::AlreadyExists
                } else {
                    KeysetError::Hub(err)
                }
            })?
            .into_inner();
        created.keyset.version = stored.version;
        Ok(created)
    }

    /// Opens the account's keyset with the unlock key; `None` when none exists yet.
    pub async fn open_keyset(
        &self,
        account_id: &str,
        unlock: &UnlockKey,
    ) -> Result<Option<Keyset>, KeysetError> {
        let Some(record) = self.keyset_record().await? else {
            return Ok(None);
        };
        Keyset::open(&record, account_id, unlock).map(Some)
    }

    /// Opens the keyset with the recovery key and seals the account key anew under the unlock
    /// key of the new password, so the next sign-in opens it without the recovery key.
    ///
    /// The recovery key stays valid. The write is conditional on the version just read.
    pub async fn recover_keyset(
        &self,
        account_id: &str,
        recovery: &RecoveryKey,
        unlock: &UnlockKey,
        kdf: &UnlockKdf,
    ) -> Result<Keyset, KeysetError> {
        let record = self.keyset_record().await?.ok_or(KeysetError::Incomplete)?;
        let mut keyset = Keyset::recover(&record, account_id, recovery)?;
        let request = Keyset::request(
            record.version,
            account_id,
            &keyset.account_key,
            &keyset.pair,
            unlock,
            kdf,
            recovery,
        )?;
        let stored = self
            .store()
            .put_account_keyset(request)
            .await
            .map_err(ClientError::from)?
            .into_inner();
        keyset.version = stored.version;
        Ok(keyset)
    }

    /// Grants `key` of `collection_id` to another member: seals it to the member's public
    /// key, bound to the collection and the member's account, and asks the hub to store it.
    ///
    /// The caller decides whose key this is, for example after a person confirmed the
    /// fingerprint of `recipient`; the hub still checks who may grant.
    pub async fn grant(
        &self,
        collection_id: &str,
        key: &CollectionKey,
        recipient_account_id: &str,
        recipient: &PublicKey,
    ) -> Result<(), KeysetError> {
        let sealed_key = key.seal_to(recipient, collection_id, recipient_account_id)?;
        self.store()
            .grant_collection_key(v1::GrantCollectionKeyRequest {
                collection_id: collection_id.to_owned(),
                account_id: recipient_account_id.to_owned(),
                sealed_key,
            })
            .await
            .map_err(ClientError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use nocterm_keys::KdfParams;

    use super::*;

    fn unlock() -> UnlockKey {
        UnlockKey::from_vault_password(
            "correct horse battery",
            &UnlockKdf::new(KdfParams::MINIMUM, vec![5; 16]).unwrap(),
        )
        .unwrap()
    }

    fn kdf() -> UnlockKdf {
        UnlockKdf::new(KdfParams::MINIMUM, vec![5; 16]).unwrap()
    }

    /// The record the hub would return after storing `request`.
    fn stored(request: &v1::PutAccountKeysetRequest, version: u64) -> v1::AccountKeyset {
        v1::AccountKeyset {
            version,
            kdf: request.kdf.clone(),
            salt: request.salt.clone(),
            wrapped_account_key: request.wrapped_account_key.clone(),
            updated_at_ms: 0,
            public_key: request.public_key.clone(),
            sealed_private_key: request.sealed_private_key.clone(),
            recovery_wrapped_account_key: request.recovery_wrapped_account_key.clone(),
        }
    }

    #[test]
    fn a_new_keyset_opens_with_the_unlock_key_and_with_the_recovery_key() {
        let (created, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        assert_eq!(request.expected_version, 0);
        assert_eq!(request.kdf, "argon2id;m=65536;t=3;p=4");
        let record = stored(&request, 1);

        let by_unlock = Keyset::open(&record, "acc-1", &unlock()).unwrap();
        let by_recovery = Keyset::recover(&record, "acc-1", &created.recovery).unwrap();
        for opened in [&by_unlock, &by_recovery] {
            assert_eq!(opened.public_key(), created.keyset.public_key());
            assert_eq!(opened.version(), 1);
            assert_eq!(opened.account_id(), "acc-1");
        }
    }

    #[test]
    fn a_wrong_unlock_or_recovery_key_is_told_apart_from_damage() {
        let (_, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        let record = stored(&request, 1);
        let other_unlock = UnlockKey::from_vault_password(
            "another password",
            &UnlockKdf::new(KdfParams::MINIMUM, vec![6; 16]).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            Keyset::open(&record, "acc-1", &other_unlock),
            Err(KeysetError::WrongUnlockKey)
        ));
        let other_recovery = RecoveryKey::generate().unwrap();
        assert!(matches!(
            Keyset::recover(&record, "acc-1", &other_recovery),
            Err(KeysetError::WrongRecoveryKey)
        ));
        assert!(matches!(
            Keyset::open(&record, "acc-2", &unlock()),
            Err(KeysetError::WrongUnlockKey)
        ));
    }

    #[test]
    fn a_public_key_swapped_by_the_hub_is_an_error_not_a_silent_replacement() {
        let (_, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        let mut record = stored(&request, 1);
        let stranger = AccountKeyPair::generate().unwrap().public_key();
        record.public_key = stranger.to_bytes().to_vec();
        assert!(matches!(
            Keyset::open(&record, "acc-1", &unlock()),
            Err(KeysetError::Damaged(OpenError::Rejected))
        ));
        record.public_key = vec![1; 5];
        assert!(matches!(
            Keyset::open(&record, "acc-1", &unlock()),
            Err(KeysetError::PublicKey(_))
        ));
    }

    #[test]
    fn a_keyset_without_a_key_pair_is_incomplete() {
        let (created, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        let mut record = stored(&request, 1);
        record.public_key.clear();
        record.sealed_private_key.clear();
        assert!(matches!(
            Keyset::open(&record, "acc-1", &unlock()),
            Err(KeysetError::Incomplete)
        ));
        let mut record = stored(&request, 1);
        record.recovery_wrapped_account_key.clear();
        assert!(matches!(
            Keyset::recover(&record, "acc-1", &created.recovery),
            Err(KeysetError::Incomplete)
        ));
    }

    #[test]
    fn the_caller_chooses_how_an_envelope_opens_and_a_wrong_kind_is_an_error() {
        let (alice, _) = Keyset::build("alice", &unlock(), &kdf()).unwrap();
        let (bob, _) = Keyset::build("bob", &unlock(), &kdf()).unwrap();
        let key = CollectionKey::generate().unwrap();

        let own = alice.keyset.seal_collection_key(&key, "col").unwrap();
        assert!(alice.keyset.open_own_collection_key("col", &own).is_ok());
        assert!(matches!(
            alice.keyset.open_granted_collection_key("col", &own),
            Err(OpenError::Malformed)
        ));

        let grant = key.seal_to(&bob.keyset.public_key(), "col", "bob").unwrap();
        let opened = bob
            .keyset
            .open_granted_collection_key("col", &grant)
            .unwrap();
        let name = key.seal_name("col", "Servers").unwrap();
        assert_eq!(opened.open_name("col", &name).unwrap(), "Servers");

        assert!(
            alice
                .keyset
                .open_granted_collection_key("col", &grant)
                .is_err()
        );
        assert!(
            bob.keyset
                .open_granted_collection_key("other", &grant)
                .is_err()
        );
    }

    #[test]
    fn a_hub_cannot_put_a_grant_in_place_of_the_owners_own_envelope() {
        let (owner, _) = Keyset::build("owner", &unlock(), &kdf()).unwrap();
        let chosen_by_hub = CollectionKey::generate().unwrap();
        // Anyone who knows the published public key can make this; the hub answers
        // `GetCollectionKey` of the personal collection `vault` with it.
        let forged = chosen_by_hub
            .seal_to(&owner.keyset.public_key(), "vault", "owner")
            .unwrap();

        assert!(matches!(
            owner.keyset.open_own_collection_key("vault", &forged),
            Err(OpenError::Malformed)
        ));
    }
}
