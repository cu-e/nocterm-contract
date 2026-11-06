//! The account keyset on the hub: creating it and opening it with the unlock key or the recovery
//! key.
//!
//! The hub stores the keyset as sealed values and checks only versions: it never holds a key
//! that opens one. Every value read back is opened here, and one that does not open fails
//! loudly instead of being replaced.

use nocterm_hub_proto::v2;
use nocterm_keys::{
    AccountKey, CollectionKey, KdfParseError, KeyError, KeysetMaterial, KeysetMaterialError,
    OpenError, RecoveryKey, SealError, UnlockKdf, UnlockKey, UnlockSource, create_keyset,
    seal_keyset,
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
    /// The hub's keyset has no recovery key or no record of how its unlock key is derived.
    #[error("the keyset on the hub is incomplete")]
    Incomplete,
    /// The keyset records a way of deriving the unlock key that this client does not know.
    #[error("the keyset uses an unlock derivation this client does not know ({kind})")]
    UnsupportedUnlock {
        /// The value of `unlock_kind` as the hub sent it.
        kind: i32,
    },
    /// The unlock key comes from the other password than the one the keyset records: the
    /// login password where the vault password is needed, or the reverse.
    #[error("the keyset needs the {stored:?} but the unlock key comes from the {given:?}")]
    WrongUnlockSource {
        /// The source the keyset records.
        stored: UnlockSource,
        /// The source of the key that was offered.
        given: UnlockSource,
    },
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
}

/// How the unlock key of a stored keyset is derived, read from the keyset itself.
///
/// The client picks the derivation by this record, never by how the user happened to sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockMethod {
    /// From the login password: `LoginSecrets::derive(password, hub_id, username)`. The `kdf`
    /// and `salt` of the keyset are not used.
    LoginPassword,
    /// From a separate vault password: `UnlockKey::from_vault_password(password, &kdf)` with
    /// the stored parameters and salt, already checked.
    VaultPassword(UnlockKdf),
}

impl UnlockMethod {
    /// The method a keyset records. Errors are [`KeysetError::Incomplete`] for a keyset that
    /// records none, [`KeysetError::UnsupportedUnlock`] for a value this client does not know,
    /// and [`KeysetError::Kdf`] for stored parameters it refuses.
    pub fn of(record: &v2::Keyset) -> Result<Self, KeysetError> {
        match v2::UnlockKind::try_from(record.unlock_kind) {
            Ok(v2::UnlockKind::LoginPassword) => Ok(Self::LoginPassword),
            Ok(v2::UnlockKind::VaultPassword) => Ok(Self::VaultPassword(UnlockKdf::parse(
                &record.kdf,
                &record.salt,
            )?)),
            Ok(v2::UnlockKind::Unspecified) => Err(KeysetError::Incomplete),
            Err(_) => Err(KeysetError::UnsupportedUnlock {
                kind: record.unlock_kind,
            }),
        }
    }

    /// The source an unlock key must come from to open the keyset.
    pub fn source(&self) -> UnlockSource {
        match self {
            Self::LoginPassword => UnlockSource::LoginPassword,
            Self::VaultPassword(_) => UnlockSource::VaultPassword,
        }
    }
}

fn kind_of(source: UnlockSource) -> v2::UnlockKind {
    match source {
        UnlockSource::LoginPassword => v2::UnlockKind::LoginPassword,
        UnlockSource::VaultPassword => v2::UnlockKind::VaultPassword,
    }
}

impl From<KeysetMaterialError> for KeysetError {
    fn from(err: KeysetMaterialError) -> Self {
        match err {
            KeysetMaterialError::WrongUnlockSource { stored, given } => {
                Self::WrongUnlockSource { stored, given }
            }
            KeysetMaterialError::Key(err) => Self::Key(err),
            KeysetMaterialError::Seal(err) => Self::Seal(err),
        }
    }
}

/// The hub write of sealed keyset material.
fn put_request(expected_version: u64, material: KeysetMaterial) -> v2::PutKeysetRequest {
    v2::PutKeysetRequest {
        expected_version,
        kdf: material.kdf,
        salt: material.salt,
        wrapped_account_key: material.wrapped_account_key,
        recovery_wrapped_account_key: material.recovery_wrapped_account_key,
        unlock_kind: kind_of(material.unlock_source).into(),
    }
}

/// The open keys of an account.
#[derive(Debug)]
pub struct Keyset {
    account_id: String,
    version: u64,
    account_key: AccountKey,
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

    /// Opens the envelope of one of the account's collections, sealed by its account key.
    pub fn open_collection_key(
        &self,
        collection_id: &str,
        sealed: &[u8],
    ) -> Result<CollectionKey, OpenError> {
        CollectionKey::open(&self.account_key, collection_id, sealed)
    }

    /// Seals a collection key this account created, for `CreateCollection`.
    pub fn seal_collection_key(
        &self,
        key: &CollectionKey,
        collection_id: &str,
    ) -> Result<Vec<u8>, SealError> {
        key.seal_for(&self.account_key, collection_id)
    }

    /// A first keyset: a fresh account key and recovery key, sealed for the hub.
    fn build(
        account_id: &str,
        unlock: &UnlockKey,
        kdf: &UnlockKdf,
    ) -> Result<(NewKeyset, v2::PutKeysetRequest), KeysetError> {
        let created = create_keyset(account_id, unlock, kdf)?;
        let request = put_request(0, created.material);
        let keyset = Keyset {
            account_id: account_id.to_owned(),
            version: 0,
            account_key: created.account_key,
        };
        Ok((
            NewKeyset {
                keyset,
                recovery: created.recovery,
            },
            request,
        ))
    }

    fn request(
        expected_version: u64,
        account_id: &str,
        account_key: &AccountKey,
        unlock: &UnlockKey,
        kdf: &UnlockKdf,
        recovery: &RecoveryKey,
    ) -> Result<v2::PutKeysetRequest, KeysetError> {
        let material = seal_keyset(account_id, account_key, unlock, kdf, recovery)?;
        Ok(put_request(expected_version, material))
    }

    fn with_account_key(record: &v2::Keyset, account_id: &str, account_key: AccountKey) -> Self {
        Self {
            account_id: account_id.to_owned(),
            version: record.version,
            account_key,
        }
    }

    /// Opens a keyset with the unlock key derived from the password. The key must come from
    /// the source the keyset records ([`UnlockMethod::of`]); another source is
    /// [`KeysetError::WrongUnlockSource`], not a wrong password.
    pub fn open(
        record: &v2::Keyset,
        account_id: &str,
        unlock: &UnlockKey,
    ) -> Result<Self, KeysetError> {
        let method = UnlockMethod::of(record)?;
        if method.source() != unlock.source() {
            return Err(KeysetError::WrongUnlockSource {
                stored: method.source(),
                given: unlock.source(),
            });
        }
        let account_key = AccountKey::open(unlock, account_id, &record.wrapped_account_key)
            .map_err(|err| match err {
                OpenError::Rejected => KeysetError::WrongUnlockKey,
                OpenError::Malformed => KeysetError::Damaged(err),
            })?;
        Ok(Self::with_account_key(record, account_id, account_key))
    }

    /// Opens a keyset with the recovery key.
    pub fn recover(
        record: &v2::Keyset,
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
        Ok(Self::with_account_key(record, account_id, account_key))
    }
}

impl HubClient {
    /// The account's keyset record as the hub stores it; `None` before the first device
    /// created it.
    pub async fn keyset_record(&self) -> Result<Option<v2::Keyset>, ClientError> {
        match self.vault().get_keyset(v2::Empty {}).await {
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

    /// How the unlock key of the account's keyset is derived; `None` before the first device
    /// created it. Read it before asking the user for a password.
    pub async fn unlock_method(&self) -> Result<Option<UnlockMethod>, KeysetError> {
        match self.keyset_record().await? {
            Some(record) => UnlockMethod::of(&record).map(Some),
            None => Ok(None),
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
            .vault()
            .put_keyset(request)
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
            unlock,
            kdf,
            recovery,
        )?;
        let stored = self
            .vault()
            .put_keyset(request)
            .await
            .map_err(ClientError::from)?
            .into_inner();
        keyset.version = stored.version;
        Ok(keyset)
    }
}

#[cfg(test)]
mod tests {
    use nocterm_keys::{KdfParams, LoginSecrets};

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
    fn stored(request: &v2::PutKeysetRequest, version: u64) -> v2::Keyset {
        v2::Keyset {
            version,
            kdf: request.kdf.clone(),
            salt: request.salt.clone(),
            wrapped_account_key: request.wrapped_account_key.clone(),
            updated_at_ms: 0,
            recovery_wrapped_account_key: request.recovery_wrapped_account_key.clone(),
            unlock_kind: request.unlock_kind,
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
    fn the_keyset_records_which_password_derives_the_unlock_key() {
        let (_, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        assert_eq!(request.unlock_kind, v2::UnlockKind::VaultPassword as i32);
        assert!(matches!(
            UnlockMethod::of(&stored(&request, 1)),
            Ok(UnlockMethod::VaultPassword(found)) if found == kdf()
        ));

        let login = LoginSecrets::derive("correct horse battery", "hub", "alice").unwrap();
        let (_, request) = Keyset::build("acc-1", login.unlock(), login.kdf()).unwrap();
        assert_eq!(request.unlock_kind, v2::UnlockKind::LoginPassword as i32);
        assert_eq!(
            UnlockMethod::of(&stored(&request, 1)).unwrap(),
            UnlockMethod::LoginPassword
        );
    }

    #[test]
    fn a_key_from_the_other_password_is_told_apart_from_a_wrong_password() {
        let login = LoginSecrets::derive("correct horse battery", "hub", "alice").unwrap();
        let (_, request) = Keyset::build("acc-1", login.unlock(), login.kdf()).unwrap();
        let record = stored(&request, 1);

        // An account made with the login password, later signing in through SSO: the client
        // asks for a vault password and gets a key the keyset was never wrapped with.
        let err = Keyset::open(&record, "acc-1", &unlock()).unwrap_err();
        assert!(matches!(
            err,
            KeysetError::WrongUnlockSource {
                stored: UnlockSource::LoginPassword,
                given: UnlockSource::VaultPassword,
            }
        ));
        assert!(Keyset::open(&record, "acc-1", login.unlock()).is_ok());

        let (_, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        let err = Keyset::open(&stored(&request, 1), "acc-1", login.unlock()).unwrap_err();
        assert!(matches!(
            err,
            KeysetError::WrongUnlockSource {
                stored: UnlockSource::VaultPassword,
                given: UnlockSource::LoginPassword,
            }
        ));
    }

    #[test]
    fn a_keyset_must_be_written_with_the_derivation_of_its_unlock_key() {
        let login = LoginSecrets::derive("correct horse battery", "hub", "alice").unwrap();
        let err = Keyset::build("acc-1", login.unlock(), &kdf()).unwrap_err();
        assert!(matches!(err, KeysetError::WrongUnlockSource { .. }));
    }

    #[test]
    fn a_keyset_without_or_with_an_unknown_unlock_kind_is_not_guessed() {
        let (_, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        let mut record = stored(&request, 1);
        record.unlock_kind = v2::UnlockKind::Unspecified.into();
        assert!(matches!(
            UnlockMethod::of(&record),
            Err(KeysetError::Incomplete)
        ));
        record.unlock_kind = 99;
        assert!(matches!(
            UnlockMethod::of(&record),
            Err(KeysetError::UnsupportedUnlock { kind: 99 })
        ));
    }

    #[test]
    fn stored_vault_parameters_are_checked_when_the_method_is_read() {
        let (_, request) = Keyset::build("acc-1", &unlock(), &kdf()).unwrap();
        let mut record = stored(&request, 1);
        record.kdf = "argon2id;m=4294967295;t=4294967295;p=4".into();
        assert!(matches!(
            UnlockMethod::of(&record),
            Err(KeysetError::Kdf(KdfParseError::TooStrong))
        ));
    }
}
