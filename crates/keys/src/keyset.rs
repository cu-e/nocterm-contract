//! A first account keyset: fresh keys sealed into the values the hub stores
//! (`PutAccountKeyset`). Native clients (`nocterm-hub-client`) and the web panel
//! (`nocterm-keys-wasm`) build it with the same function, so a keyset made in a browser opens
//! on a desktop and the reverse.

use crate::{
    AccountKey, AccountKeyPair, KeyError, PublicKey, RecoveryKey, SealError, UnlockKdf, UnlockKey,
    UnlockSource,
};

/// The sealed and public values of a keyset, as the hub stores them. Nothing here opens
/// without the unlock key or the recovery key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetMaterial {
    /// Public KDF description (`argon2id;m=…;t=…;p=…`).
    pub kdf: String,
    /// The KDF salt.
    pub salt: Vec<u8>,
    /// The account key sealed by the unlock key.
    pub wrapped_account_key: Vec<u8>,
    /// The account's X25519 public key, published for grants.
    pub public_key: PublicKey,
    /// The matching private key, sealed by the account key.
    pub sealed_private_key: Vec<u8>,
    /// The account key sealed by the recovery key.
    pub recovery_wrapped_account_key: Vec<u8>,
    /// Which password the unlock key comes from (the keyset's `unlock_kind`).
    pub unlock_source: UnlockSource,
}

/// A keyset could not be built.
#[derive(Debug, thiserror::Error)]
pub enum KeysetMaterialError {
    /// The unlock key comes from another password than the derivation describes.
    #[error("the derivation is for the {stored:?} but the unlock key comes from the {given:?}")]
    WrongUnlockSource {
        /// The source the derivation records.
        stored: UnlockSource,
        /// The source of the unlock key.
        given: UnlockSource,
    },
    /// No randomness for a new key.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A key could not be sealed.
    #[error(transparent)]
    Seal(#[from] SealError),
}

/// A keyset created now: its open keys, the recovery key to show once, and the material to
/// store on the hub.
#[derive(Debug)]
pub struct CreatedKeyset {
    /// The key that wraps the account's collection keys.
    pub account_key: AccountKey,
    /// The account's X25519 pair.
    pub pair: AccountKeyPair,
    /// Shown to the user once and stored nowhere.
    pub recovery: RecoveryKey,
    /// What the hub stores.
    pub material: KeysetMaterial,
}

/// Seals existing keys of `account_id` under `unlock` (derived as `kdf` describes) and
/// `recovery`. Used for a first keyset and when the recovery key resets the password.
pub fn seal_keyset(
    account_id: &str,
    account_key: &AccountKey,
    pair: &AccountKeyPair,
    unlock: &UnlockKey,
    kdf: &UnlockKdf,
    recovery: &RecoveryKey,
) -> Result<KeysetMaterial, KeysetMaterialError> {
    if unlock.source() != kdf.source() {
        return Err(KeysetMaterialError::WrongUnlockSource {
            stored: kdf.source(),
            given: unlock.source(),
        });
    }
    Ok(KeysetMaterial {
        kdf: kdf.description(),
        salt: kdf.salt().to_vec(),
        wrapped_account_key: account_key.seal(unlock, account_id)?,
        public_key: pair.public_key(),
        sealed_private_key: pair.seal(account_key, account_id)?,
        recovery_wrapped_account_key: recovery.wrap(account_key, account_id)?,
        unlock_source: unlock.source(),
    })
}

/// A first keyset of `account_id`: a fresh account key, key pair and recovery key, sealed
/// under `unlock` (derived as `kdf` describes).
pub fn create_keyset(
    account_id: &str,
    unlock: &UnlockKey,
    kdf: &UnlockKdf,
) -> Result<CreatedKeyset, KeysetMaterialError> {
    let account_key = AccountKey::generate()?;
    let pair = AccountKeyPair::generate()?;
    let recovery = RecoveryKey::generate()?;
    let material = seal_keyset(account_id, &account_key, &pair, unlock, kdf, &recovery)?;
    Ok(CreatedKeyset {
        account_key,
        pair,
        recovery,
        material,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoginSecrets;

    #[test]
    fn a_created_keyset_opens_with_the_password_and_with_the_recovery_key() {
        let account_id = "acc-1";
        let secrets = LoginSecrets::derive("correct horse battery", "hub", "ann").unwrap();
        let created = create_keyset(account_id, secrets.unlock(), secrets.kdf()).unwrap();
        let material = &created.material;
        assert_eq!(material.unlock_source, UnlockSource::LoginPassword);
        assert_eq!(material.kdf, secrets.kdf().description());
        assert_eq!(material.public_key, created.pair.public_key());

        let account =
            AccountKey::open(secrets.unlock(), account_id, &material.wrapped_account_key).unwrap();
        let pair = AccountKeyPair::open(
            &account,
            account_id,
            &material.sealed_private_key,
            &material.public_key,
        )
        .unwrap();
        assert_eq!(pair.public_key(), material.public_key);
        let recovered = created
            .recovery
            .unwrap(account_id, &material.recovery_wrapped_account_key)
            .unwrap();
        AccountKeyPair::open(
            &recovered,
            account_id,
            &material.sealed_private_key,
            &material.public_key,
        )
        .unwrap();
        assert!(
            AccountKey::open(secrets.unlock(), "acc-2", &material.wrapped_account_key).is_err()
        );
    }

    #[test]
    fn an_unlock_key_from_the_other_password_is_refused() {
        let secrets = LoginSecrets::derive("correct horse battery", "hub", "ann").unwrap();
        let vault = UnlockKdf::random().unwrap();
        let err = create_keyset("acc-1", secrets.unlock(), &vault).unwrap_err();
        assert!(matches!(
            err,
            KeysetMaterialError::WrongUnlockSource {
                stored: UnlockSource::VaultPassword,
                given: UnlockSource::LoginPassword,
            }
        ));
    }
}
