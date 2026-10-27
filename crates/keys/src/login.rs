//! Login secrets: one password yields the value the hub verifies and the key it never sees.
//!
//! ```text
//! salt   = SHA-256("nocterm-login-v1" ‖ u32be(len hub_id) ‖ hub_id ‖ u32be(len username) ‖ username)
//! master = Argon2id(password, salt, KdfParams::MINIMUM)                 // 32 bytes
//! auth   = hex(HKDF-SHA256(ikm = master, info = "nocterm-login-v1/auth"))     // sent to the hub
//! unlock = HKDF-SHA256(ikm = master, info = "nocterm-login-v1/unlock")        // opens the account key
//! ```
//!
//! The hub hashes `auth` as if it were the password, so it can verify a sign-in but cannot
//! derive `unlock` from it: the two outputs of HKDF are independent and `master` never leaves
//! the device. The parameters are fixed by the `login-v1` label; raising them needs a
//! `login-v2` label and a way for the client to learn it before signing in.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{KdfParams, KdfParseError, KeyError, random_bytes};

/// Fewest characters of a password this crate derives keys from.
pub const MIN_PASSWORD_CHARS: usize = 8;

const SALT_LABEL: &[u8] = b"nocterm-login-v1";
const AUTH_INFO: &[u8] = b"nocterm-login-v1/auth";
const UNLOCK_INFO: &[u8] = b"nocterm-login-v1/unlock";
const VAULT_UNLOCK_INFO: &[u8] = b"nocterm-vault-v1/unlock";
const VAULT_SALT_LEN: usize = 16;
const MIN_SALT_LEN: usize = 16;
const MAX_SALT_LEN: usize = 64;

/// A password or user name that cannot be used to derive keys.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// Shorter than [`MIN_PASSWORD_CHARS`] characters.
    #[error("the password must have at least {min} characters")]
    PasswordTooShort {
        /// The shortest accepted length.
        min: usize,
    },
    /// Nothing is left of the user name after trimming.
    #[error("the user name is empty")]
    EmptyUsername,
    /// The key derivation itself failed.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// How an unlock key is derived: public Argon2id parameters and the salt, as stored in the
/// account keyset on the hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockKdf {
    params: KdfParams,
    salt: Vec<u8>,
}

impl UnlockKdf {
    /// Parameters and salt read from a keyset; weak parameters and odd salts are refused, so
    /// a hostile hub cannot downgrade the derivation.
    pub fn new(params: KdfParams, salt: Vec<u8>) -> Result<Self, KdfParseError> {
        let params = params.check()?;
        if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
            return Err(KdfParseError::BadSalt);
        }
        Ok(Self { params, salt })
    }

    /// The description (`argon2id;m=…;t=…;p=…`) and salt of a keyset as the hub sent them.
    pub fn parse(kdf: &str, salt: &[u8]) -> Result<Self, KdfParseError> {
        Self::new(kdf.parse()?, salt.to_vec())
    }

    /// The derivation of a vault password with a fresh random salt (accounts that sign in
    /// through an identity provider and set a password for their vault).
    pub fn random() -> Result<Self, KeyError> {
        Ok(Self {
            params: KdfParams::MINIMUM,
            salt: random_bytes::<VAULT_SALT_LEN>()?.to_vec(),
        })
    }

    /// The salt of `login-v1`: bound to the hub and the (trimmed) user name, so the same
    /// password gives unrelated keys on another hub or for another user.
    pub fn login(hub_id: &str, username: &str) -> Result<Self, LoginError> {
        let username = username.trim();
        if username.is_empty() {
            return Err(LoginError::EmptyUsername);
        }
        let mut hash = Sha256::new();
        hash.update(SALT_LABEL);
        for part in [hub_id, username] {
            let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
            hash.update(len.to_be_bytes());
            hash.update(part.as_bytes());
        }
        Ok(Self {
            params: KdfParams::MINIMUM,
            salt: hash.finalize().to_vec(),
        })
    }

    /// The Argon2id parameters.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// The text form stored in the keyset (`argon2id;m=…;t=…;p=…`).
    pub fn description(&self) -> String {
        self.params.to_string()
    }

    /// The salt.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    fn master(&self, password: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let argon = Params::new(
            self.params.memory_kib,
            self.params.iterations,
            self.params.parallelism,
            Some(32),
        )
        .map_err(KeyError::Argon2)?;
        let mut master = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon)
            .hash_password_into(password.as_bytes(), &self.salt, master.as_mut())
            .map_err(KeyError::Argon2)?;
        Ok(master)
    }
}

fn expand(master: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, master)
        .expand(info, out.as_mut())
        .map_err(KeyError::Expand)?;
    Ok(out)
}

fn check_password(password: &str) -> Result<(), LoginError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(LoginError::PasswordTooShort {
            min: MIN_PASSWORD_CHARS,
        });
    }
    Ok(())
}

/// The key that opens the account key; it exists only while a vault is unlocked.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockKey(pub(crate) [u8; 32]);

impl UnlockKey {
    /// The unlock key of a vault password that is not the account's login password.
    ///
    /// Uses its own HKDF label, so it never equals the key a login password would give.
    pub fn from_vault_password(password: &str, kdf: &UnlockKdf) -> Result<Self, LoginError> {
        check_password(password)?;
        let master = kdf.master(password)?;
        Ok(Self(*expand(&master, VAULT_UNLOCK_INFO)?))
    }
}

impl fmt::Debug for UnlockKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnlockKey(…)")
    }
}

/// What one password derives for one user on one hub.
///
/// `auth` is the only part that leaves the device. `unlock` stays in memory for as long as
/// the account key is needed and is wiped when dropped.
pub struct LoginSecrets {
    auth: Zeroizing<String>,
    unlock: UnlockKey,
    kdf: UnlockKdf,
}

impl LoginSecrets {
    /// Derives the secrets of `username` on the hub `hub_id`.
    ///
    /// Costs 64 MiB and a few hundred milliseconds: call it off the interface thread. The
    /// user name is trimmed and otherwise taken as typed (the hub tells case apart).
    pub fn derive(password: &str, hub_id: &str, username: &str) -> Result<Self, LoginError> {
        check_password(password)?;
        let kdf = UnlockKdf::login(hub_id, username)?;
        let master = kdf.master(password)?;
        let auth = expand(&master, AUTH_INFO)?;
        let unlock = expand(&master, UNLOCK_INFO)?;
        Ok(Self {
            auth: Zeroizing::new(hex::encode(&auth[..])),
            unlock: UnlockKey(*unlock),
            kdf,
        })
    }

    /// The 64 hexadecimal characters sent to the hub where it expects the password.
    pub fn auth(&self) -> &str {
        &self.auth
    }

    /// The key that opens the account key.
    pub fn unlock(&self) -> &UnlockKey {
        &self.unlock
    }

    /// The derivation to store in the keyset of a new account.
    pub fn kdf(&self) -> &UnlockKdf {
        &self.kdf
    }

    /// Drops `auth` and keeps the unlock key.
    pub fn into_unlock(self) -> UnlockKey {
        self.unlock
    }
}

impl fmt::Debug for LoginSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginSecrets(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery";

    fn bytes(text: &str) -> Vec<u8> {
        hex::decode(text).unwrap()
    }

    /// Computed independently (Python: hashlib, OpenSSL Argon2id and HKDF through the
    /// `cryptography` package) so the vectors do not merely echo this implementation.
    #[test]
    fn login_v1_matches_the_fixed_vectors() {
        let secrets = LoginSecrets::derive(PASSWORD, "hub-0001", "alice").unwrap();
        assert_eq!(
            secrets.kdf().salt(),
            bytes("dc58f1ba3606c1a4e66c6c00c00cb904d06a965e90c89c28151bfaa7d9ff977d")
        );
        assert_eq!(
            secrets.auth(),
            "ca8e15a64e5d6c6b9665b80e36865989104ab55e4887bf95d982945fd96a48fb"
        );
        assert_eq!(
            secrets.unlock().0.as_slice(),
            bytes("e2ac0aa789521a48e2fe1b5a2d00c28929a5a9918223686cf4dee7eb81607614")
        );
        assert_eq!(secrets.kdf().params(), KdfParams::MINIMUM);
    }

    #[test]
    fn the_auth_value_is_not_the_unlock_key_nor_the_master() {
        let secrets = LoginSecrets::derive(PASSWORD, "hub-0001", "alice").unwrap();
        let master = "223f027752f75b5426e5326953ac67130799c71901da2a23e0b0cd9338808223";
        assert_eq!(secrets.auth().len(), 64);
        assert_ne!(secrets.auth(), hex::encode(secrets.unlock().0));
        assert_ne!(secrets.auth(), master);
        assert_ne!(hex::encode(secrets.unlock().0), master);
    }

    #[test]
    fn the_user_name_is_trimmed_and_case_sensitive() {
        let plain = LoginSecrets::derive(PASSWORD, "hub-0001", "alice").unwrap();
        let padded = LoginSecrets::derive(PASSWORD, "hub-0001", "  alice\n").unwrap();
        let upper = LoginSecrets::derive(PASSWORD, "hub-0001", "Alice").unwrap();
        assert_eq!(plain.auth(), padded.auth());
        assert_ne!(plain.auth(), upper.auth());
    }

    #[test]
    fn another_hub_gives_unrelated_secrets() {
        let one = LoginSecrets::derive(PASSWORD, "hub-0001", "alice").unwrap();
        let two = LoginSecrets::derive(PASSWORD, "hub-0002", "alice").unwrap();
        assert_ne!(one.auth(), two.auth());
        assert_ne!(one.unlock().0, two.unlock().0);
    }

    #[test]
    fn the_salt_is_unambiguous_across_field_boundaries() {
        let a = UnlockKdf::login("ab", "c").unwrap();
        let b = UnlockKdf::login("a", "bc").unwrap();
        let c = UnlockKdf::login("abc", "").unwrap_err();
        assert_ne!(a.salt(), b.salt());
        assert!(matches!(c, LoginError::EmptyUsername));
    }

    #[test]
    fn short_passwords_are_refused_before_any_derivation() {
        let err = LoginSecrets::derive("seven77", "hub", "alice").unwrap_err();
        assert!(matches!(err, LoginError::PasswordTooShort { min: 8 }));
        // Eight characters, more than eight bytes: counted in characters, like the hub does.
        assert!(LoginSecrets::derive("пароль12", "hub", "alice").is_ok());
        let err = LoginSecrets::derive("   ", "hub", "alice").unwrap_err();
        assert!(matches!(err, LoginError::PasswordTooShort { .. }));
    }

    #[test]
    fn an_empty_user_name_is_refused() {
        let err = LoginSecrets::derive(PASSWORD, "hub", " \t").unwrap_err();
        assert!(matches!(err, LoginError::EmptyUsername));
    }

    #[test]
    fn a_vault_password_has_its_own_label() {
        let salt = (16..32).collect::<Vec<u8>>();
        let kdf = UnlockKdf::new(KdfParams::MINIMUM, salt).unwrap();
        let key = UnlockKey::from_vault_password(PASSWORD, &kdf).unwrap();
        assert_eq!(
            key.0.as_slice(),
            bytes("39e98f2c3915166726cd54d7e67f59fd2c5ddaebddde7dde733f0f195186b946")
        );
        assert!(matches!(
            UnlockKey::from_vault_password("short", &kdf),
            Err(LoginError::PasswordTooShort { .. })
        ));
    }

    #[test]
    fn keysets_with_weak_parameters_or_odd_salts_are_refused() {
        let weak = KdfParams {
            memory_kib: 1024,
            ..KdfParams::MINIMUM
        };
        assert_eq!(
            UnlockKdf::new(weak, vec![0; 16]),
            Err(KdfParseError::TooWeak)
        );
        assert_eq!(
            UnlockKdf::new(KdfParams::MINIMUM, vec![0; 15]),
            Err(KdfParseError::BadSalt)
        );
        assert_eq!(
            UnlockKdf::new(KdfParams::MINIMUM, vec![0; 65]),
            Err(KdfParseError::BadSalt)
        );
        let kdf = UnlockKdf::parse("argon2id;m=65536;t=3;p=4", &[7; 16]).unwrap();
        assert_eq!(kdf.description(), "argon2id;m=65536;t=3;p=4");
        assert!(UnlockKdf::parse("argon2id;m=8;t=1;p=1", &[7; 16]).is_err());
    }

    #[test]
    fn secrets_are_not_printed() {
        let secrets = LoginSecrets::derive(PASSWORD, "hub-0001", "alice").unwrap();
        let debug = format!("{secrets:?} {:?}", secrets.unlock());
        assert!(!debug.contains(secrets.auth()));
        assert!(!debug.contains("e2ac"));
    }

    #[test]
    fn a_fresh_vault_derivation_is_random_and_valid() {
        let a = UnlockKdf::random().unwrap();
        let b = UnlockKdf::random().unwrap();
        assert_ne!(a.salt(), b.salt());
        assert!(UnlockKdf::new(a.params(), a.salt().to_vec()).is_ok());
    }
}
