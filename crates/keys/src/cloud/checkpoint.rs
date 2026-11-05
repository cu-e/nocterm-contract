//! The key a device seals its verified chat checkpoints with (`nocterm-cloud-device`).
//!
//! A checkpoint is device-local state: the position a chat was verified to and the transcript
//! reduced from it. It is derived from the account key and the checkpoint's own context
//! (HKDF-SHA256, salt SHA-256(context), info `nocterm-cloud-device-checkpoint/v1`) and sealed with
//! purpose 21, so a checkpoint moved to another chat, account or hub does not open, and a store
//! that only holds ciphertext (IndexedDB, a file) learns nothing from it.
use crate::{AccountKey, KeyError, OpenError, SealError, seal};
use core::fmt;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The largest checkpoint plaintext this key seals or opens.
pub const MAX_CHECKPOINT_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;
const INFO: &[u8] = b"nocterm-cloud-device-checkpoint/v1";
const OVERHEAD: usize = 2 + 24 + 16;

/// One chat's checkpoint key; it never leaves the device and is never stored.
pub struct CheckpointKey {
    key: Zeroizing<[u8; 32]>,
    context: String,
}
impl CheckpointKey {
    /// Derives the key of `context` (the canonical bytes that name hub, account and chat
    /// generation) from the account key.
    pub fn derive(account: &AccountKey, context: &[u8]) -> Result<Self, CheckpointKeyError> {
        if context.is_empty() || context.len() > 4096 {
            return Err(CheckpointKeyError::Context);
        }
        let salt = Sha256::digest(context);
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&salt), &account.0)
            .expand(INFO, key.as_mut())
            .map_err(KeyError::Expand)?;
        Ok(Self {
            key,
            context: hex::encode(context),
        })
    }
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CheckpointKeyError> {
        if plaintext.is_empty() || plaintext.len() > MAX_CHECKPOINT_PLAINTEXT_BYTES {
            return Err(CheckpointKeyError::Bounds);
        }
        Ok(seal::seal(
            &self.key,
            seal::Purpose::CloudDeviceCheckpoint,
            &[&self.context],
            plaintext,
        )?)
    }
    pub fn open(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CheckpointKeyError> {
        if sealed.len() <= OVERHEAD || sealed.len() > MAX_CHECKPOINT_PLAINTEXT_BYTES + OVERHEAD {
            return Err(CheckpointKeyError::Bounds);
        }
        Ok(seal::open(
            &self.key,
            seal::Purpose::CloudDeviceCheckpoint,
            &[&self.context],
            sealed,
        )?)
    }
}
impl fmt::Debug for CheckpointKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckpointKey(…)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointKeyError {
    #[error("the checkpoint context is empty or too long")]
    Context,
    #[error("the checkpoint is empty or exceeds its bound")]
    Bounds,
    #[error("the checkpoint key could not be derived")]
    Key(#[from] KeyError),
    #[error("the checkpoint could not be sealed")]
    Seal(#[from] SealError),
    #[error("the checkpoint does not open under this account and context")]
    Open(#[from] OpenError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
    use super::*;

    #[test]
    fn a_checkpoint_opens_only_under_its_account_and_context() {
        let account = AccountKey::generate().unwrap();
        let key = CheckpointKey::derive(&account, b"chat-a").unwrap();
        let sealed = key.seal(b"verified state").unwrap();
        assert_eq!(key.open(&sealed).unwrap().as_slice(), b"verified state");
        let moved = CheckpointKey::derive(&account, b"chat-b").unwrap();
        assert!(matches!(
            moved.open(&sealed),
            Err(CheckpointKeyError::Open(OpenError::Rejected))
        ));
        let other = CheckpointKey::derive(&AccountKey::generate().unwrap(), b"chat-a").unwrap();
        assert!(matches!(
            other.open(&sealed),
            Err(CheckpointKeyError::Open(_))
        ));
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(key.open(&altered).is_err());
    }

    #[test]
    fn empty_or_oversized_inputs_are_refused() {
        let account = AccountKey::generate().unwrap();
        assert!(matches!(
            CheckpointKey::derive(&account, b""),
            Err(CheckpointKeyError::Context)
        ));
        let key = CheckpointKey::derive(&account, b"c").unwrap();
        assert!(matches!(key.seal(b""), Err(CheckpointKeyError::Bounds)));
        assert!(matches!(
            key.open(&[1; 10]),
            Err(CheckpointKeyError::Bounds)
        ));
    }
}
