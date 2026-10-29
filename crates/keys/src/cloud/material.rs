//! Per-chat secrets and purpose-bound journal encryption, without storage or replay.
mod grant;
mod record;

pub use grant::{open_chat_key_from_account, seal_chat_key_to_runner};
pub use record::{
    CloudRecordError, OpenedRecord, open_event, open_snapshot, seal_event, seal_snapshot,
};

use crate::{AccountKey, KeyError, OpenError, SealError, random_bytes, seal};
use core::fmt;
use nocterm_hub_model::cloud::{ChatCoordinate, JournalCoordinate, MaterialError};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Includes framing and authentication tag, matching the bounded native slot port.
pub const MAX_JOURNAL_CIPHERTEXT_BYTES: usize = 32 * 1024 * 1024 + 64 * 1024;
const SEAL_OVERHEAD: usize = 2 + 24 + 16;

/// A single chat's random content key, independent of every other chat and account root.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChatKey([u8; 32]);

impl ChatKey {
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self(random_bytes::<32>()?))
    }

    /// Wraps only this key, under the account root already opened by normal sign-in.
    pub fn seal_for_account(
        &self,
        account: &AccountKey,
        chat: &ChatCoordinate,
    ) -> Result<Vec<u8>, CloudMaterialError> {
        let context = hex::encode(chat.canonical_bytes()?);
        Ok(seal::seal(
            &account.0,
            seal::Purpose::CloudChatAccountKey,
            &[&context],
            &self.0,
        )?)
    }

    pub fn open_for_account(
        account: &AccountKey,
        expected: &ChatCoordinate,
        ciphertext: &[u8],
    ) -> Result<Self, CloudMaterialError> {
        require_key_envelope(ciphertext, SEAL_OVERHEAD + 32)?;
        let context = hex::encode(expected.canonical_bytes()?);
        let plaintext = seal::open(
            &account.0,
            seal::Purpose::CloudChatAccountKey,
            &[&context],
            ciphertext,
        )?;
        Ok(Self::from_plaintext(&plaintext)?)
    }

    /// Encrypts one native codec value. Never use this as a network event envelope.
    /// The caller owns transactional durability, freshness and writer authorization.
    pub fn seal_journal(
        &self,
        slot: &JournalCoordinate,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CloudMaterialError> {
        if plaintext.len() > MAX_JOURNAL_CIPHERTEXT_BYTES - SEAL_OVERHEAD {
            return Err(CloudMaterialError::Capacity);
        }
        let context = hex::encode(slot.canonical_bytes()?);
        Ok(seal::seal(
            &self.0,
            seal::Purpose::CloudJournal,
            &[&context],
            plaintext,
        )?)
    }

    pub fn open_journal(
        &self,
        expected: &JournalCoordinate,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CloudMaterialError> {
        if ciphertext.len() > MAX_JOURNAL_CIPHERTEXT_BYTES {
            return Err(CloudMaterialError::Capacity);
        }
        let context = hex::encode(expected.canonical_bytes()?);
        Ok(seal::open(
            &self.0,
            seal::Purpose::CloudJournal,
            &[&context],
            ciphertext,
        )?)
    }

    fn from_plaintext(bytes: &[u8]) -> Result<Self, OpenError> {
        bytes.try_into().map(Self).map_err(|_| OpenError::Malformed)
    }
}

impl fmt::Debug for ChatKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChatKey(…)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CloudMaterialError {
    #[error("Cloud material coordinates are invalid")]
    Context(#[from] MaterialError),
    #[error("Cloud material exceeds its byte limit")]
    Capacity,
    #[error("Cloud material envelope has an invalid length")]
    Length,
    #[error("Cloud material sealing failed")]
    Seal(#[from] SealError),
    #[error("Cloud material authentication failed")]
    Open(#[from] OpenError),
    #[error("Cloud material key generation or derivation failed")]
    Key(#[from] KeyError),
}

fn require_key_envelope(bytes: &[u8], exact_length: usize) -> Result<(), CloudMaterialError> {
    if bytes.len() == exact_length {
        Ok(())
    } else {
        Err(CloudMaterialError::Length)
    }
}

#[cfg(test)]
mod tests;
