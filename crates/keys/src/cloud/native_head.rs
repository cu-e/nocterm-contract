//! Bounded per-chat metadata protected independently of a ChatKey. Catalog
//! membership, atomic roots, storage and anti-rollback marks remain native-owned.
use super::RunnerEncryptionKey;
use crate::{KeyError, OpenError, SealError, seal};
use core::fmt;
use hkdf::Hkdf;
use nocterm_hub_model::cloud::native_chat_head::{
    MAX_NATIVE_CHAT_HEAD_BYTES, MAX_NATIVE_CHAT_HEAD_CIPHERTEXT_BYTES, NativeChatHeadContextError,
    NativeChatHeadCoordinate,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct NativeChatHeadKey {
    key: Zeroizing<[u8; 32]>,
    context: String,
}
impl NativeChatHeadKey {
    /// Requires the real retained runner identity and independently configured
    /// source context. A value constructor establishes neither trusted pins nor
    /// the current metadata revision; the native owner must verify both.
    pub fn for_runner(
        runner: &RunnerEncryptionKey,
        coordinate: &NativeChatHeadCoordinate,
    ) -> Result<Self, NativeChatHeadError> {
        let mut context = coordinate.canonical_bytes()?;
        context.extend_from_slice(runner.public_key().as_bytes());
        let salt = Sha256::digest(&context);
        let seed = runner.seed();
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&salt), seed.as_ref())
            .expand(b"nocterm-cloud-native-chat-head-key-v1", key.as_mut())
            .map_err(KeyError::Expand)?;
        Ok(Self {
            key,
            context: hex::encode(context),
        })
    }
    pub fn seal_head(&self, plaintext: &[u8]) -> Result<Vec<u8>, NativeChatHeadError> {
        if plaintext.is_empty() || plaintext.len() > MAX_NATIVE_CHAT_HEAD_BYTES {
            return Err(NativeChatHeadError::Bounds);
        }
        Ok(seal::seal(
            &self.key,
            seal::Purpose::CloudNativeChatHead,
            &[&self.context],
            plaintext,
        )?)
    }
    pub fn open_head(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, NativeChatHeadError> {
        if ciphertext.len() <= 42 || ciphertext.len() > MAX_NATIVE_CHAT_HEAD_CIPHERTEXT_BYTES {
            return Err(NativeChatHeadError::Bounds);
        }
        let plaintext = seal::open(
            &self.key,
            seal::Purpose::CloudNativeChatHead,
            &[&self.context],
            ciphertext,
        )?;
        if plaintext.is_empty() || plaintext.len() > MAX_NATIVE_CHAT_HEAD_BYTES {
            return Err(NativeChatHeadError::Bounds);
        }
        Ok(plaintext)
    }
}
impl fmt::Debug for NativeChatHeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeChatHeadKey(…)")
    }
}
#[derive(Debug, thiserror::Error)]
pub enum NativeChatHeadError {
    #[error("native chat-head exceeds its bounds")]
    Bounds,
    #[error("native chat-head context is invalid")]
    Context(#[from] NativeChatHeadContextError),
    #[error("native chat-head key derivation failed")]
    Key(#[from] KeyError),
    #[error("native chat-head encryption failed")]
    Seal(#[from] SealError),
    #[error("native chat-head authentication failed")]
    Open(#[from] OpenError),
}
#[cfg(test)]
mod tests;
