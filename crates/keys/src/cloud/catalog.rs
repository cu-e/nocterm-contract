//! A native metadata key derived from the runner's own identity, never an account root.
use super::RunnerEncryptionKey;
use crate::{KeyError, OpenError, SealError, seal};
use core::fmt;
use hkdf::Hkdf;
use nocterm_hub_model::cloud::account_catalog::{
    AccountCatalogCoordinate, AccountCatalogError, MAX_ACCOUNT_CATALOG_BYTES,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct NativeCatalogKey {
    key: Zeroizing<[u8; 32]>,
    context: String,
}
impl NativeCatalogKey {
    /// Restore the exact purpose-specific runner identity backup to reopen a catalog.
    /// A valid old catalog still requires a trusted high-water position for anti-rollback.
    pub fn for_runner(
        runner: &RunnerEncryptionKey,
        coordinate: &AccountCatalogCoordinate,
    ) -> Result<Self, NativeCatalogError> {
        let mut context = coordinate.canonical_bytes()?;
        context.extend_from_slice(runner.public_key().as_bytes());
        let salt = Sha256::digest(&context);
        let seed = runner.seed();
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&salt), seed.as_ref())
            .expand(b"nocterm-cloud-native-account-catalog-key-v1", key.as_mut())
            .map_err(KeyError::Expand)?;
        Ok(Self {
            key,
            context: hex::encode(context),
        })
    }
    pub fn seal_catalog(&self, plaintext: &[u8]) -> Result<Vec<u8>, NativeCatalogError> {
        if plaintext.is_empty() || plaintext.len() > MAX_ACCOUNT_CATALOG_BYTES {
            return Err(NativeCatalogError::Bounds);
        }
        Ok(seal::seal(
            &self.key,
            seal::Purpose::CloudAccountCatalog,
            &[&self.context],
            plaintext,
        )?)
    }
    pub fn open_catalog(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, NativeCatalogError> {
        if ciphertext.len() <= 42 || ciphertext.len() > MAX_ACCOUNT_CATALOG_BYTES + 42 {
            return Err(NativeCatalogError::Bounds);
        }
        let plaintext = seal::open(
            &self.key,
            seal::Purpose::CloudAccountCatalog,
            &[&self.context],
            ciphertext,
        )?;
        if plaintext.is_empty() || plaintext.len() > MAX_ACCOUNT_CATALOG_BYTES {
            return Err(NativeCatalogError::Bounds);
        }
        Ok(plaintext)
    }
}
impl fmt::Debug for NativeCatalogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeCatalogKey(…)")
    }
}
#[derive(Debug, thiserror::Error)]
pub enum NativeCatalogError {
    #[error("native account catalog exceeds its bounds")]
    Bounds,
    #[error("native account catalog context is invalid")]
    Context(#[from] AccountCatalogError),
    #[error("native account catalog key derivation failed")]
    Key(#[from] KeyError),
    #[error("native account catalog encryption failed")]
    Seal(#[from] SealError),
    #[error("native account catalog authentication failed")]
    Open(#[from] OpenError),
}
#[cfg(test)]
mod tests;
