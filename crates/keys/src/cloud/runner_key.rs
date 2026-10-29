//! Runner-owned encryption identity, independent of account root material.
use crate::{KeyError, PublicKey, random_bytes};
use core::fmt;
use x25519_dalek::{SharedSecret, StaticSecret};
use zeroize::Zeroizing;

/// An X25519 recipient installed on a user-trusted runner.
///
/// The runner stores this identity in its private identity file; it never needs
/// the account's private key or root key. Provider credentials use the separate
/// `RunnerBootKey`, whose API deliberately cannot export or restore its seed.
pub struct RunnerEncryptionKey {
    secret: StaticSecret,
}

impl RunnerEncryptionKey {
    /// Generates a fresh identity, refusing an operating-system random failure.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self::from_seed(&Zeroizing::new(random_bytes::<32>()?)))
    }

    /// Restores this runner's identity from its private, purpose-specific seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(*seed),
        }
    }

    /// Returns a zeroizing seed for the runner's private identity storage only.
    /// Never put this value in a hub record, settings DTO, tool or provider call.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Public recipient key pinned in the account's sealed runner descriptor.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_array(x25519_dalek::PublicKey::from(&self.secret).to_bytes())
    }

    pub(super) fn agree(&self, peer: &[u8; 32]) -> SharedSecret {
        self.secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*peer))
    }
}

impl fmt::Debug for RunnerEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerEncryptionKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_runner_identity_restores_without_account_keys() -> Result<(), KeyError> {
        let original = RunnerEncryptionKey::generate()?;
        let restored = RunnerEncryptionKey::from_seed(&original.seed());
        assert_eq!(original.public_key(), restored.public_key());
        let peer = RunnerEncryptionKey::generate()?;
        assert_eq!(
            original.agree(peer.public_key().as_bytes()).as_bytes(),
            restored.agree(peer.public_key().as_bytes()).as_bytes()
        );
        Ok(())
    }

    #[test]
    fn runner_debug_omits_private_seed() {
        let key = RunnerEncryptionKey::from_seed(&[7; 32]);
        let debug = format!("{key:?}");
        assert!(!debug.contains("[7, 7, 7"));
        assert!(!debug.contains(&hex::encode([7; 32])));
        assert!(debug.contains("public_key"));
    }

    #[test]
    fn boot_identity_cannot_be_recovered_from_a_new_boot() -> Result<(), KeyError> {
        let old = RunnerEncryptionKey::generate()?;
        let peer = RunnerEncryptionKey::generate()?;
        let old_public = old.public_key();
        let old_shared = Zeroizing::new(*peer.agree(old_public.as_bytes()).as_bytes());
        drop(old);
        let next = RunnerEncryptionKey::generate()?;
        assert_ne!(old_public, next.public_key());
        assert_ne!(
            &*old_shared,
            next.agree(peer.public_key().as_bytes()).as_bytes()
        );
        Ok(())
    }
}
