use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::{KeyError, random_bytes};

/// The Ed25519 key a device uses to prove possession of its tokens.
pub struct DeviceKey {
    signing: SigningKey,
}

impl DeviceKey {
    /// A fresh random key.
    pub fn generate() -> Result<Self, KeyError> {
        let seed = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self::from_seed(&seed))
    }

    /// Restores a key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte seed, for storage in the device's private key file.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// The 32-byte public key registered with the hub.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Signs `message` (one of the canonical messages of `nocterm-hub-model::pop`).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignatureError, verify_signature};

    #[test]
    fn signatures_verify_only_for_their_message() {
        let key = DeviceKey::generate().unwrap();
        let signature = key.sign(b"hello");
        assert_eq!(
            verify_signature(&key.public_key(), b"hello", &signature),
            Ok(())
        );
        assert_eq!(
            verify_signature(&key.public_key(), b"hellO", &signature),
            Err(SignatureError::Invalid)
        );
        assert_eq!(
            verify_signature(&key.public_key()[..31], b"hello", &signature),
            Err(SignatureError::MalformedKey)
        );
    }

    #[test]
    fn a_key_restores_from_its_seed() {
        let key = DeviceKey::generate().unwrap();
        let restored = DeviceKey::from_seed(&key.seed());
        assert_eq!(key.public_key(), restored.public_key());
    }

    #[test]
    fn debug_does_not_print_the_seed() {
        let key = DeviceKey::from_seed(&[7; 32]);
        let debug = format!("{key:?}");
        assert!(!debug.contains("[7, 7, 7"));
    }
}
