//! Purpose-separated key derivation for account-authenticated boxes.
use crate::KeyError;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zeroize::Zeroizing;

/// Public coordinates in the exact HKDF salt order. Callers reject noncontributory DH.
pub(crate) struct AuthenticatedBoxKeys<'a> {
    ephemeral: &'a [u8; 32],
    sender: &'a [u8; 32],
    recipient: &'a [u8; 32],
}
impl<'a> AuthenticatedBoxKeys<'a> {
    pub(crate) fn new(
        ephemeral: &'a [u8; 32],
        sender: &'a [u8; 32],
        recipient: &'a [u8; 32],
    ) -> Self {
        Self {
            ephemeral,
            sender,
            recipient,
        }
    }
    pub(crate) fn key(
        &self,
        dh_ephemeral: &SharedSecret,
        dh_sender: &SharedSecret,
        purpose_info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let mut salt = [0u8; 96];
        salt[..32].copy_from_slice(self.ephemeral);
        salt[32..64].copy_from_slice(self.sender);
        salt[64..].copy_from_slice(self.recipient);
        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[..32].copy_from_slice(dh_ephemeral.as_bytes());
        ikm[32..].copy_from_slice(dh_sender.as_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&salt), ikm.as_ref())
            .expand(purpose_info, key.as_mut())
            .map_err(KeyError::Expand)?;
        Ok(key)
    }
}
