//! Canonical messages signed by device and node keys (proof of possession).
//!
//! Every message starts with a purpose tag and encodes its fields with a length prefix, so a
//! signature made for one purpose or one hub never verifies for another. Tokens are never
//! signed directly: only their SHA-256 digest enters the message.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Largest accepted difference between the signer's clock and the verifier's clock.
pub const MAX_CLOCK_SKEW_MS: i64 = 60_000;

/// Hex SHA-256 digest of a bearer token or grant, as used inside signed messages.
pub fn token_digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Whether a signed timestamp is close enough to the verifier's clock.
pub fn is_fresh(signed_at_ms: i64, now_ms: i64) -> bool {
    (now_ms - signed_at_ms).abs() <= MAX_CLOCK_SKEW_MS
}

struct Message(Vec<u8>);

impl Message {
    fn new(purpose: &str) -> Self {
        let mut message = Self(Vec::with_capacity(160));
        message.field(b"nocterm/v1");
        message.field(purpose.as_bytes());
        message
    }

    fn field(&mut self, bytes: &[u8]) -> &mut Self {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    fn text(&mut self, text: &str) -> &mut Self {
        self.field(text.as_bytes())
    }

    fn int(&mut self, value: i64) -> &mut Self {
        self.field(&value.to_be_bytes())
    }

    fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Signed by a device when it completes a login and registers (or re-binds) itself.
///
/// `grant` is the login ticket or authorization code being redeemed; `signing_key` is the
/// device's public key, so the signature proves possession of the matching private key.
pub fn login_message(hub_id: &str, grant: &str, signing_key: &[u8], signed_at_ms: i64) -> Vec<u8> {
    Message::new("login")
        .text(hub_id)
        .text(&token_digest(grant))
        .field(signing_key)
        .int(signed_at_ms)
        .finish()
}

/// Signed by a device when it exchanges a refresh token.
pub fn refresh_message(hub_id: &str, refresh_token: &str, signed_at_ms: i64) -> Vec<u8> {
    Message::new("refresh")
        .text(hub_id)
        .text(&token_digest(refresh_token))
        .int(signed_at_ms)
        .finish()
}

/// Signed by a device on every authenticated request (DPoP equivalent for gRPC).
pub fn request_message(
    hub_id: &str,
    path: &str,
    access_token: &str,
    nonce: &str,
    signed_at_ms: i64,
) -> Vec<u8> {
    Message::new("request")
        .text(hub_id)
        .text(path)
        .text(&token_digest(access_token))
        .text(nonce)
        .int(signed_at_ms)
        .finish()
}

/// Signed by a node when it connects to the hub.
pub fn node_message(hub_id: &str, node_id: &str, nonce: &str, signed_at_ms: i64) -> Vec<u8> {
    Message::new("node")
        .text(hub_id)
        .text(node_id)
        .text(nonce)
        .int(signed_at_ms)
        .finish()
}

/// Signed by a node when it redeems an enrollment token.
pub fn enroll_message(hub_id: &str, enrollment_token: &str, identity_key: &[u8]) -> Vec<u8> {
    Message::new("enroll")
        .text(hub_id)
        .text(&token_digest(enrollment_token))
        .field(identity_key)
        .finish()
}

/// A signature or public key that does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The public key is not 32 bytes or not a valid point.
    #[error("malformed public key")]
    MalformedKey,
    /// The signature is not 64 bytes.
    #[error("malformed signature")]
    MalformedSignature,
    /// The signature does not match the message and key.
    #[error("signature does not verify")]
    Invalid,
}

/// Verifies an Ed25519 signature over one of the canonical messages (strict verification:
/// no malleable or small-order signatures).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
    let key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignatureError::MalformedKey)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| SignatureError::MalformedKey)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureError::MalformedSignature)?;
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| SignatureError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_never_collide() {
        let request = request_message("hub", "/x", "token", "n", 1);
        let refresh = refresh_message("hub", "token", 1);
        assert_ne!(request, refresh);
    }

    #[test]
    fn fields_are_length_prefixed() {
        // Moving a byte between adjacent fields must change the message.
        let a = node_message("hub", "ab", "c", 1);
        let b = node_message("hub", "a", "bc", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn freshness_is_symmetric() {
        assert!(is_fresh(1_000_000, 1_000_000 + MAX_CLOCK_SKEW_MS));
        assert!(is_fresh(1_000_000 + MAX_CLOCK_SKEW_MS, 1_000_000));
        assert!(!is_fresh(1_000_000, 1_000_001 + MAX_CLOCK_SKEW_MS));
    }

    #[test]
    fn digests_hide_tokens() {
        let message = request_message("hub", "/x", "super-secret-token", "n", 1);
        let needle = b"super-secret-token";
        assert!(!message.windows(needle.len()).any(|w| w == needle));
    }
}
