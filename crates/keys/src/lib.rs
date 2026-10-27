//! Client-side key material of the Nocterm hub.
//!
//! Owns: device signing keys (Ed25519) used for proof of possession; the two-secret key
//! derivation (passphrase + secret key, 2SKD) of the unlock key; the key hierarchy
//! unlock key → account key → collection key; and the sealed formats of keys, names and
//! objects (XChaCha20-Poly1305 with purpose-bound associated data).
//! Does not own: storage of keys on the device, the network, or any user interface.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants:
//! - the hub never receives a key that opens user data: only sealed keys and ciphertext;
//! - every sealed value binds its purpose and owner identifiers as associated data, so a
//!   ciphertext moved to another object, collection or account fails to open;
//! - KDF parameters weaker than [`KdfParams::MINIMUM`] are rejected, so a hostile hub cannot
//!   downgrade them;
//! - secrets are zeroized on drop and never printed by `Debug`.
//!
//! The control plane must never depend on this crate (blindness hygiene, checked by xtask).

mod device;
mod kdf;
mod random;
mod seal;

pub use device::DeviceKey;
pub use kdf::{KdfParams, KdfParseError, SecretKey, SecretKeyParseError, UnlockKey};
pub use nocterm_hub_model::pop::{SignatureError, verify as verify_signature};
pub use random::{random_bytes, random_token};
pub use seal::{AccountKey, CollectionKey, OpenError, SealError};

/// Errors from key derivation and sealing.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The KDF parameters are invalid or too weak.
    #[error(transparent)]
    Kdf(#[from] KdfParseError),
    /// The operating system could not provide randomness.
    #[error("no randomness available")]
    Random(#[source] getrandom::Error),
    /// Argon2 rejected the parameters or failed to hash.
    #[error("key derivation failed")]
    Argon2(#[source] argon2::Error),
    /// HKDF could not expand to the requested key length.
    #[error("key expansion failed")]
    Expand(#[source] hkdf::InvalidLength),
}
