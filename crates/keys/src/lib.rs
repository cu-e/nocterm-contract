//! Client-side key material of the Nocterm hub.
//!
//! Owns: device signing keys (Ed25519) used for proof of possession; the derivation of the
//! login value the hub verifies and of the unlock key it never sees (`login-v1`, from one
//! password); the recovery key; the key hierarchy unlock key → account key → collection key;
//! the account's X25519 pair with collection key grants authenticated by the granter's key; the
//! pins (trust on first use) of the public keys of other accounts; account-authenticated,
//! device-signed Cloud command boxes with a pinned runner, its separately
//! restorable encryption identity; and the sealed
//! formats of keys, names and objects (XChaCha20-Poly1305 with purpose-bound associated data).
//! Also owns per-chat key wraps/grants, runner-signed encrypted events/snapshots,
//! and purpose-separated encryption of native journal slots. Read-only head probes
//! have separate signed purposes and account-key replies, independent of ChatKey.
//! Native head cells use a distinct runner-derived key and finite purpose18 blob.
//! Provider credentials use a separate non-restorable boot recipient with finite
//! stable-runner attestation; opening returns a zeroizing secret owner.
//! Does not own: storage of keys on the device, the network, or any user interface.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants:
//! - the hub never receives a key that opens user data: only sealed keys and ciphertext;
//! - every sealed value binds its purpose and owner identifiers as associated data, so a
//!   ciphertext moved to another object, collection or account fails to open;
//! - KDF parameters outside [`KdfParams::MINIMUM`]..=[`KdfParams::MAXIMUM`] are rejected, so a
//!   hostile hub can neither downgrade them nor make the client allocate or compute without
//!   bound;
//! - the unlock key and the master key behind it never leave the device: the hub gets only the
//!   independent `auth` output, and each HKDF output has its own `info` label. `auth` still lets
//!   the hub test password guesses offline, so the unlock key is as strong against the hub as
//!   the password is: see [`LoginSecrets`];
//! - a grant opens only under the public key of the account that made it, and that key is one the
//!   client pinned: the hub can swap a key only before the first pin;
//! - the recovery key is 128 random bits shown once and used only through HKDF;
//! - secrets are zeroized on drop and never printed by `Debug`;
//! - a Cloud command binds its exact expected account/runner keys and route; its opaque
//!   payload still requires semantic validation and durable admission before effects.
//!
//! The control plane must never depend on this crate (blindness hygiene, checked by xtask).

mod authenticated_box;
pub mod cloud;
mod device;
mod kdf;
mod login;
mod pins;
mod random;
mod recovery;
mod seal;
mod sealed;

pub use device::DeviceKey;
pub use kdf::{KdfParams, KdfParseError};
pub use login::{LoginError, LoginSecrets, MIN_PASSWORD_CHARS, UnlockKdf, UnlockKey, UnlockSource};
pub use nocterm_hub_model::pop::{SignatureError, verify as verify_signature};
pub use pins::{PinError, PinnedKeys, TrustedKey};
pub use random::{random_bytes, random_token};
pub use recovery::{RecoveryKey, RecoveryKeyParseError};
pub use seal::{AccountKey, CollectionKey, OpenError, SealError};
pub use sealed::{AccountKeyPair, PublicKey, PublicKeyError};

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
