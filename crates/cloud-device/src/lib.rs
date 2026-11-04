//! Cloud chat formats for an account device that has no native storage, such as the web panel.
//!
//! Purpose: let a browser device (a non-extractable WebCrypto Ed25519 key registered on the hub)
//! read and drive the account's Cloud chats with exactly the checks a native device makes
//! (ADR 0006).
//!
//! Owns:
//! - the private account record layouts kept in personal Store collections: hub trust
//!   (`cloud-hub-trust`), the trusted runner registry (`cloud-runner-registry`), wrapped chat
//!   keys (`cloud-chat-material`) and stored chat key grants (`cloud-chat-grant`), with their
//!   collection and object identifiers ([`records`]);
//! - choosing the hub-trust record for a hub and account, and checking the hub's capability proof
//!   against it ([`trust`]);
//! - two-step device head probes: canonical bytes out, the caller's Ed25519 signature in, the
//!   sealed query out, and the witness opened and checked against the original query ([`probe`]);
//! - verification of one chat's replay frames against the expected record context, the pinned
//!   runner keys, cursor and sequence continuity, gaps and the fresh head ([`replay`]);
//! - a small transcript reducer producing neutral rows ([`transcript`]);
//! - two-step device commands (prompt, stop, inference grant, approval answer) sealed to the
//!   pinned runner with the account key pair ([`command`]) and their runner-default bounds
//!   ([`policy`]);
//! - the building blocks of a new chat: id, key, wrapped material and sealed grant ([`create`]).
//!
//! Does not own: the network, storage, clocks beyond the `now_ms` the caller passes, the device
//! key (the caller signs the bytes it is given), the user interface, or anything the runner does.
//!
//! Ports used/provided: none. Settings: none. Globals: none.
//!
//! Invariants:
//! - nothing a hub offers becomes a trust pin: hub authority, runner keys and account keys come
//!   from the account's own encrypted records or from the caller's signed-in keyset;
//! - a signature supplied by the caller is verified against the device key named in the signed
//!   bytes before anything is sealed;
//! - a replayed record is accepted only from the pinned runner, in its chat, in cursor and
//!   sequence order, and a replay that ends before the freshly witnessed head is refused;
//! - chat keys are passed in per call and never retained by a value of this crate;
//! - the transcript is display data: no row grants or admits anything.

pub mod command;
pub mod create;
mod error;
pub mod policy;
pub mod probe;
pub mod records;
pub mod replay;
mod scope;
#[cfg(test)]
mod testing;
pub mod transcript;
pub mod trust;

pub use error::CloudDeviceError;
pub use scope::{AccountScope, DeviceIdentity};
