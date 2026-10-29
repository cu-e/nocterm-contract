//! Neutral vocabulary shared by the Nocterm hub, its nodes and its clients.
//!
//! Owns: typed identifiers, roles and permissions, device assurance levels, protocol version
//! and the canonical byte layouts that devices and nodes sign (proof of possession),
//! including bounded, device-signed Cloud commands with opaque semantic payloads.
//! Cloud material coordinates and runner-signed event/snapshot framing bind
//! distinct delivered-event, native-journal and transaction positions.
//! Also owns closed Cloud semantic command/observation payloads, bounded snapshots,
//! original publication/control metadata, descriptive background lifecycle, accepted
//! view-only prompts, exact reconciliation facts and tool-argument fingerprints,
//! finite Local/SSH session startup, original login proofs and descriptive lifecycle,
//! fresh stable-authority capabilities, scoped runner proofs, finite boot descriptors
//! and bounded nonce-bound read-only catalog/head/receipt witnesses. Native
//! per-chat head contexts remain independent of content-key generations.
//! Does not own: transport, storage, private cryptographic keys, authorization decisions
//! (`nocterm-access`) or the client-side `HubRef`.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: no I/O, no clocks, no randomness except `Uuid::new_v4` in `new()` constructors;
//! signed payloads are versioned and domain-separated so a signature for one purpose can
//! never be replayed for another.
//!
//! Public contract crate: it builds for `wasm32` and mobile targets and is licensed so it can
//! move into the public client repository unchanged.

pub mod cloud;
mod ids;
mod permission;
pub mod pop;

pub use ids::{
    AccountId, AttachId, CollectionId, DeviceId, IdParseError, NodeId, ObjectId, OrgId, SessionId,
};
pub use permission::{Assurance, Permission, Role, RoleParseError};

/// Version of the wire protocol spoken between clients, hubs and nodes.
///
/// A hub accepts clients with the same major version and rejects others with
/// `UpgradeRequired`.
///
/// Version 2: the sign-in secret is derived from the password on the device (the hub no longer
/// sees the password), the keyset carries a public key, and relays exist. A new service that
/// leaves every existing message alone does not change the version; a client reads
/// `UNIMPLEMENTED` from it as "this hub does not offer it".
pub const PROTOCOL_VERSION: u32 = 2;
