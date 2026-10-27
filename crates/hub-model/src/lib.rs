//! Neutral vocabulary shared by the Nocterm hub, its nodes and its clients.
//!
//! Owns: typed identifiers, roles and permissions, device assurance levels, protocol version
//! and the canonical byte layouts that devices and nodes sign (proof of possession).
//! Does not own: transport, storage, cryptographic keys, authorization decisions
//! (`nocterm-access`) or the client-side `HubRef`.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: no I/O, no clocks, no randomness except `Uuid::new_v4` in `new()` constructors;
//! signed payloads are versioned and domain-separated so a signature for one purpose can
//! never be replayed for another.
//!
//! Public contract crate: it builds for `wasm32` and mobile targets and is licensed so it can
//! move into the public client repository unchanged.

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
pub const PROTOCOL_VERSION: u32 = 1;
