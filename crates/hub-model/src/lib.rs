//! Neutral vocabulary shared by the Nocterm hub and its clients.
//!
//! Owns: typed identifiers, device assurance levels, the protocol version, the bounds of what
//! people type and send ([`limits`]) and the canonical byte layouts that devices sign (proof of
//! possession, [`pop`]).
//! Does not own: transport, storage, private keys or authorization decisions (the hub's).
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: no I/O, no clocks, no randomness except `Uuid::new_v4` in `new()` constructors;
//! signed payloads are domain-separated so a signature for one purpose can never be replayed
//! for another.

mod assurance;
mod ids;
pub mod limits;
pub mod pop;

pub use assurance::Assurance;
pub use ids::{
    AccountId, AgentId, AttachmentId, ChatId, CollectionId, DeviceId, IdParseError, ObjectId,
    ProviderId, RunId, ServerId, WorkerId,
};

/// Protocol version this crate describes; a client refuses a hub that reports another one.
pub const PROTOCOL_VERSION: u32 = 3;
