//! Vocabulary of managed agents: scopes, listings, resources, typed refusals, the pool key
//! bundle and the host attestation of a runner setup document.
//!
//! Plain data and canonical bytes only: no I/O, no clocks, no randomness. Whatever a hub
//! displays here is descriptive; the sealed definition (`nocterm-keys::agents`) is what a host
//! executes.

mod attestation;
pub mod limits;
mod listing;
mod pin;
mod refusal;
mod resources;
mod scope;

pub use attestation::{AttestationError, HostRunnerAttestation, SignedHostRunnerAttestation};
pub use listing::{AgentAccess, AgentListing, Availability, InstanceState, ListingError};
pub use pin::{PoolKeyChanged, PoolTrust, check_pool_keys};
pub use refusal::{QuotaScope, RefusalReason};
pub use resources::{ResourceError, ResourceRequest, ScopeLimits};
pub use scope::{AgentScope, PoolKeys, ScopeError, ScopeKind};
