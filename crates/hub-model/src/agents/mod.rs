//! Vocabulary of managed agents: scopes, listings, resources, typed refusals, the pool key
//! bundle, the host attestation of a runner setup document, the text of chat ids, the agents
//! protocol level of a host, the host-to-runner chat access frames and provider probe results.
//!
//! Plain data and canonical bytes only: no I/O, no clocks, no randomness. Whatever a hub
//! displays here is descriptive; the sealed definition (`nocterm-keys::agents`) is what a host
//! executes.

mod attestation;
mod chat_access_frame;
mod chat_id;
pub mod limits;
mod listing;
mod pin;
mod probe;
mod protocol;
mod refusal;
mod resources;
mod scope;

pub use attestation::{AttestationError, HostRunnerAttestation, SignedHostRunnerAttestation};
pub use chat_access_frame::{
    CHAT_ACCESS_FRAME_VERSION, ChatAccessDecoder, ChatAccessFrame, ChatAccessFrameError,
    ChatAccessOp, ChatAccessToken,
};
pub use chat_id::{CHAT_ID_BYTES, ChatIdError, chat_id_from_wire, chat_id_to_wire};
pub use listing::{AgentAccess, AgentListing, Availability, InstanceState, ListingError};
pub use pin::{PoolKeyChanged, PoolTrust, check_pool_keys};
pub use probe::{PROVIDER_PROBE_TIMEOUT_MS, ProbeError, ProbeFailure, ProbeOutcome, ProviderProbe};
pub use protocol::{
    AGENTS_PROTOCOL_CURRENT, AGENTS_PROTOCOL_DEFINITION_V2, AGENTS_PROTOCOL_LEGACY,
    AGENTS_PROTOCOL_PROVIDER_PROBE, AGENTS_PROTOCOL_RUNNING_LEASES, answers_provider_probes,
    opens_definition_v2, reports_running_leases,
};
pub use refusal::{QuotaScope, RefusalReason};
pub use resources::{ResourceError, ResourceRequest, ScopeLimits};
pub use scope::{AgentScope, PoolKeys, ScopeError, ScopeKind};
