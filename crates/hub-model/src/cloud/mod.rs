//! Canonical Cloud command bytes, without transport or execution authority.
//!
//! A verified signature authenticates bytes, not the semantic payload. Callers must
//! decode that payload for its kind, enforce original authority and durably admit
//! its id before effects. These codecs provide neither replay protection nor grants.

pub mod account_catalog;
pub mod capabilities;
mod codec;
pub mod events;
pub mod head;
mod header;
mod material;
pub mod native_chat_head;
pub mod payload;
pub mod provider;
pub mod reclaim;
mod record;
pub mod relay;
mod route;
pub mod runner_auth;
pub mod runner_request;
mod signed;
pub mod tool_arguments;

pub use header::{
    CommandContext, CommandHeader, CommandIssuer, CommandKeys, CommandKind, RunCoordinate,
};
pub use material::{ChatCoordinate, JournalClass, JournalCoordinate, MaterialError};
pub use record::{
    RecordContext, RecordError, RecordHeader, RecordKind, RecordPosition, SignedRecord,
};
pub use route::{CloudNamespace, CloudRoute, CloudTextId, RunnerCoordinate, hub_namespace_id};
pub use signed::SignedCommand;

use crate::pop::SignatureError;

/// Maximum UTF-8 byte length of each opaque textual identity.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum canonical device-signed header length.
pub const MAX_HEADER_BYTES: usize = 4096;
/// Maximum entire command plaintext, including framing and signature.
pub const MAX_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;
/// Maximum encrypted command envelope length, including its authentication tag.
pub const MAX_ENVELOPE_BYTES: usize = MAX_PLAINTEXT_BYTES + 78;
/// Maximum time between issuing and first admitting a command.
pub const MAX_COMMAND_LIFETIME_MS: i64 = 30 * 60 * 1000;
/// Maximum accepted future clock difference at first admission.
pub const MAX_FUTURE_SKEW_MS: i64 = 60 * 1000;

/// A command's framing, contents or device signature could not be verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    #[error("a Cloud textual identity must contain 1 to 128 UTF-8 bytes")]
    IdentityLength,
    #[error("the Cloud command header exceeds its limit")]
    HeaderTooLarge,
    #[error("the entire Cloud command plaintext exceeds its limit")]
    PlaintextTooLarge,
    #[error("malformed or noncanonical Cloud command framing")]
    Malformed,
    #[error("unsupported Cloud command format")]
    UnsupportedVersion,
    #[error("unsupported Cloud command kind")]
    UnsupportedKind,
    #[error("the Cloud command time window is invalid")]
    InvalidTimeWindow,
    #[error("the Cloud command has expired before admission")]
    Expired,
    #[error("the Cloud command was issued too far in the future")]
    IssuedInFuture,
    #[error("the Cloud command payload differs from its signed length or digest")]
    PayloadMismatch,
    #[error("the Cloud command device signature could not be verified")]
    Signature(#[from] SignatureError),
}
