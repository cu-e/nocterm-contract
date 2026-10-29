//! Fresh, read-only runner witnesses. A hub capability proof is not a history head.
//! No value here admits a command, renews a writer, advances control, or grants
//! model/SSH access. Actual journal heads and pinned keys come from consumers.
mod query;
mod reader;
mod witness;
mod writer;

pub use query::{HeadProbeKeys, HeadProbeScope, HeadQuery, HeadTarget, SignedHeadQuery};
pub use witness::{
    CatalogHeadCursor, CatalogHeadPage, ChatHead, HeadRecordAnchor, HeadValue, HeadWitness,
    ReceiptOutcome, SignedHeadWitness,
};

pub const MAX_HEAD_QUERY_BYTES: usize = 2 * 1024;
pub const MAX_HEAD_QUERY_ENVELOPE_BYTES: usize = 4 * 1024;
pub const MAX_HEAD_WITNESS_BYTES: usize = 30 * 1024;
pub const MAX_HEAD_REPLY_ENVELOPE_BYTES: usize = 32 * 1024;
pub const MAX_HEAD_CATALOG_PAGE: usize = 64;
pub const MAX_HEAD_CATALOG_CHATS: u32 = 100_000;
pub const MAX_HEAD_PROBES_PER_ACCOUNT: usize = 32;
pub const MAX_HEAD_PROBES_GLOBAL: usize = 256;
pub const MAX_HEAD_PROBE_LIFETIME_MS: i64 = 10_000;
pub const MAX_HEAD_CLOCK_SKEW_MS: i64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeadProbeError {
    #[error("the bounded head probe or witness exceeds its limit")]
    Bounds,
    #[error("the head probe contains an invalid or unsupported value")]
    Value,
    #[error("the original head probe scope, request or pins differ")]
    Scope,
    #[error("the original head probe is expired or its clock moved backwards")]
    Time,
    #[error("the head witness does not answer its original query")]
    Target,
    #[error("the witnessed catalog page or retained head is inconsistent")]
    Position,
    #[error("the head probe framing is invalid")]
    Framing(#[from] super::CommandError),
    #[error("the purpose-specific head signature is invalid")]
    Signature(#[from] crate::pop::SignatureError),
}

#[cfg(test)]
mod tests;
