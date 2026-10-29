//! Logical SDK head-buffer components, independent of transport/RSS baseline.
use super::{
    CompletedHeadProbe, DeviceHeadProbes, IncomingHeadProbe, PreparedHeadProbe, ResidentHeadQuery,
    ResidentHeadWitness, RunnerHeadProbes,
};
use crate::{cloud::transport, signer::CredentialCapture};
use nocterm_hub_model::cloud::{
    MAX_ID_BYTES,
    head::{
        CatalogHeadPage, ChatHead, MAX_HEAD_CATALOG_PAGE, MAX_HEAD_QUERY_BYTES,
        MAX_HEAD_QUERY_ENVELOPE_BYTES, MAX_HEAD_REPLY_ENVELOPE_BYTES, MAX_HEAD_WITNESS_BYTES,
        SignedHeadQuery, SignedHeadWitness,
    },
};
use nocterm_hub_proto::v1;
use std::mem::size_of;

// Bounded canonical writers append to Vec; amortized growth can retain less
// than twice the permitted final length. This is capacity slack for those
// concrete buffers, not a guessed expansion of arbitrary caller payloads.
const QUERY_CANONICAL: usize = 2 * MAX_HEAD_QUERY_BYTES;
const SIGNED_QUERY: usize = 2 * MAX_HEAD_QUERY_ENVELOPE_BYTES;
const WITNESS_CANONICAL: usize = 2 * MAX_HEAD_WITNESS_BYTES;
// Query AAD context is canonical scope plus the16-byte probe ID; witness AAD
// context is the complete canonical query, which is no larger than this limit.
const CONTEXT_LENGTH: usize = MAX_HEAD_QUERY_BYTES + 16;
const CONTEXT_BUFFER: usize = 2 * CONTEXT_LENGTH;
const HEX_CONTEXT: usize = 2 * CONTEXT_LENGTH;
// Existing seal::aad adds a fixed purpose label/length prefix below64 bytes.
const AAD_BUFFER: usize = 2 * (64 + HEX_CONTEXT);
const CONTEXT_WORK: usize = CONTEXT_BUFFER + HEX_CONTEXT + AAD_BUFFER;

/// Logical SDK query prepare/seal/open work, excluding decoded metadata below.
/// Includes canonical/signed buffers, intermediate/final encrypted query and
/// simultaneous encoded request/response bodies. Curve/hash stack and native
/// input/clone/materialization, Tonic/HTTP2/TLS/runtime/allocator baseline are
/// separate. Reserve this before prepare/next and keep its owner until Drop.
pub fn head_query_work_bytes() -> usize {
    transport::acknowledgement_work_bytes()
        +QUERY_CANONICAL+SIGNED_QUERY+CONTEXT_WORK
        // AEAD ciphertext Vec, final envelope Vec, both real encoded bodies.
        +2*MAX_HEAD_QUERY_ENVELOPE_BYTES+MAX_HEAD_QUERY_ENVELOPE_BYTES
        +2*MAX_HEAD_QUERY_ENVELOPE_BYTES
}
/// Logical SDK witness receive/open/verify and reply transport work. Counts the
/// retained ciphertext, opened AEAD buffer, canonical signature-verification
/// buffer, query/AAD scratch and simultaneous encoded request/response bodies.
/// The caller's original reply Vec and native witness signing/sealing/DTOs are
/// separately admitted; passing an Arc is not proof that they were charged.
pub fn head_reply_work_bytes() -> usize {
    transport::acknowledgement_work_bytes()
        + MAX_HEAD_REPLY_ENVELOPE_BYTES
        + 2 * MAX_HEAD_REPLY_ENVELOPE_BYTES
        + WITNESS_CANONICAL
        + QUERY_CANONICAL
        + CONTEXT_WORK
        + 2 * MAX_HEAD_REPLY_ENVELOPE_BYTES
}
/// Bounded decoded SDK head metadata and fixed owner/container working set.
/// The64-chat canonical page bound is checked before its Vec allocation; count
/// its possible amortized capacity and the owning box. Twelve bounded identity
/// copies cover port/client attribution, capture, original query and decoded
/// query/witness scopes. Caller clones/publication/native DTOs are separate.
/// For one full round trip pre-admit query + reply + decoded metadata work;
/// each concurrent operation needs its own actual admission, even if a native
/// aggregate allocation supplies several reference-counted guards.
pub fn head_decoded_metadata_bytes() -> usize {
    2 * MAX_HEAD_CATALOG_PAGE * size_of::<ChatHead>()
        + size_of::<CatalogHeadPage>()
        + size_of::<ChatHead>()
        + 12 * MAX_ID_BYTES
        + size_of::<CredentialCapture>()
        + size_of::<SignedHeadQuery>()
        + size_of::<SignedHeadWitness>()
        + size_of::<DeviceHeadProbes>()
        + size_of::<RunnerHeadProbes>()
        + size_of::<PreparedHeadProbe>()
        + size_of::<IncomingHeadProbe>()
        + size_of::<CompletedHeadProbe>()
        + size_of::<ResidentHeadQuery>()
        + size_of::<ResidentHeadWitness>()
        + size_of::<v1::CloudHeadProbe>()
        + size_of::<v1::CloudHeadProbeReply>()
        + size_of::<v1::CloudNextHeadProbe>()
        + size_of::<v1::CloudHeadProbeDelivery>()
        + size_of::<v1::CloudHeadProbeReplied>()
}
