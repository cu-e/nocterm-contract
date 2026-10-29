//! gRPC stubs (tonic) of the Nocterm hub protocol, package `nocterm.hub.v1`.
//!
//! Owns: generated service traits for servers and generated clients for every service.
//! Does not own: messages (`nocterm-hub-proto`, shared with the WebSocket transport),
//! authentication or connection setup.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: generated only from `nocterm_hub_proto::FILE_DESCRIPTOR_SET`, so stubs and
//! messages always describe the same protocol version.

#[allow(
    clippy::all,
    clippy::pedantic,
    missing_debug_implementations,
    unused_qualifications,
    reason = "generated code"
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/nocterm.hub.v1.rs"));
}

pub use v1::*;

/// Names of the gRPC metadata entries that carry device authentication and errors.
pub mod metadata {
    /// `Bearer <access token>`.
    pub const AUTHORIZATION: &str = "authorization";
    /// Device identifier the access token is bound to.
    pub const DEVICE: &str = "x-nocterm-device";
    /// Signing time in Unix milliseconds.
    pub const SIGNED_AT: &str = "x-nocterm-ts";
    /// Single-use random nonce.
    pub const NONCE: &str = "x-nocterm-nonce";
    /// Ed25519 signature over `pop::request_message(hub_id, path, token, nonce, ts)` where
    /// `path` is `/{service}/{method}` (binary metadata, base64 on the wire).
    pub const PROOF: &str = "x-nocterm-proof-bin";
    /// Strict canonical `cloud::runner_request::RunnerRequestClaim`, Cloud service only.
    pub const RUNNER_CLAIM: &str = "x-nocterm-runner-claim-bin";
    /// Runner PoP signature; never interpreted as an ordinary account-device proof.
    pub const RUNNER_PROOF: &str = "x-nocterm-runner-proof-bin";
    /// `ErrorCode` name of a failed call (`ERROR_CODE_TOKEN_EXPIRED`, …).
    pub const ERROR_CODE: &str = "x-nocterm-error";
    /// Current version of an object after a version conflict.
    pub const CURRENT_VERSION: &str = "x-nocterm-current-version";
}

/// Path signed in the `LinkHello` of every Link, whatever the transport.
pub const LINK_PATH: &str = "/v1/link";

/// Path signed for a gRPC method: `/{service}/{method}`.
pub fn method_path(service: &str, method: &str) -> String {
    format!("/{service}/{method}")
}
