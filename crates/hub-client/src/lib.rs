//! Client of a Nocterm hub, shared by `hubctl`, the node daemon and the desktop client.
//!
//! Owns: connection setup (certificate pinning, public CAs, plaintext), probing a hub's
//! certificate before trusting it, device proof of possession on every call,
//! password/invite/bootstrap and OIDC loopback sign-in (the password never leaves the device:
//! the hub gets a value derived from it), token refresh, the account keyset (create, open with
//! the unlock or the recovery key, grant collection keys), relayed byte streams, a resumable
//! terminal driver over the Link, and typed errors ([`ClientError`]) for all of them.
//! Cloud clients capture original sign-in ownership, stream bounded opaque records and
//! keep runner-only credentials separate from ordinary account-device sessions.
//! One-shot fresh-head probes preserve the original login/challenge/deadline;
//! staging authenticated native outbox bytes never rewrites signed commands.
//! Guarded capability/Store acquisition retains actual body and accepted metadata
//! owners; immutable hub information is shared rather than deeply cloned.
//! Guarded runner heartbeat and device status calls retain bounded body/result
//! ownership; runner deadline observations clone no credential or token.
//! Cloud device flows (`nocterm-cloud-device`) sign through [`HubClient::sign_cloud`], which
//! accepts only the core's sign requests for this device's key, name the device with
//! [`HubClient::cloud_device`], and send their Cloud effects with [`HubClient::capabilities`],
//! [`HubClient::probe_head`], [`HubClient::publish_one`], [`HubClient::replay`],
//! [`HubClient::watch`] and [`HubClient::runner_status`]: exactly the bytes the core built, under
//! this client's signer and token refresh, answered as the core's `Input` and `Frame` values or
//! a [`CloudCallError`] with its `EffectFailure` (contract ADR 0010). A runner publishes sealed chat summaries to its directory with
//! `CloudRunner::publish_summary` (capability bit 256, ADR 0008); devices and runners replay
//! and watch it as `CloudSelector::Directory`, whose cursors have holes and never a gap.
//! Does not own: where keys and tokens are stored (callers persist the device seed and
//! provide a [`SessionStore`] for tokens), how a device is named (callers pass a
//! [`DeviceInfo`]), terminal rendering, or vault encryption (`nocterm-keys`).
//! Ports used/provided: generated gRPC clients of `nocterm-hub-grpc`; [`SessionStore`] for
//! callers. Settings: none.
//! Globals: none.
//! Invariants: the device's private key never leaves the process; every authenticated call
//! is signed over its method path with a fresh nonce; a pinned hub is trusted only with
//! the exact certificate fingerprint; [`HubEndpoint::probe`] trusts nothing and sends no
//! credentials; the library reads no environment.

pub mod agents;
mod client;
pub mod cloud;
mod cloud_calls;
mod connect;
mod error;
mod keyset;
mod oidc;
mod probe;
mod relay;
mod resident_store;
mod signer;
mod store;
pub mod terminal;

pub use client::{DeviceInfo, HubClient, Signed, SignedIn};
pub use cloud_calls::{CloudCallError, CloudFrames, MAX_PROBE_WAIT_MS};
pub use connect::{ConnectError, EndpointError, HubEndpoint, Trust, parse_fingerprint};
pub use error::{ClientError, LinkError, OidcError, StatusCause, StatusCode};
pub use keyset::{Keyset, KeysetError, NewKeyset, UnlockMethod};
pub use probe::{Probe, ProbeError};
pub use relay::{
    MAX_FRAME, QUEUE_DEPTH, RelayConn, RelayError, RelayReader, RelayTarget, RelayWriter,
};
pub use signer::{Session, Signer, now_ms};
pub use store::SessionStore;

pub use resident_store::{
    ResidentStoreChannel, ResidentStoreClient, ResidentStoreSigned, ResidentStoreSigner,
    store_work_bytes,
};
