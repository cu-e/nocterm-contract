//! Client of a Nocterm hub, used by the desktop app.
//!
//! Owns: connection setup (certificate pinning, public CAs, plaintext), probing a hub's
//! certificate before trusting it, device proof of possession on every call (signed with the
//! hub's clock), password/invite/setup and OIDC loopback sign-in (the password never leaves the
//! device: the hub gets a value derived from it), token refresh, sign-out, the account keyset
//! (create, open with the unlock or the recovery key), relayed byte streams, signed clients of
//! every service (account, vault, agents, servers, chats) and typed errors ([`ClientError`]).
//! Does not own: where keys and tokens are stored (callers persist the device seed and
//! provide a [`SessionStore`] for tokens), how a device is named (callers pass a
//! [`DeviceInfo`]), or vault encryption (`nocterm-keys`).
//! Ports used/provided: generated gRPC clients of `nocterm-hub-grpc`; [`SessionStore`] for
//! callers. Settings: none. Globals: none.
//! Invariants: the device's private key never leaves the process; every authenticated call
//! is signed over its method path with a fresh nonce; a pinned hub is trusted only with
//! the exact certificate fingerprint; [`HubEndpoint::probe`] trusts nothing and sends no
//! credentials; the library reads no environment.

mod client;
mod connect;
mod error;
mod keyset;
mod oidc;
mod probe;
mod relay;
mod signer;
mod store;

pub use client::{DeviceInfo, HubClient, Signed, SignedIn};
pub use connect::{ConnectError, EndpointError, HubEndpoint, Trust, parse_fingerprint};
pub use error::{ClientError, OidcError, StatusCause, StatusCode};
pub use keyset::{Keyset, KeysetError, NewKeyset, UnlockMethod};
pub use probe::{Probe, ProbeError};
pub use relay::{
    MAX_FRAME, QUEUE_DEPTH, RelayConn, RelayError, RelayReader, RelayTarget, RelayWriter,
};
pub use signer::{Session, Signer, now_ms};
pub use store::SessionStore;
