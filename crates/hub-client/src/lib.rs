//! Client of a Nocterm hub, shared by `hubctl`, the node daemon and the desktop client.
//!
//! Owns: connection setup (certificate pinning, public CAs, plaintext), probing a hub's
//! certificate before trusting it, device proof of possession on every call,
//! password/invite/bootstrap and OIDC loopback sign-in, token refresh, a resumable terminal
//! driver over the Link, and typed errors ([`ClientError`]) for all of them.
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

mod client;
mod connect;
mod error;
mod oidc;
mod probe;
mod signer;
mod store;
pub mod terminal;

pub use client::{DeviceInfo, HubClient, Signed};
pub use connect::{ConnectError, EndpointError, HubEndpoint, Trust, parse_fingerprint};
pub use error::{ClientError, LinkError, OidcError, StatusCause, StatusCode};
pub use probe::{Probe, ProbeError};
pub use signer::{Session, Signer, now_ms};
pub use store::SessionStore;
