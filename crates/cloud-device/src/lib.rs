//! The sans-I/O Cloud device core: everything an account device decides about Cloud chats,
//! shared by the web panel (through `nocterm-keys-wasm`) and the native client (ADR 0006, 0007,
//! 0008).
//!
//! Purpose: one implementation of the device side of Cloud chats. Clients execute the typed
//! effects a flow hands out (sign, Store reads and writes, capability proof, head probe,
//! replay, watch, publish, start a seat, runner status) and keep storage; the core keeps the
//! formats, the checks, the reduction and the order of the steps.
//!
//! Owns:
//! - the effect protocol ([`flow`]: [`flow::Effect`], [`flow::Input`], [`flow::Frame`],
//!   [`flow::Step`], [`flow::Flow`]) and the device flows over it: [`discover::Discover`] (hub
//!   trust, capability proof, trusted runners), [`list::ListChats`] (directory summaries
//!   confirmed by catalog witnesses, no replay), [`open::OpenChat`] (probe, incremental verified replay, Watch, checkpoints,
//!   freshness), [`command::Deliver`] (wake, sign, seal, identical-bytes publish, receipt probe
//!   on an unknown outcome), [`create::CreateChat`] (seat, compare-created records, grant
//!   publication, claim wait) and [`provider::ProviderLease`] (own-runner provider lease);
//! - the private account record layouts kept in personal Store collections: hub trust
//!   (`cloud-hub-trust`), the trusted runner registry (`cloud-runner-registry`), wrapped chat
//!   keys (`cloud-chat-material`), stored chat key grants (`cloud-chat-grant`) and own-agent
//!   provider keys (`agent_provider_keys`), with their collection and object identifiers
//!   ([`records`]);
//! - choosing the hub-trust record for a hub and account, and checking the hub's capability proof
//!   against it ([`trust`]);
//! - two-step device head probes and commands: canonical bytes out as a [`flow::SignRequest`],
//!   the caller's Ed25519 signature in, sealed bytes out ([`probe`], [`command`], [`policy`]);
//! - the resumable verified reader of one chat ([`reader`]): record context, the pinned runner's
//!   keys, cursor, sequence and writer continuity, gaps, witnessed heads, the freshness levels
//!   `Current`, `Unconfirmed` and `Withheld`, and sealed device checkpoints;
//! - the transcript reducer every device shows, with deltas ([`transcript`]);
//! - the runner chat directory as a device verifies it ([`directory`]): runner-signed summaries
//!   sealed to the account, revision order, sealed directory checkpoints and the merge of
//!   summaries with the runner's catalog witness (ADR 0008);
//! - the building blocks of a new chat ([`create`]).
//!
//! Does not own: the network, storage, clocks beyond the `now_ms` the caller passes, the device
//! key (the caller signs the bytes it is given), key custody beyond holding the unlocked
//! account keys a flow was given ([`context::AccountKeys`]), the user interface, or anything the
//! runner does.
//!
//! Ports used/provided: none; the effect protocol is plain data. Settings: none. Globals: none.
//!
//! Invariants:
//! - nothing a hub offers becomes a trust pin: hub authority, runner keys and account keys come
//!   from the account's own encrypted records or from the caller's unlocked keyset;
//! - a signature supplied by the caller is verified against the device key named in the signed
//!   bytes before anything is sealed; only this crate makes the values a device signs;
//! - a replayed record is accepted only from the pinned runner, in its chat, in cursor, sequence
//!   and writer order; a transcript is always a verified prefix, and it is called `Current` only
//!   after a fresh witness was reached; a witness behind a verified checkpoint is refused;
//! - a command is sealed once and every retry publishes exactly the same bytes;
//! - a chat summary is applied only from the pinned runner, sealed to this account under its
//!   routing context, and only when its revision is newer than the one held; it is display
//!   data and never stands in for a replayed transcript;
//! - chat keys and provider keys are opened per use and never retained by a value of this crate;
//! - the transcript is display data: no row grants or admits anything.

pub mod command;
pub mod context;
pub mod create;
pub mod directory;
pub mod discover;
mod error;
pub mod flow;
pub mod list;
pub mod nonces;
pub mod open;
pub mod policy;
pub mod probe;
pub mod provider;
pub mod reader;
pub mod records;
mod scope;
#[cfg(test)]
mod testing;
pub mod transcript;
pub mod trust;

pub use error::CloudDeviceError;
pub use scope::{AccountScope, DeviceIdentity};
