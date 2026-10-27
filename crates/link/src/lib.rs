//! Pure state machines of the Nocterm Link channel for terminal sessions.
//!
//! Owns: the owner-side output ring with absolute byte offsets, the resume decision
//! (`Tail` or `Snapshot`), exactly-once input deduplication per attachment, and the
//! client-side bookkeeping that reopens a channel after the connection drops.
//! Does not own: sockets, TLS, framing, timers, terminal emulation or snapshot rendering.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants:
//! - output offsets are byte offsets in the session's output stream and only grow;
//! - the owner of the session (the node) is the only party that decides what was applied;
//!   the hub routes frames and never acknowledges on the owner's behalf;
//! - an input frame with sequence number `n` is applied at most once per attachment, across
//!   any number of reconnects, and only after `n - 1`;
//! - time is never read: callers drive every transition.
//!
//! Flow control is by bounded buffers: an owner that cannot deliver to a slow attachment
//! drops it, and the client resumes from its last offset, receiving a snapshot if the ring
//! no longer holds that offset (the "lossy with snapshot" channel class).

mod client;
mod input;
mod ring;

pub use client::{ClientTerminal, InputFrame, OpenParams, OutputError, Restore};
pub use input::{InputDedup, InputVerdict};
pub use ring::{OutputRing, ResumePoint};

#[cfg(test)]
mod simulation;
