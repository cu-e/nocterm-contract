//! Runner chat summaries, format 1: what a device lists a chat with, without replaying it
//! (ADR 0008).
//!
//! The runner is the only party that sees a chat's plaintext and orders its events, so it
//! derives a [`ChatSummary`], signs it with its pinned signing key over its [`SummaryContext`]
//! and seals it to the account key (`nocterm_keys::cloud::{seal_summary, open_summary}`). The
//! sealed summary travels in the runner's directory stream (`CloudSelector.directory`, relay
//! kind [`crate::cloud::relay::RelayKind::Summary`]), where the hub keeps the latest summary per
//! chat. A summary is display data: it admits, grants or proves nothing about the chat beyond
//! what its runner signed, and its revision is the only order a device trusts.
//!
//! Signed bytes (strict, big-endian, u32-length fields, 0/1 option flags, closed tags, exact
//! EOF): field(`nocterm/cloud-chat-summary/v1`) ‖ field(context) ‖ head ‖ control revision u64
//! ‖ created at i64 ‖ last activity i64 ‖ field(title) ‖ host ‖ model ‖ state u8 ‖ pending
//! approvals u16 ‖ u8 server count ‖ servers ‖ features u32. The whole signed body is at most
//! [`MAX_SUMMARY_BYTES`]; the signed framing is field(body) ‖ Ed25519 signature (64).
mod codec;

use super::{ChatCoordinate, CloudTextId, CommandError, MAX_HEADER_BYTES, MaterialError};
use crate::pop::{self, SignatureError};
use sha2::{Digest, Sha256};

/// The largest canonical signed summary body, context included.
pub const MAX_SUMMARY_BYTES: usize = 2048;
/// The largest signed framing: field(body) ‖ signature.
pub const MAX_SIGNED_SUMMARY_BYTES: usize = MAX_SUMMARY_BYTES + 4 + 64;
/// The largest sealed summary (version, purpose, ephemeral key, nonce, tag): one relay frame.
pub const MAX_SEALED_SUMMARY_BYTES: usize = MAX_SIGNED_SUMMARY_BYTES + 2 + 32 + 24 + 16;
/// A title is the first line of the first accepted prompt, cut at a character boundary.
pub const MAX_TITLE_BYTES: usize = 120;
/// Servers a summary lists.
pub const MAX_BOUND_SERVERS: usize = 16;
/// Runner feature: the runner binds chats to servers with per-chat SSH certificates.
pub const SUMMARY_FEATURE_SSH_BINDING: u32 = 1;
/// Runner feature: the runner takes own-provider leases (`ProviderLease`).
pub const SUMMARY_FEATURE_PROVIDER_LEASE: u32 = 2;

pub(super) const SUMMARY_LABEL: &[u8] = b"nocterm/cloud-chat-summary/v1";
pub(super) const CONTEXT_LABEL: &[u8] = b"nocterm/cloud-summary-context/v1";
const PUBLICATION_LABEL: &[u8] = b"nocterm/cloud-summary-publication/v1";

/// Which summary of which chat: the routing a directory publication carries in clear, and the
/// context the runner signs and the account box authenticates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryContext {
    chat: ChatCoordinate,
    revision: u64,
}
impl SummaryContext {
    /// `revision` is the chat's summary revision: it starts at 1 and grows with every summary
    /// the runner publishes for the chat, across key epochs.
    pub fn new(chat: ChatCoordinate, revision: u64) -> Result<Self, SummaryError> {
        if revision == 0 {
            return Err(SummaryError::Value);
        }
        Ok(Self { chat, revision })
    }
    pub fn chat(&self) -> &ChatCoordinate {
        &self.chat
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// field(`nocterm/cloud-summary-context/v1`) ‖ field(chat coordinate) ‖ revision u64.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SummaryError> {
        let mut bytes = Vec::with_capacity(400);
        super::codec::field(&mut bytes, CONTEXT_LABEL)?;
        super::codec::field(&mut bytes, &self.chat.canonical_bytes()?)?;
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SummaryError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(SummaryError::Bounds);
        }
        let mut reader = super::codec::Reader::new(bytes);
        if reader.field(64)? != CONTEXT_LABEL {
            return Err(SummaryError::Malformed);
        }
        let chat = ChatCoordinate::from_canonical_bytes(reader.field(MAX_HEADER_BYTES)?)?;
        let revision = u64::from_be_bytes(reader.array()?);
        reader.finish()?;
        Self::new(chat, revision)
    }
    /// The transport publication id of this summary: the first 16 bytes of
    /// SHA-256(field(`nocterm/cloud-summary-publication/v1`) ‖ context). A runner retrying a
    /// summary therefore publishes under the same id.
    pub fn publication_id(&self) -> Result<[u8; 16], SummaryError> {
        let mut bytes = Vec::with_capacity(448);
        super::codec::field(&mut bytes, PUBLICATION_LABEL)?;
        bytes.extend_from_slice(&self.canonical_bytes()?);
        let digest = Sha256::digest(bytes);
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Ok(id)
    }
}

/// The newest record of the chat as its catalog witness names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SummaryHead {
    /// The delivered event sequence of the newest record (at least 1).
    pub sequence: u64,
    /// SHA-256 of that record's ciphertext (`HeadRecordAnchor::ciphertext_digest`).
    pub ciphertext_digest: [u8; 32],
}

/// Where the chat runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SummaryHost {
    /// A managed agent's seat.
    Managed { agent_id: CloudTextId },
    /// The person's own runner.
    Own,
}

/// The model of the chat's latest run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryModel {
    pub provider: CloudTextId,
    pub model: CloudTextId,
}

/// What the chat is doing, as the runner last saw it. Closed: a new state needs a new format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChatState {
    Idle = 1,
    Running = 2,
    WaitingApproval = 3,
    NeedsGrant = 4,
    NeedsProvider = 5,
    NeedsSsh = 6,
    Failed = 7,
    Deleted = 8,
}
impl ChatState {
    pub(super) fn from_tag(tag: u8) -> Result<Self, SummaryError> {
        Ok(match tag {
            1 => Self::Idle,
            2 => Self::Running,
            3 => Self::WaitingApproval,
            4 => Self::NeedsGrant,
            5 => Self::NeedsProvider,
            6 => Self::NeedsSsh,
            7 => Self::Failed,
            8 => Self::Deleted,
            _ => return Err(SummaryError::Value),
        })
    }
}

/// The state of one server binding (filled in by per-chat SSH binding, ADR 0009).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ServerState {
    /// A certificate is valid until `valid_before_ms`.
    Active = 1,
    /// The runner asked for a certificate and waits for an account device to answer.
    AwaitingDevice = 2,
    /// The runner cannot reach the server.
    Unreachable = 3,
    /// The server's `authorized_keys` line needs the per-server CA principal.
    NeedsCaUpdate = 4,
}
impl ServerState {
    pub(super) fn from_tag(tag: u8) -> Result<Self, SummaryError> {
        Ok(match tag {
            1 => Self::Active,
            2 => Self::AwaitingDevice,
            3 => Self::Unreachable,
            4 => Self::NeedsCaUpdate,
            _ => return Err(SummaryError::Value),
        })
    }
}

/// One server the chat is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundServer {
    pub host: CloudTextId,
    pub port: u16,
    pub user: CloudTextId,
    pub state: ServerState,
    pub valid_before_ms: Option<i64>,
}

/// One chat's summary as its runner signs it. Plain data; [`ChatSummary::validate`] checks the
/// bounds every encoder and decoder applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatSummary {
    /// The newest record; `None` for a chat without records.
    pub head: Option<SummaryHead>,
    pub control_revision: u64,
    pub created_at_ms: i64,
    pub last_activity_ms: i64,
    /// [`title_from_prompt`] of the first accepted prompt; empty before one.
    pub title: String,
    pub host: SummaryHost,
    pub model: Option<SummaryModel>,
    pub state: ChatState,
    pub pending_approvals: u16,
    /// At most [`MAX_BOUND_SERVERS`]; empty until the chat is bound (ADR 0009).
    pub servers: Vec<BoundServer>,
    /// `SUMMARY_FEATURE_*` bits; readers ignore bits they do not know.
    pub features: u32,
}
impl ChatSummary {
    pub fn validate(&self) -> Result<(), SummaryError> {
        if self.created_at_ms <= 0
            || self.last_activity_ms < self.created_at_ms
            || self.head.is_some_and(|head| head.sequence == 0)
            || self.title.len() > MAX_TITLE_BYTES
            || self.title.chars().any(char::is_control)
            || self.servers.len() > MAX_BOUND_SERVERS
            || self
                .servers
                .iter()
                .any(|server| server.port == 0 || server.valid_before_ms.is_some_and(|at| at <= 0))
        {
            return Err(SummaryError::Value);
        }
        Ok(())
    }
    /// The bytes the runner signs: this summary under `context`, at most [`MAX_SUMMARY_BYTES`].
    pub fn signing_bytes(&self, context: &SummaryContext) -> Result<Vec<u8>, SummaryError> {
        self.validate()?;
        codec::write(context, self)
    }
    /// Decodes signing bytes into their context and summary.
    pub fn from_signing_bytes(bytes: &[u8]) -> Result<(SummaryContext, Self), SummaryError> {
        let (context, summary) = codec::read(bytes)?;
        summary.validate()?;
        Ok((context, summary))
    }
}

/// The title a runner derives from the first accepted prompt: its first non-empty line, with
/// surrounding whitespace removed, control characters replaced by spaces and cut to at most
/// [`MAX_TITLE_BYTES`] at a character boundary.
pub fn title_from_prompt(prompt: &str) -> String {
    let line = prompt
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    let mut title = String::with_capacity(MAX_TITLE_BYTES);
    for character in line.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if title.len() + character.len_utf8() > MAX_TITLE_BYTES {
            break;
        }
        title.push(character);
    }
    title.trim_end().to_owned()
}

/// A summary whose runner signature verified under the signing key the caller pinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedChatSummary {
    context: SummaryContext,
    summary: ChatSummary,
    signature: [u8; 64],
}
impl SignedChatSummary {
    /// Verifies `signature` over the signing bytes under `runner_signing`.
    pub fn new(
        context: SummaryContext,
        summary: ChatSummary,
        signature: [u8; 64],
        runner_signing: &[u8; 32],
    ) -> Result<Self, SummaryError> {
        pop::verify(
            runner_signing,
            &summary.signing_bytes(&context)?,
            &signature,
        )?;
        Ok(Self {
            context,
            summary,
            signature,
        })
    }
    pub fn context(&self) -> &SummaryContext {
        &self.context
    }
    pub fn summary(&self) -> &ChatSummary {
        &self.summary
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
    /// field(signing bytes) ‖ signature.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SummaryError> {
        let body = self.summary.signing_bytes(&self.context)?;
        let mut bytes = Vec::with_capacity(body.len() + 68);
        super::codec::field(&mut bytes, &body)?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    /// Decodes signed framing and verifies it under `runner_signing`.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        runner_signing: &[u8; 32],
    ) -> Result<Self, SummaryError> {
        if bytes.len() > MAX_SIGNED_SUMMARY_BYTES {
            return Err(SummaryError::Bounds);
        }
        let mut reader = super::codec::Reader::new(bytes);
        let body = reader.field(MAX_SUMMARY_BYTES)?;
        let signature = reader.array()?;
        reader.finish()?;
        let (context, summary) = ChatSummary::from_signing_bytes(body)?;
        Self::new(context, summary, signature, runner_signing)
    }
}

/// A summary or its context was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SummaryError {
    #[error("the chat summary exceeds its bound")]
    Bounds,
    #[error("the chat summary holds an invalid or unsupported value")]
    Value,
    #[error("malformed or noncanonical chat summary")]
    Malformed,
    #[error("the chat summary framing is invalid")]
    Framing(#[from] CommandError),
    #[error("the chat summary names invalid chat coordinates")]
    Chat(#[from] MaterialError),
    #[error("the chat summary's runner signature is invalid")]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
mod tests;
