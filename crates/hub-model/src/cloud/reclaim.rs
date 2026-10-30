//! Receipt reclaim (capability bit 64): the retry horizon of a publication, the explicit
//! deletion of a chat and the 32-byte tombstones that keep retired identities from returning.
//!
//! Everything here is optional and additive. A peer that did not negotiate
//! [`super::capabilities::CLOUD_FEATURE_RECEIPT_RECLAIM`] sends `retry_until_ms = 0` and its
//! receipts and streams are kept as before.

use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::{
    CloudNamespace, CloudTextId, CommandError, RunnerCoordinate,
    codec::{self, Reader},
};
use crate::pop::{self, SignatureError};

/// Longest promise a client may make: it will not retry a publication later than 30 days
/// after it was made.
pub const MAX_RETRY_HORIZON_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Extra time after `retry_until_ms` before a hub drops the receipt, covering clock skew and a
/// request still in flight.
pub const RECLAIM_GRACE_MS: i64 = 10 * 60 * 1000;
/// Largest canonical chat deletion tombstone.
pub const MAX_DELETION_TOMBSTONE_BYTES: usize = 1024;

const RETIRED_STREAM_DOMAIN: &[u8] = b"nocterm/cloud-retired-stream/v1";
const REVOKED_RUNNER_DOMAIN: &[u8] = b"nocterm/cloud-revoked-runner/v1";
const DELETION_DOMAIN: &[u8] = b"nocterm/cloud-chat-deletion/v1";

/// A retry horizon or tombstone that is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReclaimError {
    /// The horizon is not in the future or further than [`MAX_RETRY_HORIZON_MS`].
    #[error("the retry horizon is not within the allowed window")]
    Horizon,
    /// Not the canonical tombstone layout.
    #[error("malformed chat deletion tombstone")]
    Malformed,
    /// The signature does not verify.
    #[error("the chat deletion tombstone signature is invalid")]
    Signature(#[from] SignatureError),
    /// A textual identity is empty or too long.
    #[error(transparent)]
    Identity(#[from] CommandError),
}

/// Checks a `retry_until_ms` on a new publication at `now_ms`. Zero means "no horizon" and is
/// what peers without the capability send; it is valid and never reclaimed.
pub fn validate_retry_until(now_ms: i64, retry_until_ms: i64) -> Result<(), ReclaimError> {
    if retry_until_ms == 0 {
        return Ok(());
    }
    let ahead = retry_until_ms
        .checked_sub(now_ms)
        .ok_or(ReclaimError::Horizon)?;
    if (1..=MAX_RETRY_HORIZON_MS).contains(&ahead) {
        Ok(())
    } else {
        Err(ReclaimError::Horizon)
    }
}

/// Whether a hub may drop the receipt of a publication. Receipts without a horizon (old
/// format, `retry_until_ms == 0`) are never reclaimed.
pub fn receipt_reclaimable(retry_until_ms: i64, now_ms: i64) -> bool {
    retry_until_ms > 0
        && retry_until_ms
            .checked_add(RECLAIM_GRACE_MS)
            .is_some_and(|deadline| now_ms >= deadline)
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(128);
    let mut push = |part: &[u8]| {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(part);
    };
    push(domain);
    for part in parts {
        push(part);
    }
    Sha256::digest(bytes).into()
}

/// Identity of a retired chat stream. Its 32-byte hash replaces the stream's bookkeeping and
/// forbids the same stream from being accepted again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetiredStream<'a> {
    /// Account of the stream.
    pub account_id: &'a str,
    /// Runner id.
    pub runner_id: [u8; 16],
    /// Runner key epoch.
    pub runner_key_epoch: u64,
    /// Chat id.
    pub chat_id: [u8; 16],
}

impl RetiredStream<'_> {
    /// `SHA-256(lp(domain) lp(account) lp(runner) lp(epoch, be64) lp(chat))`.
    pub fn tombstone_hash(&self) -> [u8; 32] {
        hash(
            RETIRED_STREAM_DOMAIN,
            &[
                self.account_id.as_bytes(),
                &self.runner_id,
                &self.runner_key_epoch.to_be_bytes(),
                &self.chat_id,
            ],
        )
    }
}

/// Identity of a revoked runner. Re-registering the same id stays forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokedRunner<'a> {
    /// Account of the runner.
    pub account_id: &'a str,
    /// Runner id.
    pub runner_id: [u8; 16],
}

impl RevokedRunner<'_> {
    /// `SHA-256(lp(domain) lp(account) lp(runner))`.
    pub fn tombstone_hash(&self) -> [u8; 32] {
        hash(
            REVOKED_RUNNER_DOMAIN,
            &[self.account_id.as_bytes(), &self.runner_id],
        )
    }
}

/// The runner's statement that a chat was deleted, after the device asked for it. A hub that
/// receives it and the readers' acknowledgements may compact the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatDeletionTombstone {
    /// Hub and account coordinates.
    pub namespace: CloudNamespace,
    /// Runner and key epoch that owned the chat.
    pub runner: RunnerCoordinate,
    /// The deleted chat.
    pub chat_id: [u8; 16],
    /// The device that asked for the deletion.
    pub requested_by: CloudTextId,
    /// Deletion time in Unix milliseconds.
    pub deleted_at_ms: i64,
}

impl ChatDeletionTombstone {
    /// The exact bytes the runner signs.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReclaimError> {
        let mut out = Vec::with_capacity(256);
        codec::field(&mut out, DELETION_DOMAIN)?;
        codec::field(&mut out, self.namespace.hub_instance_id.as_str().as_bytes())?;
        codec::field(&mut out, self.namespace.account_id.as_str().as_bytes())?;
        out.extend_from_slice(&self.runner.id);
        out.extend_from_slice(&self.runner.key_epoch.to_be_bytes());
        out.extend_from_slice(&self.chat_id);
        codec::field(&mut out, self.requested_by.as_str().as_bytes())?;
        out.extend_from_slice(&self.deleted_at_ms.to_be_bytes());
        Ok(out)
    }

    /// Strict decoder.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReclaimError> {
        if bytes.len() > MAX_DELETION_TOMBSTONE_BYTES {
            return Err(ReclaimError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(DELETION_DOMAIN.len())? != DELETION_DOMAIN {
            return Err(ReclaimError::Malformed);
        }
        let namespace = CloudNamespace {
            hub_instance_id: reader.text()?,
            account_id: reader.text()?,
        };
        let runner = RunnerCoordinate {
            id: reader.array()?,
            key_epoch: u64::from_be_bytes(reader.array()?),
        };
        let chat_id = reader.array()?;
        let requested_by = reader.text()?;
        let deleted_at_ms = i64::from_be_bytes(reader.array()?);
        reader.finish()?;
        Ok(Self {
            namespace,
            runner,
            chat_id,
            requested_by,
            deleted_at_ms,
        })
    }

    /// Signs the canonical bytes with the runner's signing key.
    pub fn sign(&self, key: &SigningKey) -> Result<[u8; 64], ReclaimError> {
        let signature: Signature = key.sign(&self.canonical_bytes()?);
        Ok(signature.to_bytes())
    }

    /// Verifies the signature under the runner's pinned signing key.
    pub fn verify(&self, runner_key: &[u8; 32], signature: &[u8]) -> Result<(), ReclaimError> {
        pop::verify(runner_key, &self.canonical_bytes()?, signature)?;
        Ok(())
    }

    /// The tombstone hash of the stream this deletion retires.
    pub fn retired_stream_hash(&self) -> [u8; 32] {
        RetiredStream {
            account_id: self.namespace.account_id.as_str(),
            runner_id: self.runner.id,
            runner_key_epoch: self.runner.key_epoch,
            chat_id: self.chat_id,
        }
        .tombstone_hash()
    }
}
