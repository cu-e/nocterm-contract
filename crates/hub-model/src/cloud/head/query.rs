use super::{CatalogHeadCursor, HeadProbeError, MAX_HEAD_PROBE_LIFETIME_MS, reader, writer};
use crate::{
    cloud::{CloudNamespace, CommandIssuer, RunnerCoordinate, capabilities::CapabilityWindow},
    pop,
};

/// Independently configured account and runner pins, never offered-directory trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadProbeKeys {
    pub account: [u8; 32],
    pub runner_encryption: [u8; 32],
    pub runner_signing: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadProbeScope {
    pub namespace: CloudNamespace,
    pub runner: RunnerCoordinate,
    pub keys: HeadProbeKeys,
}
impl HeadProbeScope {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HeadProbeError> {
        writer::scope(self)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HeadProbeError> {
        reader::scope(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadTarget {
    Catalog {
        after: Option<CatalogHeadCursor>,
    },
    Chat {
        chat_id: [u8; 16],
        chat_key_epoch: u64,
    },
    CommandReceipt {
        chat_id: [u8; 16],
        chat_key_epoch: u64,
        command_id: [u8; 16],
        semantic_digest: [u8; 32],
        expected_control_revision: u64,
    },
}

/// A fresh read-only request. Randomness, membership and one-shot lifetime are
/// supplied by the native/SDK owner; constructing bytes proves none of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadQuery {
    pub scope: HeadProbeScope,
    pub issuer: CommandIssuer,
    pub probe_id: [u8; 16],
    pub challenge: [u8; 32],
    pub window: CapabilityWindow,
    pub target: HeadTarget,
}
impl HeadQuery {
    pub fn validate(&self) -> Result<(), HeadProbeError> {
        let duration = self
            .window
            .expires_at_ms
            .checked_sub(self.window.issued_at_ms)
            .ok_or(HeadProbeError::Time)?;
        if self.window.issued_at_ms <= 0 || !(1..=MAX_HEAD_PROBE_LIFETIME_MS).contains(&duration) {
            return Err(HeadProbeError::Time);
        }
        writer::validate_query(self)
    }
    /// Device-side acceptance never extends the original deadline or accepts a
    /// backwards local clock. A monotonic native timeout is required as well.
    pub fn require_fresh(&self, now_ms: i64) -> Result<(), HeadProbeError> {
        self.validate()?;
        if now_ms < self.window.issued_at_ms || now_ms >= self.window.expires_at_ms {
            return Err(HeadProbeError::Time);
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HeadProbeError> {
        self.validate()?;
        writer::query(self)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HeadProbeError> {
        reader::query(bytes)
    }
}

/// Valid device self-signature only; account authentication and exact installed
/// pins are separately checked by the authenticated-box opener and native owner.
#[derive(Clone, Debug)]
pub struct SignedHeadQuery {
    query: HeadQuery,
    signature: [u8; 64],
}
impl SignedHeadQuery {
    pub fn new(query: HeadQuery, signature: [u8; 64]) -> Result<Self, HeadProbeError> {
        pop::verify(
            &query.issuer.signing_key,
            &query.canonical_bytes()?,
            &signature,
        )?;
        Ok(Self { query, signature })
    }
    pub fn query(&self) -> &HeadQuery {
        &self.query
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HeadProbeError> {
        writer::signed(
            &self.query.canonical_bytes()?,
            &self.signature,
            super::MAX_HEAD_QUERY_ENVELOPE_BYTES,
        )
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HeadProbeError> {
        let (body, signature) = reader::signed(bytes, super::MAX_HEAD_QUERY_ENVELOPE_BYTES)?;
        Self::new(HeadQuery::from_canonical_bytes(body)?, signature)
    }
}
