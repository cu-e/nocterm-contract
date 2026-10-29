//! Purpose-specific runner redemption/refresh PoP, separate from device sessions.
use super::{
    CloudNamespace, CloudTextId, CommandError,
    codec::{self, Reader},
};
use crate::pop::{self, SignatureError};
use core::fmt;
use zeroize::Zeroizing;

pub const MAX_RUNNER_PROOF_BYTES: usize = 1024;
pub const MAX_RUNNER_TOKEN_BYTES: usize = 256;
const PROOF_WINDOW_MS: u64 = 60_000;

/// The runner has pinned these source coordinates during account runner setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerProofSubject {
    pub raw_hub_id: CloudTextId,
    pub namespace: CloudNamespace,
    pub runner_id: [u8; 16],
    pub proof_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerProofKind {
    Redeem,
    Refresh,
}
impl RunnerProofKind {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Redeem => b"nocterm/cloud-runner-redeem/v1",
            Self::Refresh => b"nocterm/cloud-runner-refresh/v1",
        }
    }
}

pub struct RunnerProofClaim {
    subject: RunnerProofSubject,
    kind: RunnerProofKind,
    token: Zeroizing<String>,
    nonce: [u8; 16],
    signed_at_ms: i64,
}
impl RunnerProofClaim {
    pub fn new(
        subject: RunnerProofSubject,
        kind: RunnerProofKind,
        token: Zeroizing<String>,
        nonce: [u8; 16],
        signed_at_ms: i64,
    ) -> Result<Self, RunnerProofError> {
        if token.is_empty() || token.len() > MAX_RUNNER_TOKEN_BYTES {
            return Err(RunnerProofError::TokenLength);
        }
        Ok(Self {
            subject,
            kind,
            token,
            nonce,
            signed_at_ms,
        })
    }
    pub fn subject(&self) -> &RunnerProofSubject {
        &self.subject
    }
    pub fn kind(&self) -> RunnerProofKind {
        self.kind
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    pub fn signed_at_ms(&self) -> i64 {
        self.signed_at_ms
    }
    /// Contains a bearer secret; keep the zeroizing buffer out of diagnostics/storage.
    pub fn canonical_bytes(&self) -> Result<Zeroizing<Vec<u8>>, RunnerProofError> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(640));
        codec::field(&mut bytes, self.kind.label())?;
        codec::field(&mut bytes, self.subject.raw_hub_id.as_str().as_bytes())?;
        codec::field(
            &mut bytes,
            self.subject.namespace.hub_instance_id.as_str().as_bytes(),
        )?;
        codec::field(
            &mut bytes,
            self.subject.namespace.account_id.as_str().as_bytes(),
        )?;
        bytes.extend_from_slice(&self.subject.runner_id);
        bytes.extend_from_slice(&self.subject.proof_key);
        codec::field(&mut bytes, self.token.as_bytes())?;
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.signed_at_ms.to_be_bytes());
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RunnerProofError> {
        if bytes.len() > MAX_RUNNER_PROOF_BYTES {
            return Err(RunnerProofError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        let kind = match reader.field(64)? {
            b"nocterm/cloud-runner-redeem/v1" => RunnerProofKind::Redeem,
            b"nocterm/cloud-runner-refresh/v1" => RunnerProofKind::Refresh,
            _ => return Err(RunnerProofError::Malformed),
        };
        let subject = RunnerProofSubject {
            raw_hub_id: reader.text()?,
            namespace: CloudNamespace {
                hub_instance_id: reader.text()?,
                account_id: reader.text()?,
            },
            runner_id: reader.array()?,
            proof_key: reader.array()?,
        };
        let token = core::str::from_utf8(reader.field(MAX_RUNNER_TOKEN_BYTES)?)
            .map_err(|_| RunnerProofError::Malformed)?;
        let token = Zeroizing::new(token.to_owned());
        let nonce = reader.array()?;
        let signed_at_ms = i64::from_be_bytes(reader.array()?);
        reader.finish()?;
        Self::new(subject, kind, token, nonce, signed_at_ms)
    }
    /// Time checking and signature checking do not consume the durable one-use nonce/ticket.
    pub fn verify(
        &self,
        expected_kind: RunnerProofKind,
        expected: &RunnerProofSubject,
        signature: &[u8; 64],
        now_ms: i64,
    ) -> Result<(), RunnerProofError> {
        if self.kind != expected_kind {
            return Err(RunnerProofError::Purpose);
        }
        if &self.subject != expected {
            return Err(RunnerProofError::Subject);
        }
        if self.signed_at_ms.abs_diff(now_ms) > PROOF_WINDOW_MS {
            return Err(RunnerProofError::Time);
        }
        pop::verify(&expected.proof_key, &self.canonical_bytes()?, signature)?;
        Ok(())
    }
}
impl fmt::Debug for RunnerProofClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerProofClaim")
            .field("subject", &self.subject)
            .field("kind", &self.kind)
            .field("signed_at_ms", &self.signed_at_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RunnerProofError {
    #[error("malformed or unsupported runner proof")]
    Malformed,
    #[error("runner ticket/token length is invalid")]
    TokenLength,
    #[error("runner proof names another account, hub, runner or key")]
    Subject,
    #[error("runner proof belongs to another operation")]
    Purpose,
    #[error("runner proof is outside its allowed clock window")]
    Time,
    #[error("runner proof signature is invalid")]
    Signature(#[from] SignatureError),
    #[error("runner proof framing is invalid")]
    Framing(#[from] CommandError),
}
