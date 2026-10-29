//! Runner-only request proofs. Their bytes cannot authorize ordinary device services.
use super::{
    codec::{self, Reader},
    runner_auth::{RunnerProofError, RunnerProofSubject},
};
use crate::pop;

/// The complete set of RPCs available to a runner principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerMethod {
    Publish,
    Replay,
    Acknowledge,
    Watch,
    ListStreams,
    Heartbeat,
    Purge,
    NextHeadProbe,
    ReplyHeadProbe,
}
impl RunnerMethod {
    pub fn from_rpc(service: &str, method: &str) -> Result<Self, RunnerProofError> {
        if service != "nocterm.hub.v1.CloudService" {
            return Err(RunnerProofError::Purpose);
        }
        match method {
            "Publish" => Ok(Self::Publish),
            "Replay" => Ok(Self::Replay),
            "Acknowledge" => Ok(Self::Acknowledge),
            "Watch" => Ok(Self::Watch),
            "ListStreams" => Ok(Self::ListStreams),
            "RunnerHeartbeat" => Ok(Self::Heartbeat),
            "Purge" => Ok(Self::Purge),
            "NextHeadProbe" => Ok(Self::NextHeadProbe),
            "ReplyHeadProbe" => Ok(Self::ReplyHeadProbe),
            _ => Err(RunnerProofError::Purpose),
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Publish => "Publish",
            Self::Replay => "Replay",
            Self::Acknowledge => "Acknowledge",
            Self::Watch => "Watch",
            Self::ListStreams => "ListStreams",
            Self::Heartbeat => "RunnerHeartbeat",
            Self::Purge => "Purge",
            Self::NextHeadProbe => "NextHeadProbe",
            Self::ReplyHeadProbe => "ReplyHeadProbe",
        }
    }
}

/// Immutable request attribution. Authentication still consumes a durable nonce and
/// checks the actual current runner token, revocation and runner scope at the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerRequestClaim {
    subject: RunnerProofSubject,
    method: RunnerMethod,
    access_digest: [u8; 32],
    nonce: [u8; 16],
    signed_at_ms: i64,
}
impl RunnerRequestClaim {
    pub fn new(
        subject: RunnerProofSubject,
        method: RunnerMethod,
        access_digest: [u8; 32],
        nonce: [u8; 16],
        signed_at_ms: i64,
    ) -> Self {
        Self {
            subject,
            method,
            access_digest,
            nonce,
            signed_at_ms,
        }
    }
    pub fn subject(&self) -> &RunnerProofSubject {
        &self.subject
    }
    pub fn method(&self) -> RunnerMethod {
        self.method
    }
    pub fn access_digest(&self) -> [u8; 32] {
        self.access_digest
    }
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    pub fn signed_at_ms(&self) -> i64 {
        self.signed_at_ms
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RunnerProofError> {
        let mut bytes = Vec::with_capacity(512);
        codec::field(&mut bytes, b"nocterm/cloud-runner-request/v1")?;
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
        codec::field(&mut bytes, self.method.name().as_bytes())?;
        bytes.extend_from_slice(&self.access_digest);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.signed_at_ms.to_be_bytes());
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RunnerProofError> {
        if bytes.len() > 1024 {
            return Err(RunnerProofError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-runner-request/v1" {
            return Err(RunnerProofError::Malformed);
        }
        let subject = RunnerProofSubject {
            raw_hub_id: reader.text()?,
            namespace: super::CloudNamespace {
                hub_instance_id: reader.text()?,
                account_id: reader.text()?,
            },
            runner_id: reader.array()?,
            proof_key: reader.array()?,
        };
        let method =
            core::str::from_utf8(reader.field(64)?).map_err(|_| RunnerProofError::Malformed)?;
        let method = RunnerMethod::from_rpc("nocterm.hub.v1.CloudService", method)?;
        let claim = Self::new(
            subject,
            method,
            reader.array()?,
            reader.array()?,
            i64::from_be_bytes(reader.array()?),
        );
        reader.finish()?;
        Ok(claim)
    }
    pub fn verify(
        &self,
        subject: &RunnerProofSubject,
        method: RunnerMethod,
        access_digest: &[u8; 32],
        signature: &[u8; 64],
        now_ms: i64,
    ) -> Result<(), RunnerProofError> {
        if &self.subject != subject || &self.access_digest != access_digest {
            return Err(RunnerProofError::Subject);
        }
        if self.method != method {
            return Err(RunnerProofError::Purpose);
        }
        if self.signed_at_ms.abs_diff(now_ms) > 60_000 {
            return Err(RunnerProofError::Time);
        }
        pop::verify(&subject.proof_key, &self.canonical_bytes()?, signature)?;
        Ok(())
    }
}
