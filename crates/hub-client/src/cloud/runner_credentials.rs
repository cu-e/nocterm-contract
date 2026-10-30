//! Runner credentials can sign only the closed Cloud RPC set. No ordinary SDK session.
use super::CloudError;
use nocterm_hub_model::cloud::{
    runner_auth::{RunnerProofClaim, RunnerProofKind, RunnerProofSubject},
    runner_request::{RunnerMethod, RunnerRequestClaim},
};
use nocterm_hub_proto::v1;
use nocterm_keys::{DeviceKey, random_bytes};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{Arc, PoisonError, RwLock},
};
use tonic::{GrpcMethod, Request, Status, service::Interceptor};
use zeroize::Zeroizing;

/// Persist only in the runner's private credential storage. Contains no account key.
pub struct RunnerSession {
    subject: RunnerProofSubject,
    access: Zeroizing<String>,
    access_expires_at_ms: i64,
    refresh: Zeroizing<String>,
    refresh_expires_at_ms: i64,
}
impl RunnerSession {
    pub fn from_response(
        tokens: v1::CloudRunnerTokens,
        subject: &RunnerProofSubject,
    ) -> Result<Self, CloudError> {
        Self::parse(tokens, subject, false)
    }
    /// Restores private runner storage, including an expired access token whose
    /// refresh token is still live. This does not refresh or admit an RPC.
    /// Call `CloudRunner::refresh` explicitly before using expired access.
    pub fn from_stored_response(
        tokens: v1::CloudRunnerTokens,
        subject: &RunnerProofSubject,
    ) -> Result<Self, CloudError> {
        Self::parse(tokens, subject, true)
    }
    fn parse(
        tokens: v1::CloudRunnerTokens,
        subject: &RunnerProofSubject,
        stored: bool,
    ) -> Result<Self, CloudError> {
        let valid_scope = tokens.account_id == subject.namespace.account_id.as_str()
            && tokens.runner_id == subject.runner_id
            && tokens.capability_version == 1;
        let tokens = Self {
            subject: subject.clone(),
            access: Zeroizing::new(tokens.access_token),
            access_expires_at_ms: tokens.access_expires_at_ms,
            refresh: Zeroizing::new(tokens.refresh_token),
            refresh_expires_at_ms: tokens.refresh_expires_at_ms,
        };
        let now = crate::now_ms();
        if !valid_scope
            || tokens.access.is_empty()
            || tokens.refresh.is_empty()
            || tokens.access.len() > 256
            || tokens.refresh.len() > 256
            || tokens.access_expires_at_ms <= 0
            || (!stored && tokens.access_expires_at_ms <= now)
            || tokens.refresh_expires_at_ms <= now
            || tokens.refresh_expires_at_ms < tokens.access_expires_at_ms
        {
            return Err(CloudError::Protocol);
        }
        Ok(tokens)
    }
    pub fn into_response(self) -> v1::CloudRunnerTokens {
        let subject = &self.subject;
        v1::CloudRunnerTokens {
            account_id: subject.namespace.account_id.as_str().to_owned(),
            runner_id: subject.runner_id.to_vec(),
            access_token: self.access.to_string(),
            access_expires_at_ms: self.access_expires_at_ms,
            refresh_token: self.refresh.to_string(),
            refresh_expires_at_ms: self.refresh_expires_at_ms,
            capability_version: 1,
        }
    }
    pub fn access_expires_at_ms(&self) -> i64 {
        self.access_expires_at_ms
    }
    pub fn refresh_expires_at_ms(&self) -> i64 {
        self.refresh_expires_at_ms
    }
}
impl fmt::Debug for RunnerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RunnerSession(…)")
    }
}

pub(super) struct RunnerCredentials {
    subject: RunnerProofSubject,
    key: DeviceKey,
    session: RwLock<Option<RunnerSession>>,
    refreshing: tokio::sync::Mutex<()>,
}
impl RunnerCredentials {
    pub(super) async fn refresh_turn(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.refreshing.lock().await
    }
    pub(super) fn subject(&self) -> &RunnerProofSubject {
        &self.subject
    }
    pub(super) fn new(
        subject: RunnerProofSubject,
        key: DeviceKey,
        session: RunnerSession,
    ) -> Result<Self, CloudError> {
        if key.public_key() != subject.proof_key || session.subject != subject {
            return Err(CloudError::Protocol);
        }
        Ok(Self {
            subject,
            key,
            session: RwLock::new(Some(session)),
            refreshing: tokio::sync::Mutex::new(()),
        })
    }
    pub(super) fn sign_deletion(
        &self,
        tombstone: nocterm_hub_model::cloud::reclaim::ChatDeletionTombstone,
    ) -> Result<super::SignedChatDeletion, nocterm_hub_model::cloud::reclaim::ReclaimError> {
        super::SignedChatDeletion::sign(tombstone, &self.key)
    }
    pub(super) fn check(&self) -> Result<(), CloudError> {
        if self
            .session
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_none_or(|s| s.refresh_expires_at_ms <= crate::now_ms())
        {
            return Err(CloudError::SourceChanged);
        }
        Ok(())
    }
    pub(super) fn deadlines(&self) -> Result<(i64, i64), CloudError> {
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        let session = current.as_ref().ok_or(CloudError::SourceChanged)?;
        if session.refresh_expires_at_ms <= crate::now_ms() {
            return Err(CloudError::SourceChanged);
        }
        Ok((session.access_expires_at_ms, session.refresh_expires_at_ms))
    }
    pub(super) fn revoke(&self) {
        self.session
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
    pub(super) fn refresh_proof(&self) -> Result<(RunnerProofClaim, [u8; 64]), CloudError> {
        self.check()?;
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        let session = current.as_ref().ok_or(CloudError::SourceChanged)?;
        let claim = RunnerProofClaim::new(
            self.subject.clone(),
            RunnerProofKind::Refresh,
            session.refresh.clone(),
            random_bytes::<16>()?,
            crate::now_ms(),
        )?;
        let signature = self.key.sign(&claim.canonical_bytes()?);
        Ok((claim, signature))
    }
    pub(super) fn rotate(
        &self,
        claim: &RunnerProofClaim,
        tokens: v1::CloudRunnerTokens,
    ) -> Result<(), CloudError> {
        let fresh = RunnerSession::from_response(tokens, &self.subject)?;
        let mut current = self.session.write().unwrap_or_else(PoisonError::into_inner);
        let old = current.as_ref().ok_or(CloudError::SourceChanged)?;
        if old.refresh.as_str() != claim.token() || old.refresh_expires_at_ms <= crate::now_ms() {
            return Err(CloudError::SourceChanged);
        }
        *current = Some(fresh);
        Ok(())
    }
    pub(super) fn snapshot(&self) -> Result<RunnerSession, CloudError> {
        self.check()?;
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        let session = current.as_ref().ok_or(CloudError::SourceChanged)?;
        Ok(RunnerSession {
            subject: session.subject.clone(),
            access: session.access.clone(),
            access_expires_at_ms: session.access_expires_at_ms,
            refresh: session.refresh.clone(),
            refresh_expires_at_ms: session.refresh_expires_at_ms,
        })
    }
}
impl fmt::Debug for RunnerCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerCredentials")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub(super) struct RunnerSigner(Arc<RunnerCredentials>);
impl RunnerSigner {
    pub(super) fn new(credentials: Arc<RunnerCredentials>) -> Self {
        Self(credentials)
    }
    pub(super) fn check(&self) -> Result<(), CloudError> {
        self.0.check()
    }
    pub(super) fn subject(&self) -> &RunnerProofSubject {
        self.0.subject()
    }
}
impl Interceptor for RunnerSigner {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let method = request
            .extensions()
            .get::<GrpcMethod>()
            .ok_or_else(|| Status::internal("unknown method"))?;
        let method = RunnerMethod::from_rpc(method.service(), method.method())
            .map_err(|_| Status::permission_denied("runner scope"))?;
        self.0
            .check()
            .map_err(|_| Status::unauthenticated("runner access revoked or expired"))?;
        let current = self
            .0
            .session
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let session = current
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("runner revoked"))?;
        if session.access_expires_at_ms <= crate::now_ms() {
            return Err(Status::unauthenticated("runner access expired"));
        }
        let claim = RunnerRequestClaim::new(
            self.0.subject.clone(),
            method,
            Sha256::digest(session.access.as_bytes()).into(),
            random_bytes::<16>().map_err(|_| Status::internal("randomness"))?,
            crate::now_ms(),
        );
        let canonical = claim
            .canonical_bytes()
            .map_err(|_| Status::internal("runner claim"))?;
        let signature = self.0.key.sign(&canonical);
        let mut authorization: tonic::metadata::AsciiMetadataValue =
            format!("Bearer {}", session.access.as_str())
                .parse()
                .map_err(|_| Status::internal("invalid runner token"))?;
        authorization.set_sensitive(true);
        let headers = request.metadata_mut();
        headers.insert("authorization", authorization);
        headers.insert_bin(
            "x-nocterm-runner-claim-bin",
            tonic::metadata::BinaryMetadataValue::from_bytes(&canonical),
        );
        headers.insert_bin(
            "x-nocterm-runner-proof-bin",
            tonic::metadata::BinaryMetadataValue::from_bytes(&signature),
        );
        Ok(request)
    }
}
