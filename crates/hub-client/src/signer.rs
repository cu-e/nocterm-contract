//! Signs every authenticated call with the device key (proof of possession).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use nocterm_hub_grpc::{metadata, method_path};
use nocterm_hub_model::pop::request_message;
use nocterm_keys::{DeviceKey, KeyError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::metadata::{AsciiMetadataValue, BinaryMetadataValue};
use tonic::service::Interceptor;
use tonic::{GrpcMethod, Request, Status};

use crate::store::SessionStore;

/// Tokens of a signed-in device; persist them next to the device key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub account_id: String,
    pub device_id: String,
    pub access_token: String,
    pub access_expires_at_ms: i64,
    pub refresh_token: String,
    pub refresh_expires_at_ms: i64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("access_expires_at_ms", &self.access_expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl From<nocterm_hub_proto::v1::Tokens> for Session {
    fn from(tokens: nocterm_hub_proto::v1::Tokens) -> Self {
        Self {
            account_id: tokens.account_id,
            device_id: tokens.device_id,
            access_token: tokens.access_token,
            access_expires_at_ms: tokens.access_expires_at_ms,
            refresh_token: tokens.refresh_token,
            refresh_expires_at_ms: tokens.refresh_expires_at_ms,
        }
    }
}

/// Unix time in milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// A fresh single-use nonce.
pub(crate) fn nonce() -> Result<String, KeyError> {
    nocterm_keys::random_bytes::<16>().map(hex::encode)
}

/// Device key, hub identity and current tokens shared by every client of one hub.
#[derive(Debug)]
pub(crate) struct Credentials {
    pub(crate) hub_id: String,
    pub(crate) key: DeviceKey,
    session: RwLock<Option<Session>>,
    generation: AtomicU64,
    /// Refreshes of this process take turns: a refresh token is single-use.
    pub(crate) refreshing: tokio::sync::Mutex<()>,
    store: OnceLock<Arc<dyn SessionStore>>,
}

impl Credentials {
    pub(crate) fn new(hub_id: String, key: DeviceKey, session: Option<Session>) -> Self {
        Self {
            hub_id,
            key,
            session: RwLock::new(session),
            generation: AtomicU64::new(1),
            refreshing: tokio::sync::Mutex::new(()),
            store: OnceLock::new(),
        }
    }

    /// Persists rotations through `store`; the first store set wins.
    pub(crate) fn set_store(&self, store: Arc<dyn SessionStore>) {
        let _ = self.store.set(store);
    }

    pub(crate) fn store(&self) -> Option<&Arc<dyn SessionStore>> {
        self.store.get()
    }

    pub(crate) fn session(&self) -> Option<Session> {
        self.session
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set_session(&self, session: Option<Session>) {
        let mut current = self.session.write().unwrap_or_else(PoisonError::into_inner);
        let advanced = self
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            });
        *current = if advanced.is_ok() { session } else { None };
    }

    pub(crate) fn snapshot(&self) -> Option<(u64, Session)> {
        let session = self.session.read().unwrap_or_else(PoisonError::into_inner);
        Some((self.generation.load(Ordering::Acquire), session.clone()?))
    }

    /// Refresh is conditional on the original login, even if an account later logs in again.
    pub(crate) fn rotate_session(&self, generation: u64, session: Session) -> bool {
        let mut current = self.session.write().unwrap_or_else(PoisonError::into_inner);
        if self.generation.load(Ordering::Acquire) != generation
            || !current.as_ref().is_some_and(|old| {
                old.account_id == session.account_id && old.device_id == session.device_id
            })
        {
            return false;
        }
        *current = Some(session);
        true
    }

    pub(crate) fn capture(&self) -> Option<CredentialCapture> {
        let session = self.session.read().unwrap_or_else(PoisonError::into_inner);
        let session = session.as_ref()?;
        Some(self.capture_session(session))
    }

    /// Bounded Cloud attribution before any account/device clone, using the same
    /// lock for source, metadata bounds and the captured actual session values.
    pub(crate) fn capture_cloud(&self, generation: u64) -> Result<CredentialCapture, Status> {
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        if self.generation.load(Ordering::Acquire) != generation {
            return Err(Status::unauthenticated(
                "the original account sign-in was replaced",
            ));
        }
        let session = current
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("not signed in"))?;
        self.cloud_metadata(session)?;
        if session.account_id.is_empty() || session.account_id.len() > 128 {
            return Err(Status::resource_exhausted(
                "Cloud account identity exceeds its bound",
            ));
        }
        Ok(self.capture_session(session))
    }

    fn capture_session(&self, session: &Session) -> CredentialCapture {
        CredentialCapture {
            generation: self.generation.load(Ordering::Acquire),
            account_id: session.account_id.clone(),
            device_id: session.device_id.clone(),
            signing_key: self.key.public_key(),
            access_digest: Sha256::digest(session.access_token.as_bytes()).into(),
            refresh_expires_at_ms: session.refresh_expires_at_ms,
        }
    }

    pub(crate) fn require_generation(&self, generation: u64) -> Result<(), Status> {
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        if current.is_none() || self.generation.load(Ordering::Acquire) != generation {
            return Err(Status::unauthenticated(
                "the original account sign-in was replaced",
            ));
        }
        Ok(())
    }

    /// `(token, device, nonce, ts, signature)` for a request to `path`.
    pub(crate) fn sign(
        &self,
        path: &str,
    ) -> Result<(String, String, String, i64, [u8; 64]), Status> {
        self.sign_scoped(path, None)
    }

    pub(crate) fn sign_scoped(
        &self,
        path: &str,
        generation: Option<u64>,
    ) -> Result<(String, String, String, i64, [u8; 64]), Status> {
        self.sign_scoped_inner(path, generation, false)
    }
    pub(crate) fn sign_scoped_bounded(
        &self,
        path: &str,
        generation: Option<u64>,
    ) -> Result<(String, String, String, i64, [u8; 64]), Status> {
        self.sign_scoped_inner(path, generation, true)
    }
    pub(crate) fn require_cloud_metadata(&self, generation: u64) -> Result<(), Status> {
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        if self.generation.load(Ordering::Acquire) != generation {
            return Err(Status::unauthenticated(
                "the original account sign-in was replaced",
            ));
        }
        self.cloud_metadata(
            current
                .as_ref()
                .ok_or_else(|| Status::unauthenticated("not signed in"))?,
        )
    }
    fn cloud_metadata(&self, session: &Session) -> Result<(), Status> {
        if session.access_token.is_empty()
            || self.hub_id.is_empty()
            || session.device_id.is_empty()
            || session.access_token.len() > 1024
            || self.hub_id.len() > 128
            || session.device_id.len() > 128
        {
            return Err(Status::resource_exhausted(
                "Cloud authentication metadata exceeds its bound",
            ));
        }
        Ok(())
    }
    fn sign_scoped_inner(
        &self,
        path: &str,
        generation: Option<u64>,
        bounded: bool,
    ) -> Result<(String, String, String, i64, [u8; 64]), Status> {
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        if generation.is_some_and(|expected| self.generation.load(Ordering::Acquire) != expected) {
            return Err(Status::unauthenticated(
                "the original account sign-in was replaced",
            ));
        }
        let session = current
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("not signed in"))?;
        // The check and subsequent clone/sign use the same lock: a refresh
        // cannot enlarge the actual input after this bound was checked.
        if bounded {
            self.cloud_metadata(session)?;
        }
        let nonce = nonce().map_err(|_| Status::internal("no randomness"))?;
        let ts = now_ms();
        let signature = self.key.sign(&request_message(
            &self.hub_id,
            path,
            &session.access_token,
            &nonce,
            ts,
        ));
        Ok((
            session.access_token.clone(),
            session.device_id.clone(),
            nonce,
            ts,
            signature,
        ))
    }
}

/// Original attribution is immutable across refresh; it contains no bearer token.
#[derive(Clone, Debug)]
pub(crate) struct CredentialCapture {
    pub(crate) generation: u64,
    pub(crate) account_id: String,
    pub(crate) device_id: String,
    pub(crate) signing_key: [u8; 32],
    pub(crate) access_digest: [u8; 32],
    pub(crate) refresh_expires_at_ms: i64,
}

/// Tonic interceptor adding the device's proof to each call.
#[derive(Debug, Clone)]
pub struct Signer {
    credentials: Arc<Credentials>,
}

impl Signer {
    pub(crate) fn new(credentials: Arc<Credentials>) -> Self {
        Self { credentials }
    }
}

fn ascii(value: String) -> Result<AsciiMetadataValue, Status> {
    AsciiMetadataValue::try_from(value).map_err(|_| Status::internal("invalid metadata"))
}

impl Interceptor for Signer {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let method = request
            .extensions()
            .get::<GrpcMethod>()
            .ok_or_else(|| Status::internal("unknown method"))?;
        let path = method_path(method.service(), method.method());
        let (token, device, nonce, ts, signature) = self.credentials.sign(&path)?;
        let headers = request.metadata_mut();
        headers.insert(metadata::AUTHORIZATION, ascii(format!("Bearer {token}"))?);
        headers.insert(metadata::DEVICE, ascii(device)?);
        headers.insert(metadata::NONCE, ascii(nonce)?);
        headers.insert(metadata::SIGNED_AT, ascii(ts.to_string())?);
        headers.insert_bin(metadata::PROOF, BinaryMetadataValue::from_bytes(&signature));
        Ok(request)
    }
}

#[cfg(test)]
mod tests;
