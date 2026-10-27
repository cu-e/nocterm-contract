//! Signs every authenticated call with the device key (proof of possession).

use std::sync::{Arc, OnceLock, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use nocterm_hub_grpc::{metadata, method_path};
use nocterm_hub_model::pop::request_message;
use nocterm_keys::{DeviceKey, KeyError};
use serde::{Deserialize, Serialize};
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
        *self.session.write().unwrap_or_else(PoisonError::into_inner) = session;
    }

    /// `(token, device, nonce, ts, signature)` for a request to `path`.
    pub(crate) fn sign(
        &self,
        path: &str,
    ) -> Result<(String, String, String, i64, [u8; 64]), Status> {
        let session = self
            .session()
            .ok_or_else(|| Status::unauthenticated("not signed in"))?;
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
            session.access_token,
            session.device_id,
            nonce,
            ts,
            signature,
        ))
    }
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
