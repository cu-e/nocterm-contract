//! Signs every authenticated call with the device key (proof of possession).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
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

/// The tokens of one signed-in device.
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

impl From<nocterm_hub_proto::v2::Tokens> for Session {
    fn from(tokens: nocterm_hub_proto::v2::Tokens) -> Self {
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

/// This machine's clock in Unix milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

pub(crate) fn nonce() -> Result<String, KeyError> {
    nocterm_keys::random_bytes::<16>().map(hex::encode)
}

/// The device key, the current session and the hub's clock offset, shared by every service
/// client of one [`crate::HubClient`].
#[derive(Debug)]
pub(crate) struct Credentials {
    pub(crate) hub_id: String,
    pub(crate) key: DeviceKey,
    session: RwLock<Option<Session>>,
    /// Advanced by every sign-in and sign-out, so a refresh started before one is discarded.
    generation: AtomicU64,
    /// The hub's clock minus this machine's, so a skewed clock still signs fresh requests.
    clock_offset_ms: AtomicI64,
    pub(crate) refreshing: tokio::sync::Mutex<()>,
    store: OnceLock<Arc<dyn SessionStore>>,
}

impl Credentials {
    pub(crate) fn new(
        hub_id: String,
        key: DeviceKey,
        session: Option<Session>,
        clock_offset_ms: i64,
    ) -> Self {
        Self {
            hub_id,
            key,
            session: RwLock::new(session),
            generation: AtomicU64::new(1),
            clock_offset_ms: AtomicI64::new(clock_offset_ms),
            refreshing: tokio::sync::Mutex::new(()),
            store: OnceLock::new(),
        }
    }

    /// The hub's time as this client estimates it; every proof is signed with it.
    pub(crate) fn hub_now_ms(&self) -> i64 {
        now_ms().saturating_add(self.clock_offset_ms.load(Ordering::Relaxed))
    }

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
        self.generation.fetch_add(1, Ordering::AcqRel);
        *current = session;
    }

    /// The session with the generation it belongs to.
    pub(crate) fn snapshot(&self) -> Option<(u64, Session)> {
        let session = self.session.read().unwrap_or_else(PoisonError::into_inner);
        Some((self.generation.load(Ordering::Acquire), session.clone()?))
    }

    /// Installs a refreshed session unless a sign-in or sign-out happened since `generation`.
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

    /// Token, device, nonce, time and signature for one call of `path`.
    fn sign(&self, path: &str) -> Result<(String, String, String, i64, [u8; 64]), Status> {
        let current = self.session.read().unwrap_or_else(PoisonError::into_inner);
        let session = current
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("not signed in"))?;
        let nonce = nonce().map_err(|_| Status::internal("no randomness"))?;
        let ts = self.hub_now_ms();
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
mod tests {
    use super::*;

    fn session(account: &str, token: &str) -> Session {
        Session {
            account_id: account.into(),
            device_id: "device".into(),
            access_token: token.into(),
            access_expires_at_ms: 1_000_000,
            refresh_token: format!("refresh-{token}"),
            refresh_expires_at_ms: 2_000_000,
        }
    }

    #[test]
    fn a_refresh_started_before_a_new_sign_in_is_discarded() {
        let credentials = Credentials::new(
            "hub".into(),
            DeviceKey::from_seed(&[7; 32]),
            Some(session("A", "first")),
            0,
        );
        let (generation, _) = credentials.snapshot().unwrap();
        credentials.set_session(Some(session("A", "relogin")));
        assert!(!credentials.rotate_session(generation, session("A", "late")));
        assert_eq!(credentials.session().unwrap().access_token, "relogin");
    }

    #[test]
    fn a_refresh_for_another_account_is_refused() {
        let credentials = Credentials::new(
            "hub".into(),
            DeviceKey::from_seed(&[7; 32]),
            Some(session("A", "first")),
            0,
        );
        let (generation, _) = credentials.snapshot().unwrap();
        assert!(!credentials.rotate_session(generation, session("B", "other")));
        assert!(credentials.rotate_session(generation, session("A", "second")));
    }

    #[test]
    fn proofs_use_the_hubs_clock() {
        let credentials = Credentials::new(
            "hub".into(),
            DeviceKey::from_seed(&[7; 32]),
            Some(session("A", "first")),
            3_600_000,
        );
        let (_, _, _, ts, _) = credentials.sign("/x/y").unwrap();
        assert!(ts - now_ms() >= 3_599_000);
    }
}
