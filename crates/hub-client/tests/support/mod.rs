//! A fake hub on a loopback port: just enough of the auth, vault and relay services to drive
//! the client the way a real hub would, and to record what the client sent.

#![allow(clippy::expect_used, dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use nocterm_hub_client::{DeviceInfo, HubClient, HubEndpoint, Session};
use nocterm_hub_grpc::auth_service_server::{AuthService, AuthServiceServer};
use nocterm_hub_grpc::metadata;
use nocterm_hub_grpc::relay_service_server::{RelayService, RelayServiceServer};
use nocterm_hub_grpc::vault_service_server::{VaultService, VaultServiceServer};
use nocterm_hub_model::PROTOCOL_VERSION;
use nocterm_hub_proto::v2::{self, ErrorCode, relay_down, relay_up};
use nocterm_keys::DeviceKey;
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

pub const HUB_ID: &str = "hub-test";
/// The web panel URL the fake hub states in `HubInfo.web_url`.
pub const WEB_URL: &str = "https://hub.test/panel/";

type Reply<T> = Result<Response<T>, Status>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the fake hub has been asked to do.
#[derive(Default)]
pub struct Seen {
    pub password_logins: Mutex<Vec<v2::PasswordLoginRequest>>,
    pub setups: Mutex<Vec<v2::SetupRequest>>,
    pub invites: Mutex<Vec<v2::RedeemInviteRequest>>,
    pub keyset: Mutex<Option<v2::Keyset>>,
    /// Sizes of the data frames the relay received, in order.
    pub relayed_frame_sizes: Mutex<Vec<usize>>,
    /// The `open` frames of relays, in order.
    pub relay_opens: Mutex<Vec<v2::RelayOpen>>,
    /// How each relay's request stream ended, in order.
    pub relay_ends: Mutex<Vec<RelayEnd>>,
    relay_ended: Notify,
    store_control: StoreControl,
}

/// How the caller ended a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    /// With a `close` frame: a half-close.
    Closed,
    /// The request stream ended without `close`: an abort.
    Aborted,
}

#[derive(Default)]
struct StoreControl {
    hold: std::sync::atomic::AtomicBool,
    entered: Notify,
    release: Notify,
}
impl Seen {
    pub fn hold_keyset_reply(&self) {
        self.store_control
            .hold
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub async fn wait_keyset_request(&self) {
        self.store_control.entered.notified().await;
    }
    pub fn release_keyset_reply(&self) {
        self.store_control
            .hold
            .store(false, std::sync::atomic::Ordering::Release);
        self.store_control.release.notify_one();
    }
    pub fn password_logins(&self) -> Vec<v2::PasswordLoginRequest> {
        lock(&self.password_logins).clone()
    }
    pub fn setups(&self) -> Vec<v2::SetupRequest> {
        lock(&self.setups).clone()
    }
    pub fn invites(&self) -> Vec<v2::RedeemInviteRequest> {
        lock(&self.invites).clone()
    }
    pub fn keyset(&self) -> Option<v2::Keyset> {
        lock(&self.keyset).clone()
    }
    pub fn relayed_frame_sizes(&self) -> Vec<usize> {
        lock(&self.relayed_frame_sizes).clone()
    }
    pub fn relay_opens(&self) -> Vec<v2::RelayOpen> {
        lock(&self.relay_opens).clone()
    }

    /// Waits for the first relay to end and says how.
    pub async fn first_relay_end(&self) -> RelayEnd {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(end) = lock(&self.relay_ends).first().copied() {
                    return end;
                }
                self.relay_ended.notified().await;
            }
        })
        .await
        .expect("the relay ended")
    }

    fn relay_ended(&self, end: RelayEnd) {
        lock(&self.relay_ends).push(end);
        self.relay_ended.notify_one();
    }
}

struct Auth(Arc<Seen>);

fn grant(name: &str) -> Response<v2::LoginGrant> {
    Response::new(v2::LoginGrant {
        grant: name.to_owned(),
        expires_at_ms: i64::MAX,
    })
}

#[tonic::async_trait]
impl AuthService for Auth {
    async fn get_hub_info(&self, _: Request<v2::Empty>) -> Reply<v2::HubInfo> {
        Ok(Response::new(v2::HubInfo {
            hub_id: HUB_ID.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            password_login: true,
            web_url: WEB_URL.to_owned(),
            ..v2::HubInfo::default()
        }))
    }

    async fn setup(&self, request: Request<v2::SetupRequest>) -> Reply<v2::LoginGrant> {
        lock(&self.0.setups).push(request.into_inner());
        Ok(grant("setup-grant"))
    }

    async fn password_login(
        &self,
        request: Request<v2::PasswordLoginRequest>,
    ) -> Reply<v2::LoginGrant> {
        lock(&self.0.password_logins).push(request.into_inner());
        Ok(grant("login-grant"))
    }

    async fn redeem_invite(
        &self,
        request: Request<v2::RedeemInviteRequest>,
    ) -> Reply<v2::LoginGrant> {
        lock(&self.0.invites).push(request.into_inner());
        Ok(grant("invite-grant"))
    }

    async fn start_oidc_login(
        &self,
        _: Request<v2::StartOidcLoginRequest>,
    ) -> Reply<v2::StartOidcLoginResponse> {
        Err(Status::unimplemented("oidc"))
    }

    async fn complete_login(&self, _: Request<v2::CompleteLoginRequest>) -> Reply<v2::Tokens> {
        Ok(Response::new(v2::Tokens {
            access_token: "access".into(),
            access_expires_at_ms: i64::MAX,
            refresh_token: "refresh".into(),
            refresh_expires_at_ms: i64::MAX,
            account_id: "acc-1".into(),
            device_id: "dev-1".into(),
        }))
    }

    async fn refresh(&self, _: Request<v2::RefreshRequest>) -> Reply<v2::Tokens> {
        Err(Status::unimplemented("refresh"))
    }
}

struct Store(Arc<Seen>);

fn conflict(current: u64) -> Status {
    let mut status = Status::aborted("the keyset moved");
    status.metadata_mut().insert(
        metadata::ERROR_CODE,
        ErrorCode::Conflict.as_str_name().parse().expect("ascii"),
    );
    status.metadata_mut().insert(
        metadata::CURRENT_VERSION,
        current.to_string().parse().expect("ascii"),
    );
    status
}

fn no<T>() -> Reply<T> {
    Err(Status::unimplemented("not part of this test"))
}

#[tonic::async_trait]
impl VaultService for Store {
    type WatchChangesStream = Pin<Box<dyn Stream<Item = Result<v2::ChangeHint, Status>> + Send>>;

    async fn get_keyset(&self, _: Request<v2::Empty>) -> Reply<v2::Keyset> {
        if self
            .0
            .store_control
            .hold
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let released = self.0.store_control.release.notified();
            self.0.store_control.entered.notify_one();
            released.await;
        }
        lock(&self.0.keyset)
            .clone()
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no keyset yet"))
    }

    async fn put_keyset(&self, request: Request<v2::PutKeysetRequest>) -> Reply<v2::Keyset> {
        let r = request.into_inner();
        let mut slot = lock(&self.0.keyset);
        let current = slot.as_ref().map_or(0, |k| k.version);
        if r.expected_version != current {
            return Err(conflict(current));
        }
        let stored = v2::Keyset {
            version: current + 1,
            kdf: r.kdf,
            salt: r.salt,
            wrapped_account_key: r.wrapped_account_key,
            updated_at_ms: 0,
            recovery_wrapped_account_key: r.recovery_wrapped_account_key,
            unlock_kind: r.unlock_kind,
        };
        *slot = Some(stored.clone());
        Ok(Response::new(stored))
    }

    async fn create_collection(
        &self,
        _: Request<v2::CreateCollectionRequest>,
    ) -> Reply<v2::Collection> {
        no()
    }
    async fn list_collections(
        &self,
        _: Request<v2::ListCollectionsRequest>,
    ) -> Reply<v2::CollectionList> {
        no()
    }
    async fn delete_collection(&self, _: Request<v2::IdRequest>) -> Reply<v2::Collection> {
        no()
    }
    async fn get_collection_key(&self, _: Request<v2::IdRequest>) -> Reply<v2::CollectionKey> {
        no()
    }
    async fn put_object(&self, _: Request<v2::PutObjectRequest>) -> Reply<v2::ObjectVersion> {
        no()
    }
    async fn delete_object(&self, _: Request<v2::DeleteObjectRequest>) -> Reply<v2::ObjectVersion> {
        no()
    }
    async fn get_object(&self, _: Request<v2::GetObjectRequest>) -> Reply<v2::StoredObject> {
        no()
    }
    async fn list_changes(&self, _: Request<v2::ListChangesRequest>) -> Reply<v2::ChangeBatch> {
        no()
    }
    async fn watch_changes(
        &self,
        _: Request<v2::WatchChangesRequest>,
    ) -> Reply<Self::WatchChangesStream> {
        no()
    }
}

/// Echoes data back. Targets by name: `denied.test` is refused with `RELAY_DENIED`;
/// `stall.test` is opened and then never read; `empty.test` answers with empty data frames
/// around `x` and closes; `hangup.test` is opened and closed at once. After the caller
/// half-closes an echo target, it says `bye` and ends the stream.
struct Relay(Arc<Seen>);

#[allow(clippy::unnecessary_wraps)]
fn down(frame: relay_down::Frame) -> Result<v2::RelayDown, Status> {
    Ok(v2::RelayDown { frame: Some(frame) })
}

fn data(bytes: &[u8]) -> Result<v2::RelayDown, Status> {
    down(relay_down::Frame::Data(bytes.to_vec()))
}

fn closed() -> Result<v2::RelayDown, Status> {
    down(relay_down::Frame::Closed(v2::RelayClosed::default()))
}

#[tonic::async_trait]
impl RelayService for Relay {
    type OpenStream = ReceiverStream<Result<v2::RelayDown, Status>>;

    async fn open(&self, request: Request<Streaming<v2::RelayUp>>) -> Reply<Self::OpenStream> {
        let mut up = request.into_inner();
        let Some(v2::RelayUp {
            frame: Some(relay_up::Frame::Open(open)),
        }) = up.message().await?
        else {
            return Err(Status::invalid_argument("the first frame must be open"));
        };
        lock(&self.0.relay_opens).push(open.clone());
        let (tx, rx) = mpsc::channel(16);
        let seen = Arc::clone(&self.0);
        tokio::spawn(async move {
            if open.host == "denied.test" {
                let _ = tx
                    .send(down(relay_down::Frame::Closed(v2::RelayClosed {
                        code: ErrorCode::RelayDenied.into(),
                        message: "the target is not allowed".into(),
                    })))
                    .await;
                return;
            }
            let opened = v2::RelayOpened {
                peer_ip: "192.0.2.7".into(),
            };
            let _ = tx.send(down(relay_down::Frame::Opened(opened))).await;
            match open.host.as_str() {
                "stall.test" => std::future::pending::<()>().await,
                "empty.test" => {
                    for frame in [data(b""), data(b"x"), data(b""), closed()] {
                        let _ = tx.send(frame).await;
                    }
                    return;
                }
                "hangup.test" => {
                    let _ = tx.send(closed()).await;
                    return;
                }
                _ => {}
            }
            while let Some(Ok(frame)) = up.next().await {
                match frame.frame {
                    Some(relay_up::Frame::Data(bytes)) => {
                        lock(&seen.relayed_frame_sizes).push(bytes.len());
                        let _ = tx.send(data(&bytes)).await;
                    }
                    Some(relay_up::Frame::Close(_)) => {
                        seen.relay_ended(RelayEnd::Closed);
                        let _ = tx.send(data(b"bye")).await;
                        let _ = tx.send(closed()).await;
                        return;
                    }
                    _ => {}
                }
            }
            seen.relay_ended(RelayEnd::Aborted);
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// A running fake hub; it stops when dropped.
pub struct FakeHub {
    pub seen: Arc<Seen>,
    addr: SocketAddr,
    _stop: oneshot::Sender<()>,
}

impl FakeHub {
    /// A hub with the auth and vault services, and the relay service when `relay` is set (one
    /// without it answers `UNIMPLEMENTED`).
    pub async fn start(relay: bool) -> Self {
        let seen = Arc::new(Seen::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let (stop, stopped) = oneshot::channel::<()>();
        let relay_service = relay.then(|| RelayServiceServer::new(Relay(Arc::clone(&seen))));
        let router = Server::builder()
            .add_service(AuthServiceServer::new(Auth(Arc::clone(&seen))))
            .add_service(VaultServiceServer::new(Store(Arc::clone(&seen))))
            .add_optional_service(relay_service);
        tokio::spawn(async move {
            let _ = router
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = stopped.await;
                })
                .await;
        });
        Self {
            seen,
            addr,
            _stop: stop,
        }
    }

    pub fn endpoint(&self) -> HubEndpoint {
        HubEndpoint::new(&format!("http://{}", self.addr), None).expect("endpoint")
    }

    /// A client of this hub that is not signed in.
    pub async fn client(&self) -> HubClient {
        HubClient::connect(&self.endpoint(), DeviceKey::generate().expect("key"), None)
            .await
            .expect("connect")
    }

    /// A client with a session the fake hub accepts.
    pub async fn signed_in_client(&self) -> HubClient {
        let session = Session {
            account_id: "acc-1".into(),
            device_id: "dev-1".into(),
            access_token: "access".into(),
            access_expires_at_ms: i64::MAX,
            refresh_token: "refresh".into(),
            refresh_expires_at_ms: i64::MAX,
        };
        HubClient::connect(
            &self.endpoint(),
            DeviceKey::generate().expect("key"),
            Some(session),
        )
        .await
        .expect("connect")
    }
}

pub fn device() -> DeviceInfo {
    DeviceInfo::new("test host", "tests")
}
