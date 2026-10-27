//! A fake hub on a loopback port: just enough of the auth, store and relay services to drive
//! the client the way a real hub would, and to record what the client sent.

#![allow(clippy::expect_used, dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use nocterm_hub_client::{DeviceInfo, HubClient, HubEndpoint, Session};
use nocterm_hub_grpc::auth_service_server::{AuthService, AuthServiceServer};
use nocterm_hub_grpc::metadata;
use nocterm_hub_grpc::relay_service_server::{RelayService, RelayServiceServer};
use nocterm_hub_grpc::store_service_server::{StoreService, StoreServiceServer};
use nocterm_hub_model::PROTOCOL_VERSION;
use nocterm_hub_proto::v1::{self, ErrorCode, relay_down, relay_up};
use nocterm_keys::DeviceKey;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

pub const HUB_ID: &str = "hub-test";

type Reply<T> = Result<Response<T>, Status>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the fake hub has been asked to do.
#[derive(Default)]
pub struct Seen {
    pub password_logins: Mutex<Vec<v1::PasswordLoginRequest>>,
    pub bootstraps: Mutex<Vec<v1::BootstrapRequest>>,
    pub invites: Mutex<Vec<v1::RedeemInviteRequest>>,
    pub keyset: Mutex<Option<v1::AccountKeyset>>,
    pub grants: Mutex<Vec<v1::GrantCollectionKeyRequest>>,
    /// Sizes of the data frames the relay received, in order.
    pub relayed_frame_sizes: Mutex<Vec<usize>>,
}

impl Seen {
    pub fn password_logins(&self) -> Vec<v1::PasswordLoginRequest> {
        lock(&self.password_logins).clone()
    }
    pub fn bootstraps(&self) -> Vec<v1::BootstrapRequest> {
        lock(&self.bootstraps).clone()
    }
    pub fn invites(&self) -> Vec<v1::RedeemInviteRequest> {
        lock(&self.invites).clone()
    }
    pub fn keyset(&self) -> Option<v1::AccountKeyset> {
        lock(&self.keyset).clone()
    }
    pub fn grants(&self) -> Vec<v1::GrantCollectionKeyRequest> {
        lock(&self.grants).clone()
    }
    pub fn relayed_frame_sizes(&self) -> Vec<usize> {
        lock(&self.relayed_frame_sizes).clone()
    }
}

struct Auth(Arc<Seen>);

fn grant(name: &str) -> Response<v1::LoginGrant> {
    Response::new(v1::LoginGrant {
        grant: name.to_owned(),
        expires_at_ms: i64::MAX,
    })
}

#[tonic::async_trait]
impl AuthService for Auth {
    async fn get_hub_info(&self, _: Request<v1::Empty>) -> Reply<v1::HubInfo> {
        Ok(Response::new(v1::HubInfo {
            hub_id: HUB_ID.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            bootstrapped: true,
            password_login: true,
            ..v1::HubInfo::default()
        }))
    }

    async fn bootstrap(&self, request: Request<v1::BootstrapRequest>) -> Reply<v1::LoginGrant> {
        lock(&self.0.bootstraps).push(request.into_inner());
        Ok(grant("bootstrap-grant"))
    }

    async fn password_login(
        &self,
        request: Request<v1::PasswordLoginRequest>,
    ) -> Reply<v1::LoginGrant> {
        lock(&self.0.password_logins).push(request.into_inner());
        Ok(grant("login-grant"))
    }

    async fn redeem_invite(
        &self,
        request: Request<v1::RedeemInviteRequest>,
    ) -> Reply<v1::LoginGrant> {
        lock(&self.0.invites).push(request.into_inner());
        Ok(grant("invite-grant"))
    }

    async fn start_oidc_login(
        &self,
        _: Request<v1::StartOidcLoginRequest>,
    ) -> Reply<v1::StartOidcLoginResponse> {
        Err(Status::unimplemented("oidc"))
    }

    async fn complete_login(&self, _: Request<v1::CompleteLoginRequest>) -> Reply<v1::Tokens> {
        Ok(Response::new(v1::Tokens {
            access_token: "access".into(),
            access_expires_at_ms: i64::MAX,
            refresh_token: "refresh".into(),
            refresh_expires_at_ms: i64::MAX,
            account_id: "acc-1".into(),
            device_id: "dev-1".into(),
        }))
    }

    async fn refresh(&self, _: Request<v1::RefreshRequest>) -> Reply<v1::Tokens> {
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
impl StoreService for Store {
    type WatchChangesStream = Pin<Box<dyn Stream<Item = Result<v1::ChangeHint, Status>> + Send>>;

    async fn get_account_keyset(
        &self,
        _: Request<v1::GetAccountKeysetRequest>,
    ) -> Reply<v1::AccountKeyset> {
        lock(&self.0.keyset)
            .clone()
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no keyset yet"))
    }

    async fn put_account_keyset(
        &self,
        request: Request<v1::PutAccountKeysetRequest>,
    ) -> Reply<v1::AccountKeyset> {
        let r = request.into_inner();
        let mut slot = lock(&self.0.keyset);
        let current = slot.as_ref().map_or(0, |k| k.version);
        if r.expected_version != current {
            return Err(conflict(current));
        }
        let stored = v1::AccountKeyset {
            version: current + 1,
            kdf: r.kdf,
            salt: r.salt,
            wrapped_account_key: r.wrapped_account_key,
            updated_at_ms: 0,
            public_key: r.public_key,
            sealed_private_key: r.sealed_private_key,
            recovery_wrapped_account_key: r.recovery_wrapped_account_key,
            unlock_kind: r.unlock_kind,
        };
        *slot = Some(stored.clone());
        Ok(Response::new(stored))
    }

    async fn grant_collection_key(
        &self,
        request: Request<v1::GrantCollectionKeyRequest>,
    ) -> Reply<v1::Empty> {
        lock(&self.0.grants).push(request.into_inner());
        Ok(Response::new(v1::Empty {}))
    }

    async fn create_collection(
        &self,
        _: Request<v1::CreateCollectionRequest>,
    ) -> Reply<v1::Collection> {
        no()
    }
    async fn list_collections(
        &self,
        _: Request<v1::ListCollectionsRequest>,
    ) -> Reply<v1::CollectionList> {
        no()
    }
    async fn delete_collection(
        &self,
        _: Request<v1::DeleteCollectionRequest>,
    ) -> Reply<v1::Collection> {
        no()
    }
    async fn get_collection_key(
        &self,
        _: Request<v1::GetCollectionKeyRequest>,
    ) -> Reply<v1::CollectionKey> {
        no()
    }
    async fn list_collection_members(
        &self,
        _: Request<v1::ListCollectionMembersRequest>,
    ) -> Reply<v1::CollectionMemberList> {
        no()
    }
    async fn put_object(&self, _: Request<v1::PutObjectRequest>) -> Reply<v1::ObjectVersion> {
        no()
    }
    async fn delete_object(&self, _: Request<v1::DeleteObjectRequest>) -> Reply<v1::ObjectVersion> {
        no()
    }
    async fn get_object(&self, _: Request<v1::GetObjectRequest>) -> Reply<v1::StoredObject> {
        no()
    }
    async fn list_changes(&self, _: Request<v1::ListChangesRequest>) -> Reply<v1::ChangeBatch> {
        no()
    }
    async fn watch_changes(
        &self,
        _: Request<v1::WatchChangesRequest>,
    ) -> Reply<Self::WatchChangesStream> {
        no()
    }
}

/// Echoes data back. A target named `denied.test` is refused with `RELAY_DENIED`; after the
/// caller half-closes, the target says `bye` and ends the stream.
struct Relay(Arc<Seen>);

#[allow(clippy::unnecessary_wraps)]
fn down(frame: relay_down::Frame) -> Result<v1::RelayDown, Status> {
    Ok(v1::RelayDown { frame: Some(frame) })
}

#[tonic::async_trait]
impl RelayService for Relay {
    type OpenStream = ReceiverStream<Result<v1::RelayDown, Status>>;

    async fn open(&self, request: Request<Streaming<v1::RelayUp>>) -> Reply<Self::OpenStream> {
        let mut up = request.into_inner();
        let Some(v1::RelayUp {
            frame: Some(relay_up::Frame::Open(open)),
        }) = up.message().await?
        else {
            return Err(Status::invalid_argument("the first frame must be open"));
        };
        let (tx, rx) = mpsc::channel(16);
        let seen = Arc::clone(&self.0);
        tokio::spawn(async move {
            if open.host == "denied.test" {
                let _ = tx
                    .send(down(relay_down::Frame::Closed(v1::RelayClosed {
                        code: ErrorCode::RelayDenied.into(),
                        message: "the target is not allowed".into(),
                    })))
                    .await;
                return;
            }
            let opened = v1::RelayOpened {
                peer_ip: "192.0.2.7".into(),
            };
            let _ = tx.send(down(relay_down::Frame::Opened(opened))).await;
            while let Some(Ok(frame)) = up.next().await {
                match frame.frame {
                    Some(relay_up::Frame::Data(data)) => {
                        lock(&seen.relayed_frame_sizes).push(data.len());
                        let _ = tx.send(down(relay_down::Frame::Data(data))).await;
                    }
                    Some(relay_up::Frame::Close(_)) => {
                        let _ = tx
                            .send(down(relay_down::Frame::Data(b"bye".to_vec())))
                            .await;
                        let closed = relay_down::Frame::Closed(v1::RelayClosed::default());
                        let _ = tx.send(down(closed)).await;
                        return;
                    }
                    _ => {}
                }
            }
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
    /// A hub with the auth and store services, and the relay service when `relay` is set (one
    /// without it answers `UNIMPLEMENTED`, like an older hub).
    pub async fn start(relay: bool) -> Self {
        let seen = Arc::new(Seen::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let (stop, stopped) = oneshot::channel::<()>();
        let server = Server::builder()
            .add_service(AuthServiceServer::new(Auth(Arc::clone(&seen))))
            .add_service(StoreServiceServer::new(Store(Arc::clone(&seen))));
        let relay_service = relay.then(|| RelayServiceServer::new(Relay(Arc::clone(&seen))));
        let router = server.add_optional_service(relay_service);
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
