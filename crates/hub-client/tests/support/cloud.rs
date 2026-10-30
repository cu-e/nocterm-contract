//! Scripted Cloud peer for actual gRPC framing and backpressure tests.
mod head;
mod retention;
mod runner;
mod status;
use super::{HUB_ID, Reply, lock};
use nocterm_hub_client::now_ms;
use nocterm_hub_grpc::cloud_service_server::{CloudService, CloudServiceServer};
use nocterm_hub_model::cloud::{
    CloudTextId,
    capabilities::{CapabilitiesClaim, CapabilityLimits, CapabilityWindow},
    relay::{PublicationMetadata, PublicationVerifier, RelayBinding},
};
use nocterm_hub_proto::v1::{self, cloud_publish_frame::Frame};
use nocterm_keys::DeviceKey;
use std::{
    fmt,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, mpsc};
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, Streaming};

/// Injected receipt failures.
#[derive(Default)]
struct ReceiptFault {
    hold: bool,
    wrong: bool,
}
#[derive(Default)]
struct State {
    publications: Vec<(PublicationMetadata, Vec<u8>)>,
    frame_sizes: Vec<usize>,
    receipt: ReceiptFault,
    replay: Vec<v1::CloudReplayFrame>,
    hold_upload: bool,
    retention: retention::Retention,
    additional_capabilities: u64,
    oversized_capability_reply: bool,
    max_frame_bytes: Option<u32>,
}
#[derive(Clone)]
pub struct CloudHarness {
    state: Arc<Mutex<State>>,
    published: Arc<Notify>,
    release: Arc<Notify>,
    runner: Arc<runner::RunnerPeer>,
    authority: Arc<DeviceKey>,
    heads: head::HeadLane,
    status: Arc<status::StatusLane>,
}
impl CloudHarness {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            published: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            runner: Arc::new(runner::RunnerPeer::default()),
            authority: Arc::new(DeviceKey::from_seed(&[0x91; 32])),
            heads: head::HeadLane::default(),
            status: Arc::new(status::StatusLane::default()),
        }
    }
    pub fn enable_key_material(&self) {
        lock(&self.state).additional_capabilities |=
            nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_CHAT_KEY_MATERIAL;
    }
    pub fn enable_session_start(&self) {
        lock(&self.state).additional_capabilities |=
            nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_SESSION_START;
    }
    pub fn oversized_capability_reply(&self, enabled: bool) {
        lock(&self.state).oversized_capability_reply = enabled;
    }
    pub fn enable_head_probes(&self) {
        lock(&self.state).additional_capabilities |=
            nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_FRESH_HEAD;
    }
    pub async fn wait_head_probes(&self, count: usize) {
        self.heads.wait_count(count).await;
    }
    pub fn authority(&self) -> [u8; 32] {
        self.authority.public_key()
    }
    pub fn publications(&self) -> Vec<(PublicationMetadata, Vec<u8>)> {
        lock(&self.state).publications.clone()
    }
    pub fn frame_sizes(&self) -> Vec<usize> {
        lock(&self.state).frame_sizes.clone()
    }
    pub fn hold_receipt(&self) {
        lock(&self.state).receipt.hold = true;
    }
    pub fn hold_upload(&self) {
        lock(&self.state).hold_upload = true;
    }
    pub fn set_max_frame_bytes(&self, bytes: u32) {
        lock(&self.state).max_frame_bytes = Some(bytes);
    }
    pub fn wrong_receipt(&self) {
        lock(&self.state).receipt.wrong = true;
    }
    pub fn replay(&self, frames: Vec<v1::CloudReplayFrame>) {
        lock(&self.state).replay = frames;
    }
    pub fn release_receipt(&self) {
        self.release.notify_one();
    }
    pub async fn wait_published(&self) {
        self.published.notified().await;
    }
}
impl fmt::Debug for CloudHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CloudHarness([scripted])")
    }
}
pub fn service(harness: CloudHarness) -> CloudServiceServer<CloudPeer> {
    CloudServiceServer::new(CloudPeer(harness)).max_decoding_message_size(32 * 1024)
}
#[derive(Clone, Debug)]
pub struct CloudPeer(CloudHarness);
impl CloudPeer {
    fn require_heads(&self) -> Result<(), Status> {
        if lock(&self.0.state).additional_capabilities
            & nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_FRESH_HEAD
            == 0
        {
            return Err(Status::unimplemented("fresh head probes"));
        }
        Ok(())
    }
}
type Frames = Pin<Box<dyn Stream<Item = Result<v1::CloudReplayFrame, Status>> + Send>>;
type Hints = Pin<Box<dyn Stream<Item = Result<v1::CloudHint, Status>> + Send>>;

#[tonic::async_trait]
impl CloudService for CloudPeer {
    async fn probe_head(
        &self,
        request: Request<v1::CloudHeadProbe>,
    ) -> Reply<v1::CloudHeadProbeReply> {
        self.require_heads()?;
        if request
            .metadata()
            .contains_key("x-nocterm-runner-claim-bin")
        {
            return Err(Status::permission_denied("device only"));
        }
        if request.metadata().get("authorization").is_none() {
            return Err(Status::unauthenticated("device"));
        }
        Ok(Response::new(
            self.0.heads.submit(request.into_inner()).await?,
        ))
    }
    async fn next_head_probe(
        &self,
        request: Request<v1::CloudNextHeadProbe>,
    ) -> Reply<v1::CloudHeadProbeDelivery> {
        self.require_heads()?;
        self.0.runner.authenticate(
            &request,
            nocterm_hub_model::cloud::runner_request::RunnerMethod::NextHeadProbe,
        )?;
        self.0.runner.head_scope(&request.get_ref().scope)?;
        Ok(Response::new(
            self.0.heads.next(request.into_inner()).await?,
        ))
    }
    async fn retire_chat(&self, _: Request<v1::CloudRetireChat>) -> Reply<v1::CloudChatRetired> {
        Err(Status::unimplemented(
            "receipt reclaim is not part of this peer",
        ))
    }
    async fn reply_head_probe(
        &self,
        request: Request<v1::CloudHeadProbeReply>,
    ) -> Reply<v1::CloudHeadProbeReplied> {
        self.require_heads()?;
        self.0.runner.authenticate(
            &request,
            nocterm_hub_model::cloud::runner_request::RunnerMethod::ReplyHeadProbe,
        )?;
        self.0.runner.head_scope(&request.get_ref().scope)?;
        Ok(Response::new(self.0.heads.reply(request.into_inner())?))
    }
    async fn capabilities(
        &self,
        request: Request<v1::CloudCapabilitiesRequest>,
    ) -> Reply<v1::CloudCapabilities> {
        let nonce = request
            .into_inner()
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("nonce"))?;
        let key = &self.0.authority;
        let now = now_ms();
        let mut limits = CapabilityLimits::v1();
        limits.features |= lock(&self.0.state).additional_capabilities;
        if let Some(bytes) = lock(&self.0.state).max_frame_bytes {
            limits.max_frame_bytes = bytes;
        }
        let claim = CapabilitiesClaim::new(
            CloudTextId::new(HUB_ID).map_err(|_| Status::internal("id"))?,
            key.public_key(),
            limits,
            nonce,
            CapabilityWindow {
                issued_at_ms: now,
                expires_at_ms: now + 60_000,
            },
        )
        .map_err(|_| Status::internal("claim"))?;
        let claim = claim
            .canonical_bytes()
            .map_err(|_| Status::internal("claim"))?;
        let mut signature = key.sign(&claim).to_vec();
        if lock(&self.0.state).oversized_capability_reply {
            signature.resize(2048, 0);
        }
        Ok(Response::new(v1::CloudCapabilities { claim, signature }))
    }
    async fn publish(
        &self,
        request: Request<Streaming<v1::CloudPublishFrame>>,
    ) -> Reply<v1::CloudDeliveryReceipt> {
        let mut stream = request.into_inner();
        let Some(Some(Frame::Header(header))) = stream.next().await.transpose()?.map(|f| f.frame)
        else {
            return Err(Status::invalid_argument("header"));
        };
        let id = header
            .publication_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("id"))?;
        let digest = header
            .ciphertext_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("digest"))?;
        let binding = RelayBinding::from_canonical_bytes(&header.binding)
            .map_err(|_| Status::invalid_argument("binding"))?;
        let metadata = PublicationMetadata::new(id, binding, header.total_bytes, digest)
            .map_err(|_| Status::invalid_argument("metadata"))?;
        let mut verifier = PublicationVerifier::new(metadata.clone());
        let hold = lock(&self.0.state).hold_upload;
        if hold {
            self.0.release.notified().await;
        }
        let mut body = Vec::new();
        let mut finished = false;
        while let Some(frame) = stream.next().await {
            match frame?.frame {
                Some(Frame::Data(bytes)) if !finished => {
                    verifier
                        .chunk(&bytes)
                        .map_err(|_| Status::invalid_argument("data"))?;
                    lock(&self.0.state).frame_sizes.push(bytes.len());
                    body.extend_from_slice(&bytes);
                }
                Some(Frame::Finished(_)) if !finished => {
                    verifier
                        .finish_marker()
                        .map_err(|_| Status::invalid_argument("finish"))?;
                    finished = true;
                }
                _ => return Err(Status::invalid_argument("frame order")),
            }
        }
        verifier
            .end_of_stream()
            .map_err(|_| Status::invalid_argument("incomplete"))?;
        let (cursor, hold, wrong) = {
            let mut state = lock(&self.0.state);
            (
                retention::publish(&mut state.publications, &metadata, body)?,
                state.receipt.hold,
                state.receipt.wrong,
            )
        };
        self.0.published.notify_one();
        if hold {
            self.0.release.notified().await;
        }
        Ok(Response::new(v1::CloudDeliveryReceipt {
            publication_id: metadata.id().to_vec(),
            cursor,
            ciphertext_sha256: if wrong {
                vec![0; 32]
            } else {
                metadata.digest().to_vec()
            },
        }))
    }
    type ReplayStream = Frames;
    async fn replay(&self, request: Request<v1::CloudReplayRequest>) -> Reply<Self::ReplayStream> {
        if request
            .metadata()
            .get_bin("x-nocterm-runner-claim-bin")
            .is_some()
        {
            self.0.runner.authenticate(
                &request,
                nocterm_hub_model::cloud::runner_request::RunnerMethod::Replay,
            )?;
        }
        let frames = {
            let state = lock(&self.0.state);
            if state.replay.is_empty() {
                state
                    .retention
                    .replay(&state.publications, request.into_inner())?
            } else {
                state.replay.clone()
            }
        };
        let (sender, receiver) = mpsc::channel(2);
        tokio::spawn(async move {
            for frame in frames {
                if sender.send(Ok(frame)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
    async fn create_runner_grant(
        &self,
        _: Request<v1::CloudCreateRunnerGrant>,
    ) -> Reply<v1::CloudRunnerGrant> {
        Ok(Response::new(v1::CloudRunnerGrant {
            ticket: "fixture-ticket".into(),
            expires_at_ms: now_ms() + 60_000,
        }))
    }
    async fn redeem_runner_grant(
        &self,
        request: Request<v1::CloudRedeemRunnerGrant>,
    ) -> Reply<v1::CloudRunnerTokens> {
        Ok(Response::new(self.0.runner.redeem(&request.into_inner())?))
    }
    async fn refresh_runner(
        &self,
        request: Request<v1::CloudRefreshRunner>,
    ) -> Reply<v1::CloudRunnerTokens> {
        Ok(Response::new(
            self.0.runner.refresh(request.into_inner()).await?,
        ))
    }
    async fn revoke_runner(&self, _: Request<v1::CloudRunnerRef>) -> Reply<v1::CloudRevoked> {
        Err(Status::unimplemented("fixture"))
    }
    async fn runner_heartbeat(
        &self,
        request: Request<v1::CloudHeartbeat>,
    ) -> Reply<v1::CloudHeartbeatReceipt> {
        self.0.runner.authenticate(
            &request,
            nocterm_hub_model::cloud::runner_request::RunnerMethod::Heartbeat,
        )?;
        let signed = request.into_inner().signed_status;
        if signed.is_empty() || signed.len() > 4096 {
            return Err(Status::invalid_argument("status"));
        }
        self.0.status.heartbeat(signed).await?;
        Ok(Response::new(v1::CloudHeartbeatReceipt {
            accepted_at_ms: now_ms(),
        }))
    }
    async fn runner_status(
        &self,
        request: Request<v1::CloudRunnerRef>,
    ) -> Reply<v1::CloudRunnerStatus> {
        if request
            .metadata()
            .get_bin("x-nocterm-runner-claim-bin")
            .is_some()
        {
            return Err(Status::permission_denied("device status scope"));
        }
        if request.metadata().get("authorization").is_none() {
            return Err(Status::unauthenticated("device"));
        }
        if request.get_ref().runner_id != [2; 16] {
            return Err(Status::not_found("runner"));
        }
        Ok(Response::new(v1::CloudRunnerStatus {
            signed_status: self.0.status.read().await?,
            received_at_ms: now_ms(),
        }))
    }
    async fn acknowledge(
        &self,
        request: Request<v1::CloudAcknowledge>,
    ) -> Reply<v1::CloudAcknowledged> {
        if request
            .metadata()
            .get_bin("x-nocterm-runner-claim-bin")
            .is_some()
        {
            self.0.runner.authenticate(
                &request,
                nocterm_hub_model::cloud::runner_request::RunnerMethod::Acknowledge,
            )?;
        } else if request.metadata().get("authorization").is_none() {
            return Err(Status::unauthenticated("device"));
        }
        let state = lock(&self.0.state);
        Ok(Response::new(retention::acknowledge(
            &state.publications,
            request.into_inner(),
        )?))
    }
    type WatchStream = Hints;
    async fn watch(&self, _: Request<v1::CloudWatchRequest>) -> Reply<Self::WatchStream> {
        Err(Status::unimplemented("fixture"))
    }
    async fn list_streams(&self, _: Request<v1::CloudListStreams>) -> Reply<v1::CloudStreams> {
        Err(Status::unimplemented("fixture"))
    }
    async fn purge(&self, request: Request<v1::CloudPurge>) -> Reply<v1::CloudPurged> {
        self.0.runner.authenticate(
            &request,
            nocterm_hub_model::cloud::runner_request::RunnerMethod::Purge,
        )?;
        let mut state = lock(&self.0.state);
        let State {
            publications,
            retention,
            ..
        } = &mut *state;
        Ok(Response::new(
            retention.purge(publications, request.into_inner())?,
        ))
    }
}
