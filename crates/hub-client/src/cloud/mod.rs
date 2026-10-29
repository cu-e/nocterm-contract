//! Captured account Cloud access. SDK/protobuf types remain inside the hub adapter.
mod command;
mod material;
mod probe;
pub use material::PreparedChatKeyGrant;
pub use probe::{
    CompletedHeadProbe, DeviceHeadProbes, IncomingHeadProbe, PreparedHeadProbe, RunnerHeadProbes,
};
mod replay;
mod resident_channel;
mod runner;
mod runner_credentials;
mod transport;
mod watch;
pub use command::{CloudCommandInvocation, PreparedCloudCommand};
pub use runner::CloudRunner;
pub use runner_credentials::RunnerSession;
pub use watch::CloudWatch;
mod upload;
pub use replay::{
    CloudDeliveryOrigin, CloudIncomingRecord, CloudReplay, CloudReplayItem, CloudSelector,
};
pub use upload::CloudUpload;

use crate::{
    ClientError, Keyset,
    signer::{CredentialCapture, Credentials},
};
use nocterm_hub_grpc::{cloud_service_client::CloudServiceClient, metadata, method_path};
use nocterm_hub_model::cloud::{
    CloudNamespace, CloudRoute, CloudTextId, CommandContext, CommandError,
    capabilities::{CapabilitiesClaim, CapabilityError, CapabilityLimits, SignedCapabilities},
    hub_namespace_id,
    relay::{MAX_RELAY_WIRE_BYTES, PublicationMetadata, RelayFormatError},
};
use nocterm_hub_proto::v1;
use nocterm_keys::{KeyError, PublicKey, cloud::CloudCommandError, random_bytes};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use tonic::{
    GrpcMethod, Request, Status,
    service::{Interceptor, interceptor::InterceptedService},
    transport::Channel,
};

pub(crate) type CloudSigned = InterceptedService<Channel, CapturedSigner>;

/// Immutable attribution, not a server-issued stable authentication-session ID.
#[derive(Clone, Debug)]
pub struct CloudSubject {
    account: CloudTextId,
    device: CloudTextId,
    signing_key: [u8; 32],
    origin_access_digest: [u8; 32],
    hard_refresh_expires_at_ms: i64,
}
impl CloudSubject {
    pub fn account(&self) -> &CloudTextId {
        &self.account
    }
    pub fn device(&self) -> &CloudTextId {
        &self.device
    }
    pub fn signing_key(&self) -> [u8; 32] {
        self.signing_key
    }
    pub fn origin_access_digest(&self) -> [u8; 32] {
        self.origin_access_digest
    }
    pub fn hard_refresh_expires_at_ms(&self) -> i64 {
        self.hard_refresh_expires_at_ms
    }
    fn captured(capture: &CredentialCapture) -> Result<Self, CloudError> {
        Ok(Self {
            account: CloudTextId::new(&capture.account_id)?,
            device: CloudTextId::new(&capture.device_id)?,
            signing_key: capture.signing_key,
            origin_access_digest: capture.access_digest,
            hard_refresh_expires_at_ms: capture.refresh_expires_at_ms,
        })
    }
}

/// A nonce-bound self-signature from the connected hub. An offer is not an independent pin.
pub struct CloudOffer {
    channel: Channel,
    credentials: Arc<Credentials>,
    capture: CredentialCapture,
    proof: SignedCapabilities,
}
impl CloudOffer {
    pub(crate) async fn fetch(
        channel: Channel,
        credentials: Arc<Credentials>,
        raw_hub: &str,
    ) -> Result<Self, CloudError> {
        let capture = credentials.capture().ok_or(CloudError::NotSignedIn)?;
        CloudSubject::captured(&capture)?;
        let nonce = random_bytes::<16>()?;
        let mut rpc = rpc(channel.clone(), credentials.clone(), capture.generation);
        let response = rpc
            .capabilities(v1::CloudCapabilitiesRequest {
                nonce: nonce.to_vec(),
            })
            .await?
            .into_inner();
        credentials
            .require_generation(capture.generation)
            .map_err(|_| CloudError::SourceChanged)?;
        let claim = CapabilitiesClaim::from_canonical_bytes(&response.claim)?;
        let signature = response
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CloudError::Protocol)?;
        let proof = SignedCapabilities::new(claim, signature)?;
        // This checks freshness/self-possession only; pinning is an explicit later step.
        proof.require_expected(raw_hub, &proof.claim().authority(), &nonce, crate::now_ms())?;
        Ok(Self {
            channel,
            credentials,
            capture,
            proof,
        })
    }
    pub fn offered_authority(&self) -> [u8; 32] {
        self.proof.claim().authority()
    }
    pub fn raw_instance(&self) -> &CloudTextId {
        self.proof.claim().instance()
    }
    pub fn limits(&self) -> CapabilityLimits {
        self.proof.claim().limits()
    }
    /// Use a separately retained pin or the approved one-time trusted runner setup.
    /// Never replace an existing pin with offered_authority after a mismatch.
    pub fn accept(self, expected_authority: &[u8; 32]) -> Result<CloudClient, CloudError> {
        self.credentials
            .require_generation(self.capture.generation)
            .map_err(|_| CloudError::SourceChanged)?;
        self.proof.require_expected(
            self.proof.claim().instance().as_str(),
            expected_authority,
            &self.proof.claim().nonce(),
            crate::now_ms(),
        )?;
        let fingerprint: [u8; 32] = Sha256::digest(expected_authority).into();
        let namespace = CloudNamespace {
            hub_instance_id: hub_namespace_id(self.proof.claim().instance().as_str(), fingerprint)?,
            account_id: CloudTextId::new(&self.capture.account_id)?,
        };
        let subject = CloudSubject::captured(&self.capture)?;
        Ok(CloudClient {
            channel: self.channel,
            credentials: self.credentials,
            generation: self.capture.generation,
            namespace,
            subject,
            limits: self.proof.claim().limits(),
        })
    }
}
impl fmt::Debug for CloudOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudOffer")
            .field("proof", &self.proof)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct CloudClient {
    channel: Channel,
    credentials: Arc<Credentials>,
    generation: u64,
    namespace: CloudNamespace,
    subject: CloudSubject,
    limits: CapabilityLimits,
}
impl CloudClient {
    /// Captured read-only probe access. Pin establishment and native head/outbox
    /// storage remain with the consumer, never the hub capability advertisement.
    pub fn head_probes(&self) -> Result<DeviceHeadProbes, CloudError> {
        DeviceHeadProbes::new(self.clone())
    }
    /// Rebind exact original bytes loaded from an authenticated native outbox.
    /// This does not authenticate that native record or the encrypted command.
    pub fn stage_stored_command(
        &self,
        metadata: PublicationMetadata,
        ciphertext: Vec<u8>,
        semantic_digest: [u8; 32],
    ) -> Result<PreparedCloudCommand, CloudError> {
        PreparedCloudCommand::stage_stored(self, metadata, ciphertext, semantic_digest)
    }
    pub fn namespace(&self) -> &CloudNamespace {
        &self.namespace
    }
    pub fn subject(&self) -> &CloudSubject {
        &self.subject
    }
    pub fn limits(&self) -> CapabilityLimits {
        self.limits
    }
    pub fn check_source(&self) -> Result<(), CloudError> {
        self.credentials
            .require_generation(self.generation)
            .map_err(|_| CloudError::SourceChanged)
    }
    pub(crate) fn service(&self) -> Result<CloudServiceClient<CloudSigned>, CloudError> {
        self.check_source()?;
        Ok(rpc(
            self.channel.clone(),
            self.credentials.clone(),
            self.generation,
        ))
    }
    /// Seal only this chat key to the separately pinned R. No task is authorized.
    pub fn prepare_chat_key_grant(
        &self,
        keyset: &Keyset,
        pinned_runner: &PublicKey,
        chat: nocterm_hub_model::cloud::ChatCoordinate,
        key: &nocterm_keys::cloud::ChatKey,
        publication_id: [u8; 16],
    ) -> Result<PreparedChatKeyGrant, CloudError> {
        PreparedChatKeyGrant::seal(self, keyset, pinned_runner, chat, key, publication_id)
    }
    /// Rebind an immutable envelope read from the authenticated account-owned
    /// collection/outbox. This does not verify the encrypted key: only R can do so.
    pub fn stage_chat_key_grant(
        &self,
        chat: nocterm_hub_model::cloud::ChatCoordinate,
        publication_id: [u8; 16],
        ciphertext: Vec<u8>,
    ) -> Result<PreparedChatKeyGrant, CloudError> {
        PreparedChatKeyGrant::stage(self, chat, publication_id, ciphertext)
    }
    pub async fn publish_chat_key_grant(
        &self,
        grant: &PreparedChatKeyGrant,
    ) -> Result<v1::CloudDeliveryReceipt, CloudError> {
        grant.publish(self).await
    }
    pub fn command_invocation(&self) -> Result<CloudCommandInvocation, CloudError> {
        CloudCommandInvocation::capture(self)
    }
    pub fn prepare_command(
        &self,
        keyset: &Keyset,
        pinned_runner: &PublicKey,
        route: CloudRoute,
        context: CommandContext,
        payload: &[u8],
    ) -> Result<PreparedCloudCommand, CloudError> {
        self.command_invocation()?
            .seal(keyset, pinned_runner, route, context, payload)
    }
    pub fn prepare_payload(
        &self,
        keyset: &Keyset,
        pinned_runner: &PublicKey,
        route: CloudRoute,
        context: CommandContext,
        payload: &nocterm_hub_model::cloud::payload::CloudCommandPayload<'_>,
    ) -> Result<PreparedCloudCommand, CloudError> {
        self.command_invocation()?
            .seal_payload(keyset, pinned_runner, route, context, payload)
    }
    pub async fn create_runner_grant(
        &self,
        runner: [u8; 16],
        proof_key: [u8; 32],
    ) -> Result<RunnerGrantTicket, CloudError> {
        let response = self
            .service()?
            .create_runner_grant(v1::CloudCreateRunnerGrant {
                runner_id: runner.to_vec(),
                proof_key: proof_key.to_vec(),
            })
            .await?
            .into_inner();
        self.check_source()?;
        RunnerGrantTicket::new(response.ticket, response.expires_at_ms)
    }
    pub async fn publish_prepared(
        &self,
        command: &PreparedCloudCommand,
    ) -> Result<v1::CloudDeliveryReceipt, CloudError> {
        command.require_source(&self.credentials, self.generation)?;
        let mut upload = self.begin_publication(command.metadata().clone())?;
        let frame =
            usize::try_from(self.limits.max_frame_bytes).map_err(|_| CloudError::Protocol)?;
        for bytes in command.ciphertext().chunks(frame) {
            upload.write(bytes).await?;
        }
        upload.finish().await
    }
    /// Streams one lazy/spooled command. Semantic decoding and durable outbox ownership
    /// belong to the caller; no complete logical payload is queued here.
    pub fn begin_publication(
        &self,
        metadata: PublicationMetadata,
    ) -> Result<CloudUpload, CloudError> {
        CloudUpload::start(transport::RelayAccess::device(self), metadata)
    }
    pub async fn replay(
        &self,
        selector: CloudSelector,
        after: u64,
        max_records: u32,
        max_bytes: u32,
    ) -> Result<CloudReplay, CloudError> {
        CloudReplay::start(
            transport::RelayAccess::device(self),
            selector,
            after,
            max_records,
            max_bytes,
        )
        .await
    }
    pub async fn acknowledge(
        &self,
        selector: &CloudSelector,
        through: u64,
    ) -> Result<u64, CloudError> {
        let response = self
            .service()?
            .acknowledge(v1::CloudAcknowledge {
                selector: Some(selector.wire()?),
                through_cursor: through,
            })
            .await?
            .into_inner();
        self.check_source()?;
        if response.through_cursor != through {
            return Err(CloudError::Protocol);
        }
        Ok(through)
    }
    pub async fn watch(
        &self,
        selector: &CloudSelector,
        after: u64,
    ) -> Result<CloudWatch, CloudError> {
        CloudWatch::start(transport::RelayAccess::device(self), selector, after).await
    }
    pub async fn list_streams(
        &self,
        runner: Option<[u8; 16]>,
        after: Vec<u8>,
        limit: u32,
    ) -> Result<v1::CloudStreams, CloudError> {
        if after.len() > 256 || !(1..=64).contains(&limit) {
            return Err(CloudError::Protocol);
        }
        let response = self
            .service()?
            .list_streams(v1::CloudListStreams {
                runner_id: runner.map_or_else(Vec::new, |id| id.to_vec()),
                after,
                limit,
            })
            .await?
            .into_inner();
        self.check_source()?;
        if response.streams.len() > usize::try_from(limit).map_err(|_| CloudError::Protocol)?
            || response.next.len() > 256
        {
            return Err(CloudError::Protocol);
        }
        for row in &response.streams {
            if row.runner_id.len() != 16
                || row.chat_id.len() != 16
                || row.runner_key_epoch == 0
                || (!row.snapshot_publication_id.is_empty()
                    && row.snapshot_publication_id.len() != 16)
                || runner.is_some_and(|id| row.runner_id != id)
            {
                return Err(CloudError::Protocol);
            }
        }
        Ok(response)
    }
    pub async fn runner_status(
        &self,
        runner: [u8; 16],
    ) -> Result<v1::CloudRunnerStatus, CloudError> {
        let response = self
            .service()?
            .runner_status(v1::CloudRunnerRef {
                runner_id: runner.to_vec(),
            })
            .await?
            .into_inner();
        self.check_source()?;
        if response.signed_status.len() > 4096 {
            return Err(CloudError::Protocol);
        }
        Ok(response)
    }
    pub async fn revoke_runner(&self, runner: [u8; 16]) -> Result<bool, CloudError> {
        let response = self
            .service()?
            .revoke_runner(v1::CloudRunnerRef {
                runner_id: runner.to_vec(),
            })
            .await?
            .into_inner();
        self.check_source()?;
        Ok(response.revoked)
    }
}
impl fmt::Debug for CloudClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudClient")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

pub struct RunnerGrantTicket {
    token: zeroize::Zeroizing<String>,
    expires_at_ms: i64,
}
impl RunnerGrantTicket {
    fn new(token: String, expires_at_ms: i64) -> Result<Self, CloudError> {
        let token = zeroize::Zeroizing::new(token);
        if token.is_empty()
            || token.len() > 256
            || expires_at_ms <= crate::now_ms()
            || expires_at_ms.saturating_sub(crate::now_ms()) > 120_000
        {
            return Err(CloudError::Protocol);
        }
        Ok(Self {
            token,
            expires_at_ms,
        })
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}
impl fmt::Debug for RunnerGrantTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RunnerGrantTicket(…)")
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CapturedSigner {
    credentials: Arc<Credentials>,
    generation: u64,
}
impl Interceptor for CapturedSigner {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let method = request
            .extensions()
            .get::<GrpcMethod>()
            .ok_or_else(|| Status::internal("unknown method"))?;
        let path = method_path(method.service(), method.method());
        let (token, device, nonce, ts, signature) =
            self.credentials.sign_scoped(&path, Some(self.generation))?;
        let headers = request.metadata_mut();
        let mut authorization: tonic::metadata::AsciiMetadataValue = format!("Bearer {token}")
            .parse()
            .map_err(|_| Status::internal("invalid metadata"))?;
        authorization.set_sensitive(true);
        headers.insert(metadata::AUTHORIZATION, authorization);
        headers.insert(
            metadata::DEVICE,
            device
                .parse()
                .map_err(|_| Status::internal("invalid metadata"))?,
        );
        headers.insert(
            metadata::NONCE,
            nonce
                .parse()
                .map_err(|_| Status::internal("invalid metadata"))?,
        );
        headers.insert(
            metadata::SIGNED_AT,
            ts.to_string()
                .parse()
                .map_err(|_| Status::internal("invalid metadata"))?,
        );
        headers.insert_bin(
            metadata::PROOF,
            tonic::metadata::BinaryMetadataValue::from_bytes(&signature),
        );
        Ok(request)
    }
}
fn rpc(
    channel: Channel,
    credentials: Arc<Credentials>,
    generation: u64,
) -> CloudServiceClient<CloudSigned> {
    CloudServiceClient::new(InterceptedService::new(
        channel,
        CapturedSigner {
            credentials,
            generation,
        },
    ))
    .max_decoding_message_size(MAX_RELAY_WIRE_BYTES)
    .max_encoding_message_size(MAX_RELAY_WIRE_BYTES)
}

#[derive(thiserror::Error)]
pub enum CloudError {
    #[error("this hub does not support Cloud chats")]
    Unsupported,
    #[error("not signed in to the Cloud account")]
    NotSignedIn,
    #[error("the original Cloud account sign-in changed")]
    SourceChanged,
    #[error("the Cloud relay protocol is invalid or exceeded its bounds")]
    Protocol,
    #[error("the Cloud delivery was interrupted; its remote acceptance is unknown")]
    Interrupted,
    #[error("the Cloud transport task was interrupted")]
    Task(#[source] tokio::task::JoinError),
    #[error("the Cloud transport requires a Tokio runtime")]
    Runtime(#[source] tokio::runtime::TryCurrentError),
    #[error("the Cloud request failed")]
    Hub(#[source] Box<ClientError>),
    #[error("the Cloud capability proof was refused")]
    Capability(#[from] CapabilityError),
    #[error("the Cloud relay format was refused")]
    Relay(#[from] RelayFormatError),
    #[error("the Cloud command format was refused")]
    Command(#[from] CommandError),
    #[error("the Cloud key material was refused")]
    Material(#[from] nocterm_keys::cloud::CloudMaterialError),
    #[error("the Cloud command encryption failed")]
    Encryption(#[from] CloudCommandError),
    #[error("the Cloud request needs randomness")]
    Key(#[from] KeyError),
    #[error("the runner proof was refused")]
    RunnerProof(#[from] nocterm_hub_model::cloud::runner_auth::RunnerProofError),
    #[error("the Cloud command semantic payload was refused")]
    Payload(#[from] nocterm_hub_model::cloud::payload::PayloadError),
    #[error("the read-only head probe or witness was refused")]
    Head(#[from] nocterm_hub_model::cloud::head::HeadProbeError),
    #[error("the purpose-specific head encryption or authentication failed")]
    HeadCrypto(#[from] nocterm_keys::cloud::HeadCryptoError),
}
impl fmt::Debug for CloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl From<Status> for CloudError {
    fn from(status: Status) -> Self {
        if status.code() == tonic::Code::Unimplemented {
            Self::Unsupported
        } else {
            Self::Hub(Box::new(status.into()))
        }
    }
}
