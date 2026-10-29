//! Shared bounded relay transport; device and runner authentication stay distinct.
use super::{
    CapturedSigner, CloudClient, CloudError, Credentials, runner_credentials::RunnerSigner,
};
use nocterm_hub_grpc::cloud_service_client::CloudServiceClient;
use nocterm_hub_model::cloud::{
    CloudNamespace,
    capabilities::{CLOUD_FEATURE_CHAT_KEY_MATERIAL, CapabilityLimits},
    relay::{MAX_RELAY_WIRE_BYTES, RelayBinding, RelayKind},
};
use std::sync::Arc;
use tonic::{
    Request, Status,
    service::{Interceptor, interceptor::InterceptedService},
    transport::Channel,
};

#[derive(Clone, Debug)]
pub(super) enum RelaySigner {
    Device(CapturedSigner),
    Runner(RunnerSigner),
}
#[derive(Clone)]
pub(super) struct GuardedRelaySigner(RelaySigner);
impl Interceptor for GuardedRelaySigner {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        match &mut self.0 {
            RelaySigner::Device(s) => s.call_bounded(request),
            RelaySigner::Runner(s) => s.call(request),
        }
    }
}
impl Interceptor for RelaySigner {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        match self {
            Self::Device(s) => s.call(request),
            Self::Runner(s) => s.call(request),
        }
    }
}
#[derive(Clone)]
pub(super) struct RelayAccess {
    channel: Channel,
    signer: RelaySigner,
    namespace: CloudNamespace,
    limits: CapabilityLimits,
}
pub(super) type RelayService = CloudServiceClient<InterceptedService<Channel, RelaySigner>>;
pub(super) type ResidentRelayService = CloudServiceClient<
    InterceptedService<super::resident_channel::ResidentChannel, GuardedRelaySigner>,
>;
impl RelayAccess {
    pub(super) async fn acknowledge(
        &self,
        selector: &super::CloudSelector,
        through: u64,
        residency: Option<Arc<dyn Send + Sync>>,
    ) -> Result<u64, CloudError> {
        self.require_selector(selector)?;
        let request = nocterm_hub_proto::v1::CloudAcknowledge {
            selector: Some(selector.wire()?),
            through_cursor: through,
        };
        let response = match residency {
            Some(owner) => {
                self.service_with_residency(owner)?
                    .acknowledge(request)
                    .await
            }
            None => self.service()?.acknowledge(request).await,
        };
        self.check_source()?;
        let response = response?.into_inner();
        if response.through_cursor != through {
            return Err(CloudError::Protocol);
        }
        Ok(through)
    }
    pub(super) fn namespace(&self) -> &CloudNamespace {
        &self.namespace
    }
    pub(super) fn limits(&self) -> CapabilityLimits {
        self.limits
    }
    pub(super) fn device(client: &CloudClient) -> Self {
        Self {
            channel: client.channel.clone(),
            signer: RelaySigner::Device(CapturedSigner {
                credentials: Arc::<Credentials>::clone(&client.credentials),
                generation: client.generation,
            }),
            namespace: client.namespace.clone(),
            limits: client.limits,
        }
    }
    pub(super) fn runner(
        channel: Channel,
        signer: RunnerSigner,
        namespace: CloudNamespace,
        limits: CapabilityLimits,
    ) -> Self {
        Self {
            channel,
            signer: RelaySigner::Runner(signer),
            namespace,
            limits,
        }
    }
    pub(super) fn check_source(&self) -> Result<(), CloudError> {
        match &self.signer {
            RelaySigner::Device(s) => s
                .credentials
                .require_generation(s.generation)
                .map_err(|_| CloudError::SourceChanged),
            RelaySigner::Runner(s) => s.check(),
        }
    }
    pub(super) fn supports_key_material(&self) -> bool {
        self.limits.features & CLOUD_FEATURE_CHAT_KEY_MATERIAL != 0
    }
    pub(super) fn can_publish(&self, binding: &RelayBinding) -> bool {
        if binding.namespace() != &self.namespace {
            return false;
        }
        match &self.signer {
            RelaySigner::Device(_) => {
                binding.kind() == RelayKind::Command
                    || (binding.kind() == RelayKind::ChatKeyGrant && self.supports_key_material())
            }
            RelaySigner::Runner(s) => {
                binding.runner().id == s.subject().runner_id
                    && matches!(binding.kind(), RelayKind::Event | RelayKind::Snapshot)
            }
        }
    }
    pub(super) fn require_selector(
        &self,
        selector: &super::CloudSelector,
    ) -> Result<(), CloudError> {
        let wire = selector.wire()?;
        if let RelaySigner::Runner(s) = &self.signer
            && wire.runner_id != s.subject().runner_id
        {
            return Err(CloudError::Protocol);
        }
        Ok(())
    }
    pub(super) fn service(&self) -> Result<RelayService, CloudError> {
        self.check_source()?;
        Ok(CloudServiceClient::new(InterceptedService::new(
            self.channel.clone(),
            self.signer.clone(),
        ))
        .max_decoding_message_size(MAX_RELAY_WIRE_BYTES)
        .max_encoding_message_size(MAX_RELAY_WIRE_BYTES))
    }
    pub(super) fn service_with_residency(
        &self,
        residency: Arc<dyn Send + Sync>,
    ) -> Result<ResidentRelayService, CloudError> {
        self.check_source()?;
        if let RelaySigner::Device(s) = &self.signer {
            s.require_bounded()?;
        }
        Ok(CloudServiceClient::new(InterceptedService::new(
            super::resident_channel::ResidentChannel::new(self.channel.clone(), residency),
            GuardedRelaySigner(self.signer.clone()),
        ))
        .max_decoding_message_size(MAX_RELAY_WIRE_BYTES)
        .max_encoding_message_size(MAX_RELAY_WIRE_BYTES))
    }
}

/// Bounded guarded unary ACK metadata, with no publication queue or ciphertext.
/// Guarded device tokens are <=1024 bytes; textual device/hub identities <=128.
/// Proof serialization and header conversion are checked under the signer lock.
/// This excludes Tonic/HTTP2/TLS/runtime/allocator baseline and backend storage.
pub(super) fn acknowledgement_work_bytes() -> usize {
    const CANONICAL_PROOF: usize =
        2 * nocterm_hub_model::cloud::runner_auth::MAX_RUNNER_PROOF_BYTES;
    // Encoded proof + signature, bearer/header construction and device DPoP data.
    const SIGNING_METADATA: usize =
        4 * nocterm_hub_model::cloud::runner_auth::MAX_RUNNER_PROOF_BYTES;
    const SELECTOR_METADATA: usize = 4 * nocterm_hub_model::cloud::MAX_ID_BYTES;
    CANONICAL_PROOF
        + SIGNING_METADATA
        + SELECTOR_METADATA
        + super::resident_channel::working_owner_bytes()
        + std::mem::size_of::<nocterm_hub_proto::v1::CloudAcknowledge>()
        + std::mem::size_of::<nocterm_hub_proto::v1::CloudAcknowledged>()
}
