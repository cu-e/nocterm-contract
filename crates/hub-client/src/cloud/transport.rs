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
pub(super) type ResidentRelayService =
    CloudServiceClient<InterceptedService<super::resident_channel::ResidentChannel, RelaySigner>>;
impl RelayAccess {
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
        Ok(CloudServiceClient::new(InterceptedService::new(
            super::resident_channel::ResidentChannel::new(self.channel.clone(), residency),
            self.signer.clone(),
        ))
        .max_decoding_message_size(MAX_RELAY_WIRE_BYTES)
        .max_encoding_message_size(MAX_RELAY_WIRE_BYTES))
    }
}
