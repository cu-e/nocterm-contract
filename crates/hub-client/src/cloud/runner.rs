//! A runner principal has no device session, account key or ordinary Store client.
use super::{
    CloudError, CloudReplay, CloudSelector, CloudUpload,
    runner_credentials::{RunnerCredentials, RunnerSession, RunnerSigner},
    transport::RelayAccess,
};
use nocterm_hub_grpc::cloud_service_client::CloudServiceClient;
use nocterm_hub_model::cloud::{
    capabilities::{CapabilitiesClaim, CapabilityLimits, SignedCapabilities},
    hub_namespace_id,
    relay::{MAX_RELAY_WIRE_BYTES, PublicationMetadata},
    runner_auth::{RunnerProofClaim, RunnerProofKind, RunnerProofSubject},
};
use nocterm_hub_proto::v1;
use nocterm_keys::{DeviceKey, random_bytes};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use tonic::transport::Channel;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct CloudRunner {
    channel: Channel,
    credentials: Arc<RunnerCredentials>,
    limits: CapabilityLimits,
}
impl CloudRunner {
    pub fn head_probes(
        &self,
        scope: nocterm_hub_model::cloud::head::HeadProbeScope,
    ) -> Result<super::RunnerHeadProbes, CloudError> {
        if scope.namespace != self.subject().namespace
            || scope.runner.id != self.subject().runner_id
        {
            return Err(CloudError::Protocol);
        }
        super::RunnerHeadProbes::new(self.access(), scope)
    }
    pub async fn redeem(
        endpoint: &crate::HubEndpoint,
        subject: RunnerProofSubject,
        authority: [u8; 32],
        key: DeviceKey,
        ticket: Zeroizing<String>,
    ) -> Result<Self, CloudError> {
        if key.public_key() != subject.proof_key {
            return Err(CloudError::Protocol);
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| CloudError::Hub(Box::new(e.into())))?;
        let limits = capabilities(channel.clone(), &subject, &authority).await?;
        let claim = RunnerProofClaim::new(
            subject.clone(),
            RunnerProofKind::Redeem,
            ticket,
            random_bytes::<16>()?,
            crate::now_ms(),
        )?;
        let bytes = claim.canonical_bytes()?;
        let signature = key.sign(&bytes).to_vec();
        let response = unsigned(channel.clone())
            .redeem_runner_grant(v1::CloudRedeemRunnerGrant {
                claim: bytes.to_vec(),
                signature,
            })
            .await?
            .into_inner();
        let session = RunnerSession::from_response(response, &subject)?;
        Ok(Self {
            channel,
            credentials: Arc::new(RunnerCredentials::new(subject, key, session)?),
            limits,
        })
    }
    /// Restored secrets must come from private runner storage, never an account vault.
    pub async fn restore(
        endpoint: &crate::HubEndpoint,
        subject: RunnerProofSubject,
        authority: [u8; 32],
        key: DeviceKey,
        session: RunnerSession,
    ) -> Result<Self, CloudError> {
        let credentials = Arc::new(RunnerCredentials::new(subject.clone(), key, session)?);
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| CloudError::Hub(Box::new(e.into())))?;
        let limits = capabilities(channel.clone(), &subject, &authority).await?;
        credentials.check()?;
        Ok(Self {
            channel,
            credentials,
            limits,
        })
    }
    pub fn subject(&self) -> &RunnerProofSubject {
        self.credentials.subject()
    }
    pub fn session(&self) -> Result<RunnerSession, CloudError> {
        self.credentials.snapshot()
    }
    /// Local revocation is permanent for all clones, including a pending refresh.
    pub fn revoke_local(&self) {
        self.credentials.revoke();
    }
    pub fn check_source(&self) -> Result<(), CloudError> {
        self.credentials.check()
    }
    pub async fn refresh(&self) -> Result<RunnerSession, CloudError> {
        let _guard = self.credentials.refresh_turn().await;
        let (claim, signature) = self.credentials.refresh_proof()?;
        let response = unsigned(self.channel.clone())
            .refresh_runner(v1::CloudRefreshRunner {
                claim: claim.canonical_bytes()?.to_vec(),
                signature: signature.to_vec(),
            })
            .await?
            .into_inner();
        self.credentials.rotate(&claim, response)?;
        self.credentials.snapshot()
    }
    pub fn begin_publication(
        &self,
        metadata: PublicationMetadata,
    ) -> Result<CloudUpload, CloudError> {
        CloudUpload::start(self.access(), metadata)
    }
    /// The same opaque allocation owner follows producer, RPC task and request body.
    /// Cancellation requests abort; residency ends on the final actual owner drop.
    pub fn begin_publication_with_residency(
        &self,
        metadata: PublicationMetadata,
        residency: Arc<dyn Send + Sync>,
    ) -> Result<CloudUpload, CloudError> {
        CloudUpload::start_with_residency(self.access(), metadata, Some(residency))
    }
    pub async fn replay(
        &self,
        selector: CloudSelector,
        after: u64,
        max_records: u32,
        max_bytes: u32,
    ) -> Result<CloudReplay, CloudError> {
        CloudReplay::start(self.access(), selector, after, max_records, max_bytes).await
    }
    pub async fn heartbeat(&self, signed_status: Vec<u8>) -> Result<i64, CloudError> {
        if signed_status.is_empty() || signed_status.len() > 4096 {
            return Err(CloudError::Protocol);
        }
        let response = self
            .access()
            .service()?
            .runner_heartbeat(v1::CloudHeartbeat { signed_status })
            .await?
            .into_inner();
        self.check_source()?;
        Ok(response.accepted_at_ms)
    }
    pub async fn watch(
        &self,
        selector: &CloudSelector,
        after: u64,
    ) -> Result<super::CloudWatch, CloudError> {
        super::CloudWatch::start(self.access(), selector, after).await
    }
    pub async fn acknowledge(
        &self,
        selector: &CloudSelector,
        through: u64,
    ) -> Result<u64, CloudError> {
        let access = self.access();
        access.require_selector(selector)?;
        let response = access
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
    /// Retain the same stream's durable Snapshot at cursor through+1.
    /// The hub validates that anchor atomically; inbox retention is not supported.
    pub async fn purge(
        &self,
        selector: &CloudSelector,
        through: u64,
        retained_publication: [u8; 16],
    ) -> Result<u64, CloudError> {
        if !matches!(selector, CloudSelector::Chat { .. }) || through.checked_add(1).is_none() {
            return Err(CloudError::Protocol);
        }
        let access = self.access();
        access.require_selector(selector)?;
        let response = access
            .service()?
            .purge(v1::CloudPurge {
                selector: Some(selector.wire()?),
                through_cursor: through,
                retained_publication_id: retained_publication.to_vec(),
            })
            .await?
            .into_inner();
        self.check_source()?;
        if response.through_cursor != through {
            return Err(CloudError::Protocol);
        }
        Ok(through)
    }
    fn access(&self) -> RelayAccess {
        RelayAccess::runner(
            self.channel.clone(),
            RunnerSigner::new(self.credentials.clone()),
            self.subject().namespace.clone(),
            self.limits,
        )
    }
}
impl fmt::Debug for CloudRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudRunner")
            .field("subject", self.subject())
            .finish_non_exhaustive()
    }
}
fn unsigned(channel: Channel) -> CloudServiceClient<Channel> {
    CloudServiceClient::new(channel)
        .max_decoding_message_size(MAX_RELAY_WIRE_BYTES)
        .max_encoding_message_size(MAX_RELAY_WIRE_BYTES)
}
async fn capabilities(
    channel: Channel,
    subject: &RunnerProofSubject,
    authority: &[u8; 32],
) -> Result<CapabilityLimits, CloudError> {
    let fingerprint: [u8; 32] = Sha256::digest(authority).into();
    if hub_namespace_id(subject.raw_hub_id.as_str(), fingerprint)?
        != subject.namespace.hub_instance_id
    {
        return Err(CloudError::Protocol);
    }
    let nonce = random_bytes::<16>()?;
    let response = unsigned(channel)
        .capabilities(v1::CloudCapabilitiesRequest {
            nonce: nonce.to_vec(),
        })
        .await?
        .into_inner();
    let claim = CapabilitiesClaim::from_canonical_bytes(&response.claim)?;
    let signature = response
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CloudError::Protocol)?;
    let proof = SignedCapabilities::new(claim, signature)?;
    proof.require_expected(
        subject.raw_hub_id.as_str(),
        authority,
        &nonce,
        crate::now_ms(),
    )?;
    Ok(proof.claim().limits())
}
