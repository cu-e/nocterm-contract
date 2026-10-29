use super::{ResidentHeadWitness, require_feature, require_reply, require_wire};
use crate::cloud::transport::RelayAccess;
use crate::{
    Keyset,
    cloud::{CloudClient, CloudError},
    signer::Credentials,
};
use nocterm_hub_model::cloud::{
    CommandIssuer,
    capabilities::CapabilityWindow,
    head::{
        HeadProbeError, HeadProbeScope, HeadQuery, HeadTarget, MAX_HEAD_PROBE_LIFETIME_MS,
        MAX_HEAD_QUERY_ENVELOPE_BYTES, SignedHeadQuery, SignedHeadWitness,
    },
};
use nocterm_hub_proto::v1;
use nocterm_keys::{
    cloud::{open_head_witness, seal_head_query},
    random_bytes,
};
use std::{
    fmt,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::time::{Instant, timeout_at};

#[derive(Clone)]
pub struct DeviceHeadProbes {
    client: CloudClient,
    _residency: Option<Arc<dyn Send + Sync>>,
}
impl DeviceHeadProbes {
    pub(in crate::cloud) fn new(
        client: CloudClient,
        residency: Option<Arc<dyn Send + Sync>>,
    ) -> Result<Self, CloudError> {
        require_feature(client.limits())?;
        client.check_source()?;
        if residency.is_some() {
            client.credentials.capture_cloud(client.generation)?;
        }
        Ok(Self {
            client,
            _residency: residency,
        })
    }
    /// Scope contains independently established account/R pins. The SDK repeats
    /// its actual account key, device attribution and original login capture.
    pub fn prepare(
        &self,
        keyset: &Keyset,
        scope: HeadProbeScope,
        target: HeadTarget,
        now_ms: i64,
    ) -> Result<PreparedHeadProbe, CloudError> {
        self.client.check_source()?;
        if scope.namespace != *self.client.namespace()
            || scope.keys.account != keyset.public_key().to_bytes()
            || keyset.account_id() != scope.namespace.account_id.as_str()
        {
            return Err(CloudError::Protocol);
        }
        let capture = if self._residency.is_some() {
            self.client
                .credentials
                .capture_cloud(self.client.generation)?
        } else {
            self.client
                .credentials
                .capture()
                .ok_or(CloudError::NotSignedIn)?
        };
        if capture.generation != self.client.generation {
            return Err(CloudError::SourceChanged);
        }
        let expires_at_ms = now_ms
            .checked_add(MAX_HEAD_PROBE_LIFETIME_MS)
            .ok_or(HeadProbeError::Time)?
            .min(capture.refresh_expires_at_ms);
        let query = HeadQuery {
            scope,
            issuer: CommandIssuer {
                device_id: nocterm_hub_model::cloud::CloudTextId::new(&capture.device_id)?,
                signing_key: capture.signing_key,
                access_token_digest: capture.access_digest,
            },
            probe_id: random_bytes::<16>()?,
            challenge: random_bytes::<32>()?,
            window: CapabilityWindow {
                issued_at_ms: now_ms,
                expires_at_ms,
            },
            target,
        };
        query.require_fresh(now_ms)?;
        let signature = self.client.credentials.key.sign(&query.canonical_bytes()?);
        let signed = SignedHeadQuery::new(query, signature)?;
        let ciphertext = seal_head_query(keyset.key_pair(), &signed)?;
        require_wire(
            &signed.query().scope.canonical_bytes()?,
            &ciphertext,
            MAX_HEAD_QUERY_ENVELOPE_BYTES,
        )?;
        self.client.check_source()?;
        let duration = Duration::from_millis(
            u64::try_from(expires_at_ms - now_ms).map_err(|_| HeadProbeError::Time)?,
        );
        Ok(PreparedHeadProbe {
            query: signed.query().clone(),
            ciphertext,
            source: Arc::downgrade(&self.client.credentials),
            generation: capture.generation,
            deadline: Instant::now() + duration,
            _residency: self._residency.clone(),
        })
    }
    /// Consumes the actual one-shot query. The wait retains no account keyset.
    /// CompletedHeadProbe::open separately checks original membership/deadline.
    pub async fn request(
        &self,
        probe: PreparedHeadProbe,
    ) -> Result<CompletedHeadProbe, CloudError> {
        probe.require_source(&self.client.credentials, self.client.generation)?;
        if self._residency.is_some() && probe._residency.is_none() {
            return Err(CloudError::Protocol);
        }
        let scope = probe.query.scope.canonical_bytes()?;
        let request = v1::CloudHeadProbe {
            scope: scope.clone(),
            probe_id: probe.query.probe_id.to_vec(),
            ciphertext: probe.ciphertext,
            expires_at_ms: probe.query.window.expires_at_ms,
        };
        let access = RelayAccess::device(&self.client);
        let response = match probe._residency.as_ref() {
            Some(owner) => {
                timeout_at(
                    probe.deadline,
                    access
                        .service_with_residency(owner.clone())?
                        .probe_head(request),
                )
                .await
            }
            None => timeout_at(probe.deadline, access.service()?.probe_head(request)).await,
        }
        .map_err(|_| HeadProbeError::Time)??
        .into_inner();
        require_original(&probe.source, probe.generation, probe.deadline)?;
        if response.scope != scope || response.probe_id != probe.query.probe_id {
            return Err(CloudError::Protocol);
        }
        require_reply(&scope, &response.ciphertext)?;
        Ok(CompletedHeadProbe {
            query: probe.query,
            ciphertext: response.ciphertext,
            source: probe.source,
            generation: probe.generation,
            deadline: probe.deadline,
            _residency: probe._residency,
        })
    }
}
/// Private one-shot capability: cloning or reconstructing an old query is not a
/// new freshness proof. Its challenge comes from actual OS entropy at prepare.
pub struct PreparedHeadProbe {
    query: HeadQuery,
    ciphertext: Vec<u8>,
    source: Weak<Credentials>,
    generation: u64,
    deadline: Instant,
    _residency: Option<Arc<dyn Send + Sync>>,
}
impl PreparedHeadProbe {
    pub fn query(&self) -> &HeadQuery {
        &self.query
    }
    fn require_source(&self, source: &Arc<Credentials>, generation: u64) -> Result<(), CloudError> {
        if generation != self.generation
            || !self
                .source
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, source))
        {
            return Err(CloudError::SourceChanged);
        }
        require_original(&self.source, self.generation, self.deadline)
    }
}
/// Network completion is not a witness. This owner is consumed only after the
/// account opener verifies the pinned R signature and exact pending query.
pub struct CompletedHeadProbe {
    query: HeadQuery,
    ciphertext: Vec<u8>,
    source: Weak<Credentials>,
    generation: u64,
    deadline: Instant,
    _residency: Option<Arc<dyn Send + Sync>>,
}
impl CompletedHeadProbe {
    pub fn query(&self) -> &HeadQuery {
        &self.query
    }
    pub fn open(self, keyset: &Keyset, now_ms: i64) -> Result<SignedHeadWitness, CloudError> {
        if self._residency.is_some() {
            return Err(CloudError::Protocol);
        }
        self.open_value(keyset, now_ms)
    }
    /// Retains the original allocation through the returned decoded witness.
    /// Cloning borrowed payloads creates separately admitted caller generations.
    pub fn open_resident(
        self,
        keyset: &Keyset,
        now_ms: i64,
    ) -> Result<ResidentHeadWitness, CloudError> {
        let owner = self
            ._residency
            .as_ref()
            .ok_or(CloudError::Protocol)?
            .clone();
        let value = self.open_value(keyset, now_ms)?;
        Ok(ResidentHeadWitness::new(value, owner))
    }
    fn open_value(&self, keyset: &Keyset, now_ms: i64) -> Result<SignedHeadWitness, CloudError> {
        require_original(&self.source, self.generation, self.deadline)?;
        if keyset.account_id() != self.query.scope.namespace.account_id.as_str() {
            return Err(CloudError::SourceChanged);
        }
        let value = open_head_witness(keyset.key_pair(), &self.query, &self.ciphertext, now_ms)?;
        require_original(&self.source, self.generation, self.deadline)?;
        Ok(value)
    }
}
fn require_original(
    source: &Weak<Credentials>,
    generation: u64,
    deadline: Instant,
) -> Result<(), CloudError> {
    source
        .upgrade()
        .ok_or(CloudError::SourceChanged)?
        .require_generation(generation)
        .map_err(|_| CloudError::SourceChanged)?;
    if Instant::now() >= deadline {
        return Err(HeadProbeError::Time.into());
    }
    Ok(())
}
impl fmt::Debug for PreparedHeadProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedHeadProbe")
            .field("probe", &self.query.probe_id)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for CompletedHeadProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompletedHeadProbe")
            .field("probe", &self.query.probe_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DeviceHeadProbes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceHeadProbes")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}
