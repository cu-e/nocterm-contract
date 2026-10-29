use super::{require_feature, require_reply};
use crate::cloud::{CloudError, transport::RelayAccess};
use nocterm_hub_model::cloud::head::{
    HeadProbeError, HeadProbeScope, MAX_HEAD_PROBE_LIFETIME_MS, MAX_HEAD_QUERY_ENVELOPE_BYTES,
    SignedHeadQuery,
};
use nocterm_hub_proto::v1;
use nocterm_keys::cloud::{RunnerEncryptionKey, open_head_query};
use std::{fmt, time::Duration};
use tokio::time::{Instant, timeout};

#[derive(Clone)]
pub struct RunnerHeadProbes {
    access: RelayAccess,
    scope: HeadProbeScope,
}
impl RunnerHeadProbes {
    pub(in crate::cloud) fn new(
        access: RelayAccess,
        scope: HeadProbeScope,
    ) -> Result<Self, CloudError> {
        require_feature(access.limits())?;
        access.check_source()?;
        scope.canonical_bytes()?;
        Ok(Self { access, scope })
    }
    pub async fn next(&self, wait: Duration) -> Result<Option<IncomingHeadProbe>, CloudError> {
        if wait > Duration::from_millis(10_000) {
            return Err(CloudError::Protocol);
        }
        self.access.check_source()?;
        let scope = self.scope.canonical_bytes()?;
        let mut service = self.access.service()?;
        let response = timeout(
            Duration::from_millis(10_000),
            service.next_head_probe(v1::CloudNextHeadProbe {
                scope: scope.clone(),
                wait_millis: u32::try_from(wait.as_millis()).map_err(|_| CloudError::Protocol)?,
            }),
        )
        .await
        .map_err(|_| HeadProbeError::Time)??
        .into_inner();
        self.access.check_source()?;
        let Some(probe) = response.probe else {
            return Ok(None);
        };
        if probe.scope != scope || probe.probe_id.len() != 16 {
            return Err(CloudError::Protocol);
        }
        super::require_wire(&scope, &probe.ciphertext, MAX_HEAD_QUERY_ENVELOPE_BYTES)?;
        let remaining = probe
            .expires_at_ms
            .checked_sub(crate::now_ms())
            .filter(|n| *n > 0)
            .ok_or(HeadProbeError::Time)?;
        let millis = u64::try_from(remaining.min(MAX_HEAD_PROBE_LIFETIME_MS))
            .map_err(|_| HeadProbeError::Time)?;
        Ok(Some(IncomingHeadProbe {
            access: self.access.clone(),
            scope: self.scope.clone(),
            probe_id: probe
                .probe_id
                .as_slice()
                .try_into()
                .map_err(|_| CloudError::Protocol)?,
            ciphertext: probe.ciphertext,
            deadline: Instant::now() + Duration::from_millis(millis),
        }))
    }
}
/// A route-bound received query, not a head fact or execution authority. Opening
/// uses R's explicitly supplied identity and independently configured full pins.
pub struct IncomingHeadProbe {
    access: RelayAccess,
    scope: HeadProbeScope,
    probe_id: [u8; 16],
    ciphertext: Vec<u8>,
    deadline: Instant,
}
impl IncomingHeadProbe {
    fn check(&self) -> Result<(), CloudError> {
        self.access.check_source()?;
        if Instant::now() >= self.deadline {
            return Err(HeadProbeError::Time.into());
        }
        Ok(())
    }
    pub fn open(
        &self,
        runner: &RunnerEncryptionKey,
        expected: &HeadProbeScope,
        now_ms: i64,
    ) -> Result<SignedHeadQuery, CloudError> {
        self.check()?;
        if expected != &self.scope {
            return Err(HeadProbeError::Scope.into());
        }
        let value = open_head_query(runner, expected, self.probe_id, &self.ciphertext, now_ms)?;
        self.check()?;
        Ok(value)
    }
    /// Reply bytes come only from the purpose-specific native witness sealer;
    /// a hub delivery ACK does not verify them or advance any chat state.
    pub async fn reply(self, ciphertext: Vec<u8>) -> Result<(), CloudError> {
        self.check()?;
        let scope = self.scope.canonical_bytes()?;
        require_reply(&scope, &ciphertext)?;
        let mut service = self.access.service()?;
        let response = tokio::time::timeout_at(
            self.deadline,
            service.reply_head_probe(v1::CloudHeadProbeReply {
                scope,
                probe_id: self.probe_id.to_vec(),
                ciphertext,
            }),
        )
        .await
        .map_err(|_| HeadProbeError::Time)??
        .into_inner();
        self.check()?;
        if !response.delivered {
            return Err(CloudError::Protocol);
        }
        Ok(())
    }
}
impl fmt::Debug for RunnerHeadProbes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerHeadProbes")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for IncomingHeadProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingHeadProbe")
            .field("probe", &self.probe_id)
            .finish_non_exhaustive()
    }
}
