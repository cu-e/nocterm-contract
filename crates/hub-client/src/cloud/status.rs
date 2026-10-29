//! Guarded closed heartbeat/status unary RPCs; hub receive time is diagnostic only.
use super::{
    CloudClient, CloudError,
    transport::{RelayAccess, acknowledgement_work_bytes},
};
use nocterm_hub_proto::v1;
use std::sync::Arc;

pub const MAX_STATUS_BYTES: usize = 4096;
/// Status bytes plus protobuf bytes/int64 tags, lengths and worst-case varints.
pub const MAX_STATUS_WIRE_BYTES: usize = MAX_STATUS_BYTES + 32;

/// Logical SDK proof/metadata and concurrent input, encoded body and decoded
/// status generations. Actual caller-native data and Tonic/H2/TLS/runtime/RSS
/// baseline are separate. One caller's real reservation follows the RPC/result.
pub fn status_work_bytes() -> usize {
    acknowledgement_work_bytes()
        + 3 * MAX_STATUS_WIRE_BYTES
        + std::mem::size_of::<v1::CloudHeartbeat>()
        + std::mem::size_of::<v1::CloudHeartbeatReceipt>()
        + std::mem::size_of::<v1::CloudRunnerStatus>()
        + std::mem::size_of::<ResidentRunnerStatus>()
}

/// No uncharged owned extraction or Clone: original decoded bytes precede their
/// actual owner on Drop. A caller copying a borrowed status needs its own quota.
pub struct ResidentRunnerStatus {
    status: v1::CloudRunnerStatus,
    _residency: Arc<dyn Send + Sync>,
}
impl ResidentRunnerStatus {
    pub fn status(&self) -> &v1::CloudRunnerStatus {
        &self.status
    }
    pub fn signed_status(&self) -> &[u8] {
        &self.status.signed_status
    }
    /// The hub's observation time is never signed boot/head freshness.
    pub fn received_at_ms(&self) -> i64 {
        self.status.received_at_ms
    }
}
impl std::fmt::Debug for ResidentRunnerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResidentRunnerStatus")
            .field("signed_status_bytes", &self.signed_status().len())
            .field("received_at_ms", &self.received_at_ms())
            .finish_non_exhaustive()
    }
}
pub(super) async fn heartbeat(
    access: RelayAccess,
    signed_status: Vec<u8>,
    residency: Arc<dyn Send + Sync>,
) -> Result<i64, CloudError> {
    if signed_status.is_empty() || signed_status.len() > MAX_STATUS_BYTES {
        return Err(CloudError::Protocol);
    }
    let response = access
        .service_with_residency(residency.clone())?
        .max_encoding_message_size(MAX_STATUS_WIRE_BYTES)
        .max_decoding_message_size(MAX_STATUS_WIRE_BYTES)
        .runner_heartbeat(v1::CloudHeartbeat { signed_status })
        .await;
    access.check_source()?;
    Ok(response?.into_inner().accepted_at_ms)
}
pub(super) async fn receive(
    client: &CloudClient,
    runner: [u8; 16],
    residency: Arc<dyn Send + Sync>,
) -> Result<ResidentRunnerStatus, CloudError> {
    client.check_source()?;
    let response = RelayAccess::device(client)
        .service_with_residency(residency.clone())?
        .max_encoding_message_size(MAX_STATUS_WIRE_BYTES)
        .max_decoding_message_size(MAX_STATUS_WIRE_BYTES)
        .runner_status(v1::CloudRunnerRef {
            runner_id: runner.to_vec(),
        })
        .await;
    client.check_source()?;
    let status = response?.into_inner();
    if status.signed_status.len() > MAX_STATUS_BYTES {
        return Err(CloudError::Protocol);
    }
    Ok(ResidentRunnerStatus {
        status,
        _residency: residency,
    })
}
