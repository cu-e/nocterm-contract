//! One-shot read-only head probes. No chat admission, journal mutation or
//! background task is hidden here; the native caller supplies actual heads.
mod bounds;
mod device;
mod resident;
mod runner;
use super::CloudError;
pub use bounds::{head_decoded_metadata_bytes, head_query_work_bytes, head_reply_work_bytes};
pub use device::{CompletedHeadProbe, DeviceHeadProbes, PreparedHeadProbe};
use nocterm_hub_model::cloud::{
    capabilities::{CLOUD_FEATURE_FRESH_HEAD, CapabilityLimits},
    head::{MAX_HEAD_QUERY_BYTES, MAX_HEAD_REPLY_ENVELOPE_BYTES},
    relay::MAX_RELAY_WIRE_BYTES,
};
pub use resident::{ResidentHeadQuery, ResidentHeadWitness};
pub use runner::{IncomingHeadProbe, RunnerHeadProbes};

fn require_feature(limits: CapabilityLimits) -> Result<(), CloudError> {
    if limits.features & CLOUD_FEATURE_FRESH_HEAD == 0 {
        return Err(CloudError::Unsupported);
    }
    Ok(())
}
fn require_wire(scope: &[u8], ciphertext: &[u8], maximum: usize) -> Result<(), CloudError> {
    // Scope/id/ciphertext are three length-delimited fields; 128 exceeds their
    // maximum protobuf tags/lengths plus the16-byte id and optional i64 window.
    if scope.len() > MAX_HEAD_QUERY_BYTES
        || ciphertext.is_empty()
        || ciphertext.len() > maximum
        || ciphertext
            .len()
            .saturating_add(scope.len())
            .saturating_add(128)
            > maximum.min(MAX_RELAY_WIRE_BYTES)
    {
        return Err(CloudError::Protocol);
    }
    Ok(())
}
fn require_reply(scope: &[u8], ciphertext: &[u8]) -> Result<(), CloudError> {
    require_wire(scope, ciphertext, MAX_HEAD_REPLY_ENVELOPE_BYTES)
}
