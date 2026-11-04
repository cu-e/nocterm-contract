//! Cloud chats on the web panel's browser device: one [`CloudDevice`] that runs the device flows
//! of `nocterm-cloud-device` (ADR 0007).
//!
//! The page executes effects (connect-es RPCs, the WebCrypto signature, its own storage of
//! sealed chat and directory checkpoints) and shows outputs; everything that needs a key or decides trust happens
//! here. Values cross as structured objects with generated TypeScript declarations
//! ([`types`], [`view`], the listing rows of `types::WireChat`); nothing is JSON text. The account key, the account key pair,
//! collection keys, chat keys and provider keys never cross into JavaScript; the device key
//! stays in the page's WebCrypto store and signs the bytes a `sign` effect names.
mod device;
mod flow;
mod listing;
pub mod types;
pub mod view;

pub use device::CloudDevice;
pub use flow::{WebChat, WebFlow};

use nocterm_cloud_device::CloudDeviceError;
use wasm_bindgen::JsError;

use types::WireError;

/// Why a Cloud call was refused at the boundary. The message starts with a stable code in
/// brackets (`[no_runner] …`); a flow's failure carries the same code in `WireError.code`.
#[derive(Debug, thiserror::Error)]
pub enum WebCloudError {
    #[error("[{code}] {0}", code = device_code(.0))]
    Device(#[from] CloudDeviceError),
    #[error("[argument] invalid {0}")]
    Argument(&'static str),
    #[error("[not_ready] connect first: the device has no trusted hub yet")]
    NotReady,
}
impl WebCloudError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Device(error) => device_code(error),
            Self::Argument(_) => "argument",
            Self::NotReady => "not_ready",
        }
    }
    pub(crate) fn wire(&self) -> WireError {
        WireError {
            code: self.code().to_owned(),
            message: self.to_string(),
        }
    }
}

/// The stable code of a device refusal.
pub(crate) fn device_code(error: &CloudDeviceError) -> &'static str {
    use CloudDeviceError as E;
    match error {
        E::Capacity => "capacity",
        E::Format => "format",
        E::Binding => "binding",
        E::Deleted => "deleted",
        E::ObjectVersion(_) => "object_version",
        E::Unsupported => "unsupported",
        E::Signature(_) => "signature",
        E::SessionTooShort => "session_too_short",
        E::Time => "time",
        E::Policy => "policy",
        E::ReplayOrder => "replay_order",
        E::ReplaySource => "replay_source",
        E::ReplayIntegrity => "replay_integrity",
        E::Withheld => "withheld",
        E::SnapshotRequired => "snapshot_required",
        E::NoApproval => "no_approval",
        E::NoRun => "no_run",
        E::NoModel => "no_model",
        E::NoRunner => "no_runner",
        E::NotEnrolled => "not_enrolled",
        E::NotClaimed => "not_claimed",
        E::NoProviderKey => "no_provider_key",
        E::Rollback => "rollback",
        E::SummaryConflict => "summary_conflict",
        E::Summary(_) => "summary",
        E::Checkpoint | E::CheckpointCrypto(_) => "checkpoint",
        E::Protocol => "protocol",
        E::Ended => "ended",
        E::Effect(_) => "effect",
        E::ProviderLease(_) | E::ProviderSecret(_) => "provider",
        E::Capability(_) => "capability",
        E::Probe(_) | E::HeadCrypto(_) => "probe",
        E::Open(_) | E::Material(_) => "open",
        _ => "refused",
    }
}

pub(crate) type CloudResult<T> = Result<T, WebCloudError>;

/// A refusal becomes text only here, at the JavaScript boundary.
pub(crate) fn js<T>(result: CloudResult<T>) -> Result<T, JsError> {
    result.map_err(JsError::from)
}

/// A JavaScript time in milliseconds as the contract's signed milliseconds.
pub(crate) fn millis(value: f64, what: &'static str) -> CloudResult<i64> {
    if !value.is_finite() || value.fract() != 0.0 || value.abs() > 9.007_199_254_740_991e15 {
        return Err(WebCloudError::Argument(what));
    }
    // An integral value within ±2^53 converts exactly.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "checked integral and in range"
    )]
    Ok(value as i64)
}

pub(crate) fn hex_id<const N: usize>(text: &str, what: &'static str) -> CloudResult<[u8; N]> {
    let bytes = hex::decode(text).map_err(|_| WebCloudError::Argument(what))?;
    bytes.try_into().map_err(|_| WebCloudError::Argument(what))
}

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
