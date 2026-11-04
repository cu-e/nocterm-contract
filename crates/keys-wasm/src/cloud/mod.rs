//! Cloud chats on the web panel's browser device: one [`CloudDevice`] that runs the device flows
//! of `nocterm-cloud-device` (ADR 0007), including a chat's SSH binding and certificate answers
//! (`WebChat.bindServers`, `unbindServers`, `answerSsh`, `ssh`) and the account's CA-trusted
//! servers (`WebCollectionKey.openSshTrust`, ADR 0009).
//!
//! The page executes effects (connect-es RPCs, the WebCrypto signature, its own storage of
//! sealed chat and directory checkpoints) and shows outputs; everything that needs a key or decides trust happens
//! here. Values cross as structured objects with generated TypeScript declarations
//! ([`types`], [`view`], the listing rows of `types::WireChat`); nothing is JSON text. The account key, the account key pair,
//! collection keys, chat keys, provider keys and the SSH CA seed never cross into JavaScript; the device key
//! stays in the page's WebCrypto store and signs the bytes a `sign` effect names.
//!
//! Inputs arrive as plain `JsValue`s typed by their declarations and are decoded here
//! (`from_js`): a value that does not match is an `argument` refusal returned to the caller.
//! Nothing converts inside the generated binding, where a throw would leave the receiver
//! borrowed and every later call on it failing. An optional field is an `Option` on this side,
//! so `undefined` and `null` both mean absent.
mod device;
mod flow;
mod listing;
mod ssh;
pub mod types;
pub mod view;

pub use device::CloudDevice;
pub use flow::{WebChat, WebFlow};

use nocterm_cloud_device::CloudDeviceError;
use nocterm_hub_model::cloud::provider::ProviderLeaseError;
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
    /// A value from JavaScript did not match its declaration.
    #[error("[argument] invalid {what}: {source}")]
    Value {
        what: &'static str,
        #[source]
        source: serde_wasm_bindgen::Error,
    },
    #[error("[not_ready] connect first: the device has no trusted hub yet")]
    NotReady,
}
impl WebCloudError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Device(error) => device_code(error),
            Self::Argument(_) | Self::Value { .. } => "argument",
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
        E::StoredCommand => "stored_command",
        E::Protocol => "protocol",
        E::Ended => "ended",
        E::Effect(_) => "effect",
        // The runner's last signed boot is no longer current: it stopped announcing itself.
        E::ProviderLease(ProviderLeaseError::Time) => "boot_expired",
        E::ProviderLease(_) | E::ProviderSecret(_) => "provider",
        E::Capability(_) => "capability",
        E::Probe(_) | E::HeadCrypto(_) => "probe",
        E::Open(_) | E::Material(_) => "open",
        E::Ssh(refusal) => ssh::refusal_code(*refusal),
        E::SshFormat(_) | E::CaDocument(_) | E::SshCa(_) | E::Certificate(_) | E::SshTrust(_) => {
            "ssh"
        }
        _ => "refused",
    }
}

pub(crate) type CloudResult<T> = Result<T, WebCloudError>;

/// A refusal becomes text only here, at the JavaScript boundary.
pub(crate) fn js<T>(result: CloudResult<T>) -> Result<T, JsError> {
    result.map_err(JsError::from)
}

/// A value from JavaScript as `T`. The binding takes it as a `JsValue`, so a mismatch is a
/// refusal of this call only and the receiver stays usable.
pub(crate) fn from_js<T: serde::de::DeserializeOwned>(
    value: wasm_bindgen::JsValue,
    what: &'static str,
) -> CloudResult<T> {
    serde_wasm_bindgen::from_value(value).map_err(|source| WebCloudError::Value { what, source })
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
