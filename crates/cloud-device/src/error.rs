use nocterm_hub_model::{
    cloud::{
        CommandError, MaterialError, RecordError, capabilities::CapabilityError,
        events::EventPayloadError, head::HeadProbeError, payload::PayloadError,
        relay::RelayFormatError,
    },
    pop::SignatureError,
};
use nocterm_keys::{
    KeyError, OpenError, SealError,
    cloud::{CloudCommandError, CloudMaterialError, CloudRecordError, HeadCryptoError},
};

/// Why a Cloud device operation was refused. Variants name what failed for the caller; the
/// original cause of a contract failure is kept as the source.
#[derive(Debug, thiserror::Error)]
pub enum CloudDeviceError {
    #[error("a Cloud account record or one of its fields exceeds its bound")]
    Capacity,
    #[error("a Cloud account record is malformed or of an unsupported version")]
    Format,
    #[error("a Cloud account record names another hub, account, collection or object")]
    Binding,
    #[error("the stored Cloud account object was deleted")]
    Deleted,
    #[error("the stored Cloud account object has an unexpected version {0}")]
    ObjectVersion(u64),
    #[error("the hub does not offer the Cloud feature this operation needs")]
    Unsupported,
    #[error("the signature does not verify under the device key named in the signed bytes")]
    Signature(#[source] SignatureError),
    #[error("the signed-in session ends before the operation's deadline")]
    SessionTooShort,
    #[error("the operation's time window is invalid")]
    Time,
    #[error("the prompt policy bounds are invalid")]
    Policy,
    #[error("a replay frame arrived out of order or in the wrong state")]
    ReplayOrder,
    #[error("a replayed record comes from another runner, account or chat")]
    ReplaySource,
    #[error("a replayed record's length or ciphertext digest differs from its header")]
    ReplayIntegrity,
    #[error("the replay ended before the freshly witnessed head or disagrees with it")]
    Withheld,
    #[error("the replay has a gap; recover from its snapshot first")]
    SnapshotRequired,
    #[error("no pending approval matches this answer")]
    NoApproval,
    #[error("the Cloud capability proof was refused")]
    Capability(#[from] CapabilityError),
    #[error("the head probe was refused")]
    Probe(#[from] HeadProbeError),
    #[error("the head probe box was refused")]
    HeadCrypto(#[from] HeadCryptoError),
    #[error("the Cloud command framing was refused")]
    Command(#[from] CommandError),
    #[error("the Cloud command box was refused")]
    CommandCrypto(#[from] CloudCommandError),
    #[error("the Cloud command payload was refused")]
    Payload(#[from] PayloadError),
    #[error("the Cloud relay routing was refused")]
    Relay(#[from] RelayFormatError),
    #[error("the Cloud record framing was refused")]
    RecordFrame(#[from] RecordError),
    #[error("the Cloud record could not be opened under the pinned runner")]
    Record(#[from] CloudRecordError),
    #[error("the Cloud event body was refused")]
    Event(#[from] EventPayloadError),
    #[error("the chat key material was refused")]
    Material(#[from] CloudMaterialError),
    #[error("the chat coordinates are invalid")]
    Coordinate(#[from] MaterialError),
    #[error("the account object could not be opened")]
    Open(#[from] OpenError),
    #[error("the account object could not be sealed")]
    Seal(#[from] SealError),
    #[error("key generation failed")]
    Key(#[from] KeyError),
}
