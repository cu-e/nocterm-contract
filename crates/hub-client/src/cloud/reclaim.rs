//! Receipt reclaim (capability bit 64): the optional retry horizon of a publication and the
//! runner-signed deletion of a chat. A hub or peer without the bit keeps working as before.
use super::{CloudError, CloudSelector};
use crate::{ClientError, StatusCode};
use nocterm_hub_model::cloud::{
    CloudNamespace, CloudTextId, RunnerCoordinate,
    capabilities::{CLOUD_FEATURE_RECEIPT_RECLAIM, CapabilityLimits},
    reclaim::{ChatDeletionTombstone, ReclaimError, validate_retry_until},
};
use nocterm_hub_proto::v1;
use nocterm_keys::DeviceKey;

/// Whether the hub's accepted limits advertise receipt reclaim (bit 64). Only then may a
/// producer set a retry horizon or ask to retire a chat.
pub fn receipt_reclaim_negotiated(limits: CapabilityLimits) -> bool {
    limits.features & CLOUD_FEATURE_RECEIPT_RECLAIM != 0
}

/// A retry horizon accepted for a new publication: `0` (none, the hub keeps the receipt) or
/// 1 ms to 30 days ahead of `now_ms`. A nonzero horizon needs the negotiated capability.
pub(super) fn checked_retry_until(
    limits: CapabilityLimits,
    now_ms: i64,
    retry_until_ms: i64,
) -> Result<i64, CloudError> {
    validate_retry_until(now_ms, retry_until_ms)?;
    if retry_until_ms != 0 && !receipt_reclaim_negotiated(limits) {
        return Err(CloudError::Unsupported);
    }
    Ok(retry_until_ms)
}

/// A chat deletion tombstone with the runner's signature over its canonical bytes. The pair
/// cannot be built with a signature of another statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedChatDeletion {
    tombstone: ChatDeletionTombstone,
    canonical: Vec<u8>,
    signature: [u8; 64],
}
impl SignedChatDeletion {
    /// Signs the tombstone with the runner's proof key.
    pub fn sign(tombstone: ChatDeletionTombstone, key: &DeviceKey) -> Result<Self, ReclaimError> {
        let canonical = tombstone.canonical_bytes()?;
        let signature = key.sign(&canonical);
        Ok(Self {
            tombstone,
            canonical,
            signature,
        })
    }
    /// Rebinds a stored tombstone and signature; the signature is verified under the runner's
    /// pinned proof key.
    pub fn from_parts(
        tombstone: ChatDeletionTombstone,
        signature: [u8; 64],
        runner_key: &[u8; 32],
    ) -> Result<Self, ReclaimError> {
        tombstone.verify(runner_key, &signature)?;
        let canonical = tombstone.canonical_bytes()?;
        Ok(Self {
            tombstone,
            canonical,
            signature,
        })
    }
    pub fn tombstone(&self) -> &ChatDeletionTombstone {
        &self.tombstone
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
    pub(super) fn namespace(&self) -> &CloudNamespace {
        &self.tombstone.namespace
    }
    pub(super) fn request(&self) -> Result<v1::CloudRetireChat, CloudError> {
        let selector = CloudSelector::Chat {
            runner: self.tombstone.runner,
            chat: self.tombstone.chat_id,
        };
        Ok(v1::CloudRetireChat {
            selector: Some(selector.wire()?),
            tombstone: self.canonical.clone(),
            signature: self.signature.to_vec(),
        })
    }
}

/// Builds the statement a runner signs when a device asked to delete `chat_id`.
pub fn chat_deletion(
    namespace: CloudNamespace,
    runner: RunnerCoordinate,
    chat_id: [u8; 16],
    requested_by: CloudTextId,
    deleted_at_ms: i64,
) -> ChatDeletionTombstone {
    ChatDeletionTombstone {
        namespace,
        runner,
        chat_id,
        requested_by,
        deleted_at_ms,
    }
}

/// The hub's answer to a retirement it accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatRetirement {
    /// `false` while a reader has not acknowledged the stream yet; call again later.
    pub compacted: bool,
}

/// Why a chat could not be retired.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RetireChatError {
    /// The hub did not negotiate receipt reclaim (capability bit 64).
    #[error("this hub does not support receipt reclaim")]
    Unsupported,
    /// The tombstone belongs to another account or hub than this client.
    #[error("the deletion belongs to another Cloud account")]
    Namespace,
    /// The stream or its receipts are already retired and refuse the request
    /// (`FAILED_PRECONDITION`).
    #[error("the Cloud stream is already retired")]
    Retired,
    /// The hub refused the request's bounds or shape (`INVALID_ARGUMENT`).
    #[error("the Cloud deletion exceeded the hub's bounds")]
    Bounds,
    /// Any other Cloud failure, including a refused signature or scope.
    #[error("the Cloud deletion failed")]
    Cloud(#[from] CloudError),
}
impl RetireChatError {
    fn classify(error: CloudError) -> Self {
        match &error {
            CloudError::Unsupported => Self::Unsupported,
            CloudError::Hub(hub) => match hub.as_ref() {
                ClientError::Status {
                    code: StatusCode::FailedPrecondition,
                    ..
                } => Self::Retired,
                ClientError::Status {
                    code: StatusCode::InvalidArgument,
                    ..
                } => Self::Bounds,
                _ => Self::Cloud(error),
            },
            _ => Self::Cloud(error),
        }
    }
}

/// Shared by the device and runner clients after they built their guarded service call.
pub(super) fn answer(
    response: Result<tonic::Response<v1::CloudChatRetired>, tonic::Status>,
) -> Result<ChatRetirement, RetireChatError> {
    let response = response
        .map_err(CloudError::from)
        .map_err(RetireChatError::classify)?;
    Ok(ChatRetirement {
        compacted: response.into_inner().compacted,
    })
}
