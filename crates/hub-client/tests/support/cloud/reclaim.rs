//! Receipt reclaim controls on the shared peer: recorded horizons and scripted retirements.
use super::{super::lock, CloudHarness};
use nocterm_hub_model::cloud::reclaim::ChatDeletionTombstone;
use nocterm_hub_proto::v1;
use std::sync::Mutex;
use tonic::Status;

/// What the peer answers to the next retirement.
#[derive(Clone, Copy, Debug, Default)]
pub enum Retirement {
    #[default]
    Compacted,
    Pending,
    AlreadyRetired,
    OutOfBounds,
}
/// One retirement as it arrived: the decoded tombstone, its signature and the request's
/// authentication surface.
#[derive(Clone, Debug)]
pub struct SeenRetirement {
    pub tombstone: ChatDeletionTombstone,
    pub signature: Vec<u8>,
    pub device_session: bool,
    pub runner_claim: bool,
}
#[derive(Default)]
pub(super) struct ReclaimLane {
    horizons: Mutex<Vec<i64>>,
    retirements: Mutex<Vec<SeenRetirement>>,
    next: Mutex<Retirement>,
}
impl ReclaimLane {
    pub(super) fn horizon(&self, retry_until_ms: i64) {
        lock(&self.horizons).push(retry_until_ms);
    }
    pub(super) fn retire(
        &self,
        request: tonic::Request<v1::CloudRetireChat>,
    ) -> Result<v1::CloudChatRetired, Status> {
        let device_session = request.metadata().get("authorization").is_some();
        let runner_claim = request
            .metadata()
            .get_bin("x-nocterm-runner-claim-bin")
            .is_some();
        let value = request.into_inner();
        let tombstone = ChatDeletionTombstone::from_canonical_bytes(&value.tombstone)
            .map_err(|_| Status::unauthenticated("tombstone"))?;
        let selector = value
            .selector
            .ok_or_else(|| Status::invalid_argument("selector"))?;
        let Some(v1::cloud_selector::Stream::ChatId(chat)) = selector.stream else {
            return Err(Status::invalid_argument("chat stream"));
        };
        if selector.runner_id != tombstone.runner.id
            || selector.runner_key_epoch != tombstone.runner.key_epoch
            || chat != tombstone.chat_id
        {
            return Err(Status::permission_denied("selector"));
        }
        lock(&self.retirements).push(SeenRetirement {
            tombstone,
            signature: value.signature,
            device_session,
            runner_claim,
        });
        match *lock(&self.next) {
            Retirement::Compacted => Ok(v1::CloudChatRetired { compacted: true }),
            Retirement::Pending => Ok(v1::CloudChatRetired { compacted: false }),
            Retirement::AlreadyRetired => Err(Status::failed_precondition("Cloud stream retired")),
            Retirement::OutOfBounds => Err(Status::invalid_argument("Cloud delivery bounds")),
        }
    }
}
impl CloudHarness {
    pub fn enable_receipt_reclaim(&self) {
        lock(&self.state).additional_capabilities |=
            nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_RECEIPT_RECLAIM;
    }
    /// The `retry_until_ms` of every publication header, in arrival order.
    pub fn retry_horizons(&self) -> Vec<i64> {
        lock(&self.reclaim.horizons).clone()
    }
    pub fn script_retirement(&self, answer: Retirement) {
        *lock(&self.reclaim.next) = answer;
    }
    pub fn retirements(&self) -> Vec<SeenRetirement> {
        lock(&self.reclaim.retirements).clone()
    }
}
