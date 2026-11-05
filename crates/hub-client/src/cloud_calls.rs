//! The Cloud calls of the device core's effects (`nocterm-cloud-device`, contract ADR 0010), sent
//! under the client's own signer.
//!
//! The core builds and seals every probe, command and selector; these calls send exactly what an
//! effect names and hand back what its answer needs ([`Input`], [`Frame`]), so an executor maps
//! effects to calls one to one. Every call refreshes the access token first when it is about to
//! expire and carries this device's proof of possession over its method path; the device key
//! never leaves the client. Nothing here verifies a record, a witness or a capability proof:
//! that is the core's. Answers are only bounded.
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use nocterm_cloud_device::{
    CloudDeviceError,
    command::Publication,
    flow::{EffectFailure, Frame, Input, ProbeRequest, RecordHeader, StreamKind, StreamSelector},
};
use nocterm_hub_grpc::cloud_service_client::CloudServiceClient;
use nocterm_hub_model::cloud::{
    MAX_ENVELOPE_BYTES,
    capabilities::MAX_CAPABILITY_CLAIM_BYTES,
    head::MAX_HEAD_REPLY_ENVELOPE_BYTES,
    relay::{MAX_RELAY_FRAME_BYTES, MAX_RELAY_PAGE_RECORDS, MAX_RELAY_WIRE_BYTES},
};
use nocterm_hub_proto::v1::{self, cloud_publication_origin::Issuer, cloud_replay_frame};
use tokio_stream::Stream;

use crate::{ClientError, HubClient, Signed, StatusCode};

/// The longest a head probe waits for the runner; a probe expires sooner.
pub const MAX_PROBE_WAIT_MS: i64 = 10_000;

/// Why a Cloud call of a device effect failed. [`CloudCallError::failure`] says what it means for
/// the flow that asked; `Input::from` answers the effect with it.
#[derive(Debug, thiserror::Error)]
pub enum CloudCallError {
    /// No current access token: not signed in, the refresh was refused or the hub was not
    /// reached. Nothing was sent.
    #[error("the device's session cannot make a Cloud call")]
    Session(#[source] ClientError),
    /// The hub answered with an error status. `sent` says the request may have reached the hub
    /// before the answer was lost (only a publication cares).
    #[error("the hub refused or did not complete the Cloud call")]
    Hub {
        #[source]
        error: ClientError,
        sent: bool,
    },
    /// No runner answered the head probe before it expired.
    #[error("nobody answered the head probe in time")]
    Unanswered,
    /// The request or the hub's answer exceeds its bound or is malformed.
    #[error("the Cloud call or its answer exceeds its bound or is malformed")]
    Protocol,
    /// The publication's binding could not be encoded.
    #[error("the publication could not be encoded")]
    Publication(#[source] CloudDeviceError),
}
impl CloudCallError {
    fn status(status: tonic::Status, sent: bool) -> Self {
        Self::Hub {
            error: status.into(),
            sent,
        }
    }
    /// What the failure means for the device flow.
    pub fn failure(&self) -> EffectFailure {
        match self {
            Self::Session(
                ClientError::NotSignedIn | ClientError::Revoked | ClientError::SessionReplaced,
            )
            | Self::Protocol
            | Self::Publication(_) => EffectFailure::Refused,
            Self::Session(_)
            | Self::Unanswered
            | Self::Hub {
                error: ClientError::Connect(_),
                ..
            } => EffectFailure::Unavailable,
            Self::Hub {
                error: ClientError::Status { code, .. },
                sent,
            } => classify(*code, *sent),
            Self::Hub { .. } => EffectFailure::Refused,
        }
    }
}
impl From<CloudCallError> for Input {
    fn from(error: CloudCallError) -> Self {
        Input::Failed(error.failure())
    }
}

/// How a status answer fails an effect; `sent` says the request may have reached the hub.
fn classify(code: StatusCode, sent: bool) -> EffectFailure {
    match code {
        StatusCode::NotFound => EffectFailure::NotFound,
        StatusCode::AlreadyExists => EffectFailure::AlreadyExists,
        StatusCode::FailedPrecondition | StatusCode::Aborted => EffectFailure::Conflict,
        StatusCode::Unavailable
        | StatusCode::DeadlineExceeded
        | StatusCode::Cancelled
        | StatusCode::Unknown => {
            if sent {
                EffectFailure::Unknown
            } else {
                EffectFailure::Unavailable
            }
        }
        _ => EffectFailure::Refused,
    }
}

fn wire_selector(selector: &StreamSelector) -> Result<v1::CloudSelector, CloudCallError> {
    if selector.runner_key_epoch == 0 {
        return Err(CloudCallError::Protocol);
    }
    let stream = match selector.stream {
        StreamKind::Inbox => v1::cloud_selector::Stream::Inbox(v1::CloudRunnerInbox {}),
        StreamKind::Chat(chat) => v1::cloud_selector::Stream::ChatId(chat.to_vec()),
        StreamKind::Directory => v1::cloud_selector::Stream::Directory(v1::CloudRunnerDirectory {}),
    };
    Ok(v1::CloudSelector {
        runner_id: selector.runner_id.to_vec(),
        runner_key_epoch: selector.runner_key_epoch,
        stream: Some(stream),
    })
}

/// A replay frame as the core's frame; `None` for a frame without content.
fn replay_frame(frame: v1::CloudReplayFrame) -> Option<Frame> {
    use cloud_replay_frame::Frame as Wire;
    Some(match frame.frame? {
        Wire::Header(record) => {
            let publication = record.publication?;
            let origin = record.origin?;
            Frame::Header(RecordHeader {
                publication_id: publication.publication_id,
                binding: publication.binding,
                total_bytes: publication.total_bytes,
                ciphertext_sha256: publication.ciphertext_sha256,
                cursor: record.cursor,
                origin_account_id: origin.account_id,
                origin_signing_key: origin.signing_key,
                origin_runner_id: match origin.issuer {
                    Some(Issuer::RunnerId(runner)) => Some(runner),
                    _ => None,
                },
            })
        }
        Wire::Data(bytes) if bytes.len() <= MAX_RELAY_FRAME_BYTES => Frame::Data(bytes),
        Wire::Data(_) => return None,
        Wire::EndRecord(end) => Frame::End {
            publication_id: end.publication_id,
        },
        Wire::PageEnd(end) => Frame::PageEnd {
            through_cursor: end.through_cursor,
            has_more: end.has_more,
        },
        Wire::Gap(gap) => Frame::Gap {
            retained_from: gap.retained_from_cursor,
            snapshot_publication_id: gap.snapshot_publication_id,
        },
    })
}

#[derive(Debug)]
enum Frames {
    Replay(tonic::Streaming<v1::CloudReplayFrame>),
    Watch(tonic::Streaming<v1::CloudHint>),
}

/// The frames of a `Replay` or `Watch` effect, in arrival order, for `Flow::frame`. A malformed
/// or oversized frame, or a status, ends it with an error; after its last item it ends. A
/// replay is complete with its page end or gap frame; a watch's end is answered to the flow
/// with `Input::Failed(EffectFailure::Ended)` (or the error's failure).
#[derive(Debug)]
pub struct CloudFrames {
    frames: Frames,
    ended: bool,
}
impl CloudFrames {
    fn new(frames: Frames) -> Self {
        Self {
            frames,
            ended: false,
        }
    }
    /// The next frame; `None` once the stream ended.
    pub async fn next_frame(&mut self) -> Option<Result<Frame, CloudCallError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}
impl Stream for CloudFrames {
    type Item = Result<Frame, CloudCallError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let item = match &mut self.frames {
            Frames::Replay(stream) => match Pin::new(stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(item) => item.map(|frame| {
                    frame
                        .map_err(|status| CloudCallError::status(status, false))
                        .and_then(|frame| replay_frame(frame).ok_or(CloudCallError::Protocol))
                }),
            },
            Frames::Watch(stream) => match Pin::new(stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(item) => item.map(|hint| {
                    hint.map(|hint| Frame::Hint {
                        head_cursor: hint.head_cursor,
                    })
                    .map_err(|status| CloudCallError::status(status, false))
                }),
            },
        };
        if !matches!(item, Some(Ok(_))) {
            self.ended = true;
        }
        Poll::Ready(item)
    }
}

/// The calls, on a client made for one effect.
pub(crate) struct Calls(CloudServiceClient<Signed>);
impl Calls {
    /// The signed Cloud service with a current access token.
    pub(crate) async fn of(client: &HubClient) -> Result<Self, CloudCallError> {
        client
            .ensure_fresh()
            .await
            .map_err(CloudCallError::Session)?;
        Ok(Self(
            CloudServiceClient::new(client.signed())
                .max_decoding_message_size(MAX_RELAY_WIRE_BYTES)
                .max_encoding_message_size(MAX_RELAY_WIRE_BYTES),
        ))
    }
    pub(crate) async fn capabilities(mut self, nonce: [u8; 16]) -> Result<Input, CloudCallError> {
        let answer = self
            .0
            .capabilities(v1::CloudCapabilitiesRequest {
                nonce: nonce.to_vec(),
            })
            .await
            .map_err(|status| CloudCallError::status(status, false))?
            .into_inner();
        if answer.claim.is_empty()
            || answer.claim.len() > MAX_CAPABILITY_CLAIM_BYTES
            || answer.signature.len() != 64
        {
            return Err(CloudCallError::Protocol);
        }
        Ok(Input::Capabilities {
            claim: answer.claim,
            signature: answer.signature,
        })
    }
    pub(crate) async fn probe_head(
        mut self,
        request: &ProbeRequest,
        now_ms: i64,
    ) -> Result<Input, CloudCallError> {
        crate::cloud::require_head_query(&request.scope, &request.ciphertext)
            .map_err(|_| CloudCallError::Protocol)?;
        let wait = request
            .expires_at_ms
            .saturating_sub(now_ms)
            .clamp(0, MAX_PROBE_WAIT_MS);
        if wait == 0 {
            return Err(CloudCallError::Unanswered);
        }
        let call = self.0.probe_head(v1::CloudHeadProbe {
            scope: request.scope.clone(),
            probe_id: request.probe_id.to_vec(),
            ciphertext: request.ciphertext.clone(),
            expires_at_ms: request.expires_at_ms,
        });
        let wait = Duration::from_millis(u64::try_from(wait).unwrap_or(0));
        let reply = tokio::time::timeout(wait, call)
            .await
            .map_err(|_| CloudCallError::Unanswered)?
            .map_err(|status| CloudCallError::status(status, false))?
            .into_inner();
        if reply.scope != request.scope
            || reply.probe_id != request.probe_id
            || reply.ciphertext.is_empty()
            || reply.ciphertext.len() > MAX_HEAD_REPLY_ENVELOPE_BYTES
        {
            return Err(CloudCallError::Protocol);
        }
        Ok(Input::ProbeReply {
            scope: reply.scope,
            probe_id: reply.probe_id,
            ciphertext: reply.ciphertext,
        })
    }
    pub(crate) async fn publish_one(
        mut self,
        publication: &Publication,
    ) -> Result<Input, CloudCallError> {
        let binding = publication.binding().map_err(CloudCallError::Publication)?;
        let receipt = self
            .0
            .publish_one(v1::CloudPublishOne {
                header: Some(v1::CloudPublication {
                    publication_id: publication.publication_id().to_vec(),
                    binding,
                    total_bytes: publication.total_bytes(),
                    ciphertext_sha256: publication.ciphertext_sha256().to_vec(),
                    retry_until_ms: 0,
                }),
                data: publication.ciphertext().to_vec(),
            })
            .await
            .map_err(|status| CloudCallError::status(status, true))?
            .into_inner();
        if receipt.publication_id.len() != 16 || receipt.ciphertext_sha256.len() != 32 {
            return Err(CloudCallError::Protocol);
        }
        Ok(Input::Receipt {
            publication_id: receipt.publication_id,
            cursor: receipt.cursor,
            ciphertext_sha256: receipt.ciphertext_sha256,
        })
    }
    pub(crate) async fn replay(
        mut self,
        selector: &StreamSelector,
        after_cursor: u64,
        max_records: u32,
        max_bytes: u32,
    ) -> Result<CloudFrames, CloudCallError> {
        if !(1..=MAX_RELAY_PAGE_RECORDS).contains(&max_records)
            || max_bytes == 0
            || usize::try_from(max_bytes).map_or(true, |bytes| bytes > MAX_ENVELOPE_BYTES)
        {
            return Err(CloudCallError::Protocol);
        }
        let frames = self
            .0
            .replay(v1::CloudReplayRequest {
                selector: Some(wire_selector(selector)?),
                after_cursor,
                max_records,
                max_bytes,
            })
            .await
            .map_err(|status| CloudCallError::status(status, false))?
            .into_inner();
        Ok(CloudFrames::new(Frames::Replay(frames)))
    }
    pub(crate) async fn watch(
        mut self,
        selector: &StreamSelector,
        after_cursor: u64,
    ) -> Result<CloudFrames, CloudCallError> {
        let hints = self
            .0
            .watch(v1::CloudWatchRequest {
                selector: Some(wire_selector(selector)?),
                after_cursor,
            })
            .await
            .map_err(|status| CloudCallError::status(status, false))?
            .into_inner();
        Ok(CloudFrames::new(Frames::Watch(hints)))
    }
    pub(crate) async fn runner_status(mut self, runner: [u8; 16]) -> Result<Input, CloudCallError> {
        let status = self
            .0
            .runner_status(v1::CloudRunnerRef {
                runner_id: runner.to_vec(),
            })
            .await
            .map_err(|status| CloudCallError::status(status, false))?
            .into_inner();
        if status.signed_status.len() > crate::cloud::MAX_STATUS_BYTES {
            return Err(CloudCallError::Protocol);
        }
        Ok(Input::RunnerStatus {
            signed_status: status.signed_status,
        })
    }
}

#[cfg(test)]
mod tests;
