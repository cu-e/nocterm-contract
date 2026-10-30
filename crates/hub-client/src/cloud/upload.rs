//! Bounded producer-driven upload. Drop cancels the local RPC, not remote accepted work.
use super::{CloudError, transport::RelayAccess};
use nocterm_hub_model::cloud::relay::{
    MAX_RELAY_BINDING_BYTES, MAX_RELAY_FRAME_BYTES, MAX_RELAY_QUEUE_FRAMES, MAX_RELAY_WIRE_BYTES,
    PublicationMetadata, PublicationVerifier,
};
use nocterm_hub_proto::v1::{self, cloud_publish_frame::Frame};
use std::{
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_stream::{Stream, wrappers::ReceiverStream};

/// Tonic/Tower may retain the request body after the response future is dropped.
/// Receiver destruction drops its queued frames before releasing their owner.
struct ResidentFrames {
    receiver: ReceiverStream<v1::CloudPublishFrame>,
    _residency: Option<Arc<dyn Send + Sync>>,
}
impl ResidentFrames {
    fn new(
        receiver: mpsc::Receiver<v1::CloudPublishFrame>,
        residency: Option<Arc<dyn Send + Sync>>,
    ) -> Self {
        Self {
            receiver: ReceiverStream::new(receiver),
            _residency: residency,
        }
    }
}
impl Stream for ResidentFrames {
    type Item = v1::CloudPublishFrame;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().receiver).poll_next(cx)
    }
}

/// Tokio can retain a completed task's output after its future has been dropped.
/// Result data (including a remote failure) is destroyed before its allocation.
struct ResidentReceipt {
    receipt: Result<v1::CloudDeliveryReceipt, CloudError>,
    _residency: Option<Arc<dyn Send + Sync>>,
}
impl ResidentReceipt {
    fn new(
        receipt: Result<v1::CloudDeliveryReceipt, CloudError>,
        residency: Option<Arc<dyn Send + Sync>>,
    ) -> Self {
        Self {
            receipt,
            _residency: residency,
        }
    }
    fn into_result(self) -> Result<v1::CloudDeliveryReceipt, CloudError> {
        self.receipt
    }
}

pub struct CloudUpload {
    sender: Option<mpsc::Sender<v1::CloudPublishFrame>>,
    task: Option<JoinHandle<ResidentReceipt>>,
    verifier: Option<PublicationVerifier>,
    source: RelayAccess,
    frame_bytes: u32,
    write_pending: bool,
    _residency: Option<Arc<dyn Send + Sync>>,
}
enum PublicationService {
    Ordinary(super::transport::RelayService),
    Resident(super::transport::ResidentRelayService),
}
impl PublicationService {
    fn new(
        client: &RelayAccess,
        residency: Option<Arc<dyn Send + Sync>>,
    ) -> Result<Self, CloudError> {
        match residency {
            Some(owner) => Ok(Self::Resident(client.service_with_residency(owner)?)),
            None => Ok(Self::Ordinary(client.service()?)),
        }
    }
    async fn publish(self, frames: ResidentFrames) -> Result<v1::CloudDeliveryReceipt, CloudError> {
        let response = match self {
            Self::Ordinary(mut rpc) => rpc.publish(frames).await,
            Self::Resident(mut rpc) => rpc.publish(frames).await,
        };
        Ok(response?.into_inner())
    }
}
impl CloudUpload {
    pub(super) fn start(
        client: RelayAccess,
        metadata: PublicationMetadata,
    ) -> Result<Self, CloudError> {
        Self::start_with_residency(client, metadata, None)
    }
    pub(super) fn start_with_residency(
        client: RelayAccess,
        metadata: PublicationMetadata,
        residency: Option<Arc<dyn Send + Sync>>,
    ) -> Result<Self, CloudError> {
        Self::start_with_retry(client, metadata, residency, 0)
    }
    /// `retry_until_ms == 0` keeps the receipt forever; a horizon needs bit 64.
    pub(super) fn start_with_retry(
        client: RelayAccess,
        metadata: PublicationMetadata,
        residency: Option<Arc<dyn Send + Sync>>,
        retry_until_ms: i64,
    ) -> Result<Self, CloudError> {
        let retry_until_ms =
            super::reclaim::checked_retry_until(client.limits(), crate::now_ms(), retry_until_ms)?;
        client.check_source()?;
        if !client.can_publish(metadata.binding())
            || metadata.total_bytes() > client.limits().max_envelope_bytes
        {
            return Err(CloudError::Protocol);
        }
        let rpc = PublicationService::new(&client, residency.clone())?;
        let (sender, receiver) = mpsc::channel(MAX_RELAY_QUEUE_FRAMES);
        let publication = v1::CloudPublication {
            publication_id: metadata.id().to_vec(),
            binding: metadata.binding().canonical_bytes()?,
            total_bytes: metadata.total_bytes(),
            ciphertext_sha256: metadata.digest().to_vec(),
            // Zero: no retry horizon, so the hub keeps the receipt.
            retry_until_ms,
        };
        sender
            .try_send(v1::CloudPublishFrame {
                frame: Some(Frame::Header(publication)),
            })
            .map_err(|_| CloudError::Interrupted)?;
        let expected_id = metadata.id();
        let expected_digest = metadata.digest();
        let runtime = tokio::runtime::Handle::try_current().map_err(CloudError::Runtime)?;
        let task_residency = residency.clone();
        let frames = ResidentFrames::new(receiver, residency.clone());
        let task = runtime.spawn(async move {
            // The response future has its own owner. A transferred request body
            // keeps another owner if it outlives this task in Tonic/Tower.
            let response = async {
                let receipt = rpc.publish(frames).await?;
                if receipt.publication_id != expected_id
                    || receipt.ciphertext_sha256 != expected_digest
                    || receipt.cursor == 0
                {
                    return Err(CloudError::Protocol);
                }
                Ok(receipt)
            }
            .await;
            ResidentReceipt::new(response, task_residency)
        });
        let frame_bytes = client.limits().max_frame_bytes;
        Ok(Self {
            sender: Some(sender),
            task: Some(task),
            verifier: Some(PublicationVerifier::new(metadata)),
            source: client,
            frame_bytes,
            write_pending: false,
            _residency: residency,
        })
    }
    /// Signed negotiated frame limit; callers must not assume the protocol maximum.
    pub fn max_frame_bytes(&self) -> u32 {
        self.frame_bytes
    }
    /// Bound for SDK-owned upload data buffers and framing scratch, in bytes.
    /// It covers queue frames, one pending producer and one RPC-consumer frame,
    /// bounded routing/header temporaries and a maximum-size receipt. It excludes
    /// the caller's original ciphertext and the established connection/runtime,
    /// Tonic, HTTP/2, TLS and allocator baseline. It is not a total process bound.
    pub fn buffer_work_bytes(ciphertext_bytes: usize) -> Result<usize, CloudError> {
        const FRAMES: usize = MAX_RELAY_QUEUE_FRAMES + 2;
        // Routing serialization has at most three nested bounded buffers. Their
        // geometric capacities (each <2*binding limit) fit one wire-size slot.
        const ROUTING_SCRATCH: usize = 3 * 2 * MAX_RELAY_BINDING_BYTES;
        if ciphertext_bytes == 0 || ciphertext_bytes > nocterm_hub_model::cloud::MAX_ENVELOPE_BYTES
        {
            return Err(CloudError::Protocol);
        }
        // Verified chunks cannot collectively exceed the original declared bytes.
        let data = ciphertext_bytes.min(FRAMES * MAX_RELAY_FRAME_BYTES);
        [
            data,
            FRAMES * std::mem::size_of::<v1::CloudPublishFrame>(),
            ROUTING_SCRATCH,
            MAX_RELAY_WIRE_BYTES,
            MAX_RELAY_BINDING_BYTES,
            std::mem::size_of::<Self>(),
            std::mem::size_of::<ResidentFrames>(),
            std::mem::size_of::<ResidentReceipt>(),
            super::resident_channel::working_owner_bytes(),
            super::acknowledgement_work_bytes(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(CloudError::Protocol)
        })
    }
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), CloudError> {
        if self.write_pending {
            self.cancel();
            return Err(CloudError::Interrupted);
        }
        self.write_pending = true;
        let result = self.write_chunk(bytes).await;
        self.write_pending = false;
        if result.is_err() {
            self.cancel();
        }
        result
    }
    async fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), CloudError> {
        self.check_source()?;
        if bytes.len() > usize::try_from(self.frame_bytes).map_err(|_| CloudError::Protocol)? {
            self.cancel();
            return Err(CloudError::Protocol);
        }
        self.verifier
            .as_mut()
            .ok_or(CloudError::Interrupted)?
            .chunk(bytes)?;
        self.sender
            .as_ref()
            .ok_or(CloudError::Interrupted)?
            .send(v1::CloudPublishFrame {
                frame: Some(Frame::Data(bytes.to_vec())),
            })
            .await
            .map_err(|_| CloudError::Interrupted)?;
        self.check_source()
    }
    /// A hub receipt proves ciphertext storage only. Runner admission is a signed event.
    pub async fn finish(mut self) -> Result<v1::CloudDeliveryReceipt, CloudError> {
        if self.write_pending {
            return Err(CloudError::Interrupted);
        }
        self.check_source()?;
        let mut verifier = self.verifier.take().ok_or(CloudError::Interrupted)?;
        verifier.finish_marker()?;
        verifier.end_of_stream()?;
        self.sender
            .as_ref()
            .ok_or(CloudError::Interrupted)?
            .send(v1::CloudPublishFrame {
                frame: Some(Frame::Finished(v1::CloudPublishFinished {})),
            })
            .await
            .map_err(|_| CloudError::Interrupted)?;
        // EOF is part of the protocol. Dropping this sole sender closes the request stream.
        self.sender.take();
        let receipt = self
            .task
            .as_mut()
            .ok_or(CloudError::Interrupted)?
            .await
            .map_err(CloudError::Task)?;
        self.task.take();
        self.check_source()?;
        receipt.into_result()
    }
    fn check_source(&self) -> Result<(), CloudError> {
        self.source.check_source()
    }
    fn cancel(&mut self) {
        self.sender.take();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Drop for CloudUpload {
    fn drop(&mut self) {
        self.cancel();
    }
}
impl fmt::Debug for CloudUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CloudUpload([bounded ciphertext])")
    }
}

#[cfg(test)]
mod tests;
