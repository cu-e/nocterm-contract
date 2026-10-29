//! Bounded producer-driven upload. Drop cancels the local RPC, not remote accepted work.
use super::{CloudError, transport::RelayAccess};
use nocterm_hub_model::cloud::relay::{
    MAX_RELAY_QUEUE_FRAMES, PublicationMetadata, PublicationVerifier,
};
use nocterm_hub_proto::v1::{self, cloud_publish_frame::Frame};
use std::fmt;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;

pub struct CloudUpload {
    sender: Option<mpsc::Sender<v1::CloudPublishFrame>>,
    task: Option<JoinHandle<Result<v1::CloudDeliveryReceipt, CloudError>>>,
    verifier: Option<PublicationVerifier>,
    source: RelayAccess,
    frame_bytes: u32,
    write_pending: bool,
}
impl CloudUpload {
    pub(super) fn start(
        client: RelayAccess,
        metadata: PublicationMetadata,
    ) -> Result<Self, CloudError> {
        client.check_source()?;
        if !client.can_publish(metadata.binding())
            || metadata.total_bytes() > client.limits().max_envelope_bytes
        {
            return Err(CloudError::Protocol);
        }
        let mut rpc = client.service()?;
        let (sender, receiver) = mpsc::channel(MAX_RELAY_QUEUE_FRAMES);
        let publication = v1::CloudPublication {
            publication_id: metadata.id().to_vec(),
            binding: metadata.binding().canonical_bytes()?,
            total_bytes: metadata.total_bytes(),
            ciphertext_sha256: metadata.digest().to_vec(),
        };
        sender
            .try_send(v1::CloudPublishFrame {
                frame: Some(Frame::Header(publication)),
            })
            .map_err(|_| CloudError::Interrupted)?;
        let expected = metadata.clone();
        let runtime = tokio::runtime::Handle::try_current().map_err(CloudError::Runtime)?;
        let task = runtime.spawn(async move {
            let receipt = rpc
                .publish(ReceiverStream::new(receiver))
                .await?
                .into_inner();
            if receipt.publication_id != expected.id()
                || receipt.ciphertext_sha256 != expected.digest()
                || receipt.cursor == 0
            {
                return Err(CloudError::Protocol);
            }
            Ok(receipt)
        });
        let frame_bytes = client.limits().max_frame_bytes;
        Ok(Self {
            sender: Some(sender),
            task: Some(task),
            verifier: Some(PublicationVerifier::new(metadata)),
            source: client,
            frame_bytes,
            write_pending: false,
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
            .map_err(CloudError::Task)??;
        self.task.take();
        self.check_source()?;
        Ok(receipt)
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
