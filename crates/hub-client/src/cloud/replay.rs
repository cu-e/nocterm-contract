//! One borrowed ciphertext record at a time; no complete replay page is hydrated.
use super::{CloudError, transport::RelayAccess};
use nocterm_hub_model::cloud::{
    CloudTextId, MAX_ENVELOPE_BYTES, RunnerCoordinate,
    relay::{
        MAX_RELAY_PAGE_RECORDS, PublicationMetadata, PublicationVerifier, RelayBinding, RelayKind,
    },
};
use nocterm_hub_proto::v1::{self, cloud_publication_origin::Issuer, cloud_replay_frame::Frame};
use std::{fmt, sync::Arc};

#[derive(Clone, Debug)]
pub enum CloudSelector {
    RunnerInbox(RunnerCoordinate),
    Chat {
        runner: RunnerCoordinate,
        chat: [u8; 16],
    },
}
impl CloudSelector {
    pub(super) fn wire(&self) -> Result<v1::CloudSelector, CloudError> {
        let (runner, stream) = match self {
            Self::RunnerInbox(runner) => (
                *runner,
                v1::cloud_selector::Stream::Inbox(v1::CloudRunnerInbox {}),
            ),
            Self::Chat { runner, chat } => {
                (*runner, v1::cloud_selector::Stream::ChatId(chat.to_vec()))
            }
        };
        if runner.key_epoch == 0 {
            return Err(CloudError::Protocol);
        }
        Ok(v1::CloudSelector {
            runner_id: runner.id.to_vec(),
            runner_key_epoch: runner.key_epoch,
            stream: Some(stream),
        })
    }
    fn accepts(&self, binding: &RelayBinding) -> bool {
        match self {
            Self::RunnerInbox(runner) => {
                binding.runner() == *runner
                    && matches!(binding.kind(), RelayKind::Command | RelayKind::ChatKeyGrant)
            }
            Self::Chat { runner, chat } => {
                binding.runner() == *runner
                    && binding.chat_id() == *chat
                    && matches!(binding.kind(), RelayKind::Event | RelayKind::Snapshot)
            }
        }
    }
}

/// Authenticated publication metadata from the hub. It never replaces inner signatures.
#[derive(Clone, Debug)]
pub enum CloudDeliveryOrigin {
    Device {
        account: CloudTextId,
        device: CloudTextId,
        key: [u8; 32],
    },
    Runner {
        account: CloudTextId,
        runner: [u8; 16],
        key: [u8; 32],
    },
}
impl CloudDeliveryOrigin {
    fn decode(
        wire: v1::CloudPublicationOrigin,
        binding: &RelayBinding,
    ) -> Result<Self, CloudError> {
        let account = CloudTextId::new(wire.account_id)?;
        if account != binding.namespace().account_id {
            return Err(CloudError::Protocol);
        }
        let key = wire
            .signing_key
            .as_slice()
            .try_into()
            .map_err(|_| CloudError::Protocol)?;
        match (binding.kind(), wire.issuer) {
            (RelayKind::Command | RelayKind::ChatKeyGrant, Some(Issuer::DeviceId(device))) => {
                Ok(Self::Device {
                    account,
                    device: CloudTextId::new(device)?,
                    key,
                })
            }
            (RelayKind::Event | RelayKind::Snapshot, Some(Issuer::RunnerId(runner))) => {
                let runner: [u8; 16] = runner
                    .as_slice()
                    .try_into()
                    .map_err(|_| CloudError::Protocol)?;
                if runner != binding.runner().id {
                    return Err(CloudError::Protocol);
                }
                Ok(Self::Runner {
                    account,
                    runner,
                    key,
                })
            }
            _ => Err(CloudError::Protocol),
        }
    }
}

pub enum CloudReplayItem<'a> {
    Record(Box<CloudIncomingRecord<'a>>),
    End {
        through: u64,
        has_more: bool,
    },
    /// For Chat, replay from retained_from-1 with max_records=1, then require the
    /// first record to be the indicated Snapshot. Verify its expected context
    /// and pinned runner signature before accepting a baseline or acknowledging.
    /// RunnerInbox has no snapshot: recover the durable inbox or report the gap.
    Gap {
        retained_from: u64,
        snapshot: Option<[u8; 16]>,
    },
}
impl fmt::Debug for CloudReplayItem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(record) => record.fmt(f),
            Self::End { through, has_more } => {
                f.debug_tuple("End").field(through).field(has_more).finish()
            }
            Self::Gap {
                retained_from,
                snapshot,
            } => f
                .debug_tuple("Gap")
                .field(retained_from)
                .field(snapshot)
                .finish(),
        }
    }
}

pub struct CloudReplay {
    client: RelayAccess,
    stream: tonic::Streaming<v1::CloudReplayFrame>,
    selector: CloudSelector,
    last: u64,
    records: u32,
    bytes: u64,
    max_records: u32,
    max_bytes: u32,
    ended: bool,
    poisoned: bool,
    _residency: Option<Arc<dyn Send + Sync>>,
}
impl CloudReplay {
    pub(super) async fn start(
        client: RelayAccess,
        selector: CloudSelector,
        after: u64,
        max_records: u32,
        max_bytes: u32,
    ) -> Result<Self, CloudError> {
        Self::start_inner(client, selector, after, max_records, max_bytes, None).await
    }
    pub(super) async fn start_with_residency(
        client: RelayAccess,
        selector: CloudSelector,
        after: u64,
        max_records: u32,
        max_bytes: u32,
        residency: Arc<dyn Send + Sync>,
    ) -> Result<Self, CloudError> {
        Self::start_inner(
            client,
            selector,
            after,
            max_records,
            max_bytes,
            Some(residency),
        )
        .await
    }
    async fn start_inner(
        client: RelayAccess,
        selector: CloudSelector,
        after: u64,
        max_records: u32,
        max_bytes: u32,
        residency: Option<Arc<dyn Send + Sync>>,
    ) -> Result<Self, CloudError> {
        if max_records == 0
            || max_records > MAX_RELAY_PAGE_RECORDS
            || max_bytes == 0
            || usize::try_from(max_bytes).map_err(|_| CloudError::Protocol)? > MAX_ENVELOPE_BYTES
        {
            return Err(CloudError::Protocol);
        }
        client.require_selector(&selector)?;
        let request = v1::CloudReplayRequest {
            selector: Some(selector.wire()?),
            after_cursor: after,
            max_records,
            max_bytes,
        };
        let response = match residency.as_ref() {
            Some(owner) => {
                client
                    .service_with_residency(owner.clone())?
                    .replay(request)
                    .await
            }
            None => client.service()?.replay(request).await,
        };
        client.check_source()?;
        let stream = response?.into_inner();
        Ok(Self {
            client,
            stream,
            selector,
            last: after,
            records: 0,
            bytes: 0,
            max_records,
            max_bytes,
            ended: false,
            poisoned: false,
            _residency: residency,
        })
    }
    /// SDK-owned parsed frame/header and routing scratch for one guarded stream.
    /// Callers separately charge assembled ciphertext, opened plaintext and DTOs.
    /// Tonic/HTTP2/TLS/runtime/allocator/decoder internals are connection baseline,
    /// not a total process memory bound supplied by this accessor.
    pub fn buffer_work_bytes() -> usize {
        super::transport::acknowledgement_work_bytes()
            + nocterm_hub_model::cloud::relay::MAX_RELAY_WIRE_BYTES
            + 2 * nocterm_hub_model::cloud::relay::MAX_RELAY_BINDING_BYTES
            + nocterm_hub_model::cloud::relay::MAX_RELAY_FRAME_BYTES
            + std::mem::size_of::<Self>()
            + std::mem::size_of::<CloudIncomingRecord<'static>>()
    }
    pub async fn next_record(&mut self) -> Result<CloudReplayItem<'_>, CloudError> {
        if self.ended || self.poisoned {
            return Err(CloudError::Protocol);
        }
        self.poisoned = true;
        self.client.check_source()?;
        let frame = self
            .stream
            .message()
            .await?
            .ok_or(CloudError::Interrupted)?;
        self.client.check_source()?;
        match frame.frame {
            Some(Frame::Header(header)) => self.record(header),
            Some(Frame::PageEnd(end)) => {
                if end.through_cursor != self.last || (end.has_more && self.records == 0) {
                    return Err(CloudError::Protocol);
                }
                self.require_eof().await?;
                Ok(CloudReplayItem::End {
                    through: end.through_cursor,
                    has_more: end.has_more,
                })
            }
            Some(Frame::Gap(gap)) => {
                if self.records != 0
                    || gap.retained_from_cursor == 0
                    || gap.retained_from_cursor.saturating_sub(1) <= self.last
                {
                    return Err(CloudError::Protocol);
                }
                let snapshot = if gap.snapshot_publication_id.is_empty() {
                    None
                } else {
                    Some(
                        gap.snapshot_publication_id
                            .as_slice()
                            .try_into()
                            .map_err(|_| CloudError::Protocol)?,
                    )
                };
                if matches!(&self.selector, CloudSelector::Chat { .. }) != snapshot.is_some() {
                    return Err(CloudError::Protocol);
                }
                self.require_eof().await?;
                Ok(CloudReplayItem::Gap {
                    retained_from: gap.retained_from_cursor,
                    snapshot,
                })
            }
            _ => {
                self.poisoned = true;
                Err(CloudError::Protocol)
            }
        }
    }
    fn record(
        &mut self,
        header: v1::CloudDeliveredRecord,
    ) -> Result<CloudReplayItem<'_>, CloudError> {
        // Any malformed header or abandoned body poisons this stream.
        self.poisoned = true;
        if header.cursor != self.last.checked_add(1).ok_or(CloudError::Protocol)?
            || self.records >= self.max_records
        {
            return Err(CloudError::Protocol);
        }
        let wire = header.publication.ok_or(CloudError::Protocol)?;
        let id = wire
            .publication_id
            .as_slice()
            .try_into()
            .map_err(|_| CloudError::Protocol)?;
        let digest = wire
            .ciphertext_sha256
            .as_slice()
            .try_into()
            .map_err(|_| CloudError::Protocol)?;
        let binding = RelayBinding::from_canonical_bytes(&wire.binding)?;
        if binding.namespace() != self.client.namespace()
            || !self.selector.accepts(&binding)
            || wire.total_bytes > self.client.limits().max_envelope_bytes
        {
            return Err(CloudError::Protocol);
        }
        if self.records != 0
            && self.bytes.saturating_add(u64::from(wire.total_bytes)) > u64::from(self.max_bytes)
        {
            return Err(CloudError::Protocol);
        }
        if binding.kind() == RelayKind::ChatKeyGrant && !self.client.supports_key_material() {
            return Err(CloudError::Unsupported);
        }
        let origin =
            CloudDeliveryOrigin::decode(header.origin.ok_or(CloudError::Protocol)?, &binding)?;
        let metadata = PublicationMetadata::new(id, binding, wire.total_bytes, digest)?;
        let verifier = PublicationVerifier::new(metadata.clone());
        Ok(CloudReplayItem::Record(Box::new(CloudIncomingRecord {
            replay: self,
            metadata,
            origin,
            cursor: header.cursor,
            verifier: Some(verifier),
            done: false,
        })))
    }
    async fn require_eof(&mut self) -> Result<(), CloudError> {
        self.poisoned = true;
        if self.stream.message().await?.is_some() {
            return Err(CloudError::Protocol);
        }
        self.client.check_source()?;
        self.ended = true;
        self.poisoned = false;
        Ok(())
    }
}
impl fmt::Debug for CloudReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudReplay")
            .field("cursor", &self.last)
            .finish_non_exhaustive()
    }
}

pub struct CloudIncomingRecord<'a> {
    replay: &'a mut CloudReplay,
    metadata: PublicationMetadata,
    origin: CloudDeliveryOrigin,
    cursor: u64,
    verifier: Option<PublicationVerifier>,
    done: bool,
}
impl CloudIncomingRecord<'_> {
    pub fn metadata(&self) -> &PublicationMetadata {
        &self.metadata
    }
    pub fn origin(&self) -> &CloudDeliveryOrigin {
        &self.origin
    }
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    /// None means the complete ciphertext digest/end marker passed. The caller still
    /// verifies inner E2EE signatures, semantic sequence and durable projection before ACK.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, CloudError> {
        let result = self.read_chunk().await;
        if result.is_err() {
            self.verifier.take();
        }
        result
    }
    async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, CloudError> {
        if self.done {
            return Ok(None);
        }
        if self.verifier.is_none() {
            return Err(CloudError::Protocol);
        }
        self.replay.client.check_source()?;
        let frame = self
            .replay
            .stream
            .message()
            .await?
            .ok_or(CloudError::Interrupted)?;
        self.replay.client.check_source()?;
        match frame.frame {
            Some(Frame::Data(bytes)) => {
                if bytes.len()
                    > usize::try_from(self.replay.client.limits().max_frame_bytes)
                        .map_err(|_| CloudError::Protocol)?
                {
                    return Err(CloudError::Protocol);
                }
                self.verifier
                    .as_mut()
                    .ok_or(CloudError::Protocol)?
                    .chunk(&bytes)?;
                Ok(Some(bytes))
            }
            Some(Frame::EndRecord(end)) if end.publication_id == self.metadata.id() => {
                let mut verifier = self.verifier.take().ok_or(CloudError::Protocol)?;
                verifier.finish_marker()?;
                verifier.end_of_stream()?;
                self.replay.last = self.cursor;
                self.replay.records += 1;
                self.replay.bytes = self
                    .replay
                    .bytes
                    .saturating_add(u64::from(self.metadata.total_bytes()));
                self.replay.poisoned = false;
                self.done = true;
                Ok(None)
            }
            _ => Err(CloudError::Protocol),
        }
    }
}
impl Drop for CloudIncomingRecord<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.replay.poisoned = true;
        }
    }
}
impl fmt::Debug for CloudIncomingRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudIncomingRecord")
            .field("cursor", &self.cursor)
            .field("ciphertext_bytes", &self.metadata.total_bytes())
            .finish_non_exhaustive()
    }
}
