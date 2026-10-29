//! The shared peer's retained-prefix behavior; production SQL has its own adapter.
use nocterm_hub_model::cloud::relay::{
    MAX_RELAY_FRAME_BYTES, MAX_RELAY_PAGE_RECORDS, PublicationMetadata, RelayKind,
};
use nocterm_hub_proto::v1::{self, cloud_replay_frame::Frame, cloud_selector::Stream};
use tonic::Status;

type Publications = [(PublicationMetadata, Vec<u8>)];
/// Exact retries keep their original stream position; changed reuse conflicts.
/// This is the shared test peer's behavior, not a production persistence adapter.
pub(super) fn publish(
    publications: &mut Vec<(PublicationMetadata, Vec<u8>)>,
    metadata: &PublicationMetadata,
    body: Vec<u8>,
) -> Result<u64, Status> {
    if let Some(index) = publications.iter().position(|(existing, _)| {
        existing.id() == metadata.id()
            && existing.binding().namespace() == metadata.binding().namespace()
    }) {
        let (existing, bytes) = &publications[index];
        if existing != metadata || bytes != &body {
            return Err(Status::already_exists("publication identity changed"));
        }
        return cursor(&publications[..=index], metadata);
    }
    publications.push((metadata.clone(), body));
    cursor(publications, metadata)
}

#[derive(Default)]
pub(super) struct Retention {
    floors: Vec<(v1::CloudSelector, u64, Vec<u8>)>,
}
fn selected(selector: &v1::CloudSelector, meta: &PublicationMetadata) -> bool {
    let binding = meta.binding();
    selector.runner_id == binding.runner().id
        && selector.runner_key_epoch == binding.runner().key_epoch
        && binding.namespace().account_id.as_str() == "acc-1"
        && match &selector.stream {
            Some(Stream::ChatId(chat)) => {
                chat == &binding.chat_id()
                    && matches!(binding.kind(), RelayKind::Event | RelayKind::Snapshot)
            }
            Some(Stream::Inbox(_)) => {
                matches!(binding.kind(), RelayKind::Command | RelayKind::ChatKeyGrant)
            }
            None => false,
        }
}
pub(super) fn cursor(
    publications: &Publications,
    meta: &PublicationMetadata,
) -> Result<u64, Status> {
    let binding = meta.binding();
    let count = publications
        .iter()
        .filter(|(candidate, _)| {
            let other = candidate.binding();
            other.namespace() == binding.namespace()
                && other.runner() == binding.runner()
                && matches!(other.kind(), RelayKind::Command | RelayKind::ChatKeyGrant)
                    == matches!(binding.kind(), RelayKind::Command | RelayKind::ChatKeyGrant)
                && (matches!(binding.kind(), RelayKind::Command | RelayKind::ChatKeyGrant)
                    || other.chat_id() == binding.chat_id())
        })
        .count();
    u64::try_from(count).map_err(|_| Status::internal("cursor"))
}
impl Retention {
    pub(super) fn purge(
        &mut self,
        publications: &Publications,
        request: v1::CloudPurge,
    ) -> Result<v1::CloudPurged, Status> {
        let selector = request
            .selector
            .ok_or_else(|| Status::invalid_argument("selector"))?;
        if !matches!(&selector.stream, Some(Stream::ChatId(_))) {
            return Err(Status::invalid_argument("chat only"));
        }
        let floor = request
            .through_cursor
            .checked_add(1)
            .ok_or_else(|| Status::invalid_argument("cursor overflow"))?;
        let anchor = publications
            .iter()
            .filter(|(meta, _)| selected(&selector, meta))
            .enumerate()
            .find(|(_, (meta, _))| meta.id().as_slice() == request.retained_publication_id);
        let Some((index, (meta, _))) = anchor else {
            return Err(Status::failed_precondition("missing anchor"));
        };
        let cursor = u64::try_from(index).map_err(|_| Status::internal("cursor"))? + 1;
        if meta.binding().kind() != RelayKind::Snapshot || cursor != floor {
            return Err(Status::failed_precondition(
                "not the first retained snapshot",
            ));
        }
        if let Some((_, old_floor, _)) = self.floors.iter().find(|(s, _, _)| s == &selector)
            && floor < *old_floor
        {
            return Err(Status::failed_precondition(
                "retention cannot move backwards",
            ));
        }
        self.floors.retain(|(s, _, _)| s != &selector);
        self.floors
            .push((selector, floor, request.retained_publication_id));
        Ok(v1::CloudPurged {
            through_cursor: request.through_cursor,
        })
    }
    pub(super) fn replay(
        &self,
        publications: &Publications,
        request: v1::CloudReplayRequest,
    ) -> Result<Vec<v1::CloudReplayFrame>, Status> {
        let selector = request
            .selector
            .ok_or_else(|| Status::invalid_argument("selector"))?;
        if !(1..=MAX_RELAY_PAGE_RECORDS).contains(&request.max_records) || request.max_bytes == 0 {
            return Err(Status::invalid_argument("bounds"));
        }
        if let Some((_, floor, snapshot)) = self.floors.iter().find(|(s, _, _)| s == &selector)
            && request.after_cursor < floor - 1
        {
            return Ok(vec![v1::CloudReplayFrame {
                frame: Some(Frame::Gap(v1::CloudReplayGap {
                    retained_from_cursor: *floor,
                    snapshot_publication_id: snapshot.clone(),
                })),
            }]);
        }
        let mut frames = Vec::new();
        let mut through = request.after_cursor;
        let mut count = 0;
        let mut bytes = 0_u64;
        let mut more = false;
        for (index, (meta, body)) in publications
            .iter()
            .filter(|(meta, _)| selected(&selector, meta))
            .enumerate()
        {
            let cursor = u64::try_from(index).map_err(|_| Status::internal("cursor"))? + 1;
            if cursor <= request.after_cursor {
                continue;
            }
            if count == request.max_records
                || (count != 0
                    && bytes + u64::from(meta.total_bytes()) > u64::from(request.max_bytes))
            {
                more = true;
                break;
            }
            frames.push(v1::CloudReplayFrame {
                frame: Some(Frame::Header(v1::CloudDeliveredRecord {
                    publication: Some(v1::CloudPublication {
                        publication_id: meta.id().to_vec(),
                        binding: meta
                            .binding()
                            .canonical_bytes()
                            .map_err(|_| Status::internal("binding"))?,
                        total_bytes: meta.total_bytes(),
                        ciphertext_sha256: meta.digest().to_vec(),
                    }),
                    cursor,
                    origin: Some(v1::CloudPublicationOrigin {
                        account_id: "acc-1".into(),
                        signing_key: vec![9; 32],
                        issuer: Some(
                            if matches!(
                                meta.binding().kind(),
                                RelayKind::Command | RelayKind::ChatKeyGrant
                            ) {
                                v1::cloud_publication_origin::Issuer::DeviceId(
                                    "original-device".into(),
                                )
                            } else {
                                v1::cloud_publication_origin::Issuer::RunnerId(
                                    meta.binding().runner().id.to_vec(),
                                )
                            },
                        ),
                    }),
                })),
            });
            for chunk in body.chunks(MAX_RELAY_FRAME_BYTES) {
                frames.push(v1::CloudReplayFrame {
                    frame: Some(Frame::Data(chunk.to_vec())),
                });
            }
            frames.push(v1::CloudReplayFrame {
                frame: Some(Frame::EndRecord(v1::CloudRecordEnd {
                    publication_id: meta.id().to_vec(),
                })),
            });
            through = cursor;
            count += 1;
            bytes += u64::from(meta.total_bytes());
        }
        frames.push(v1::CloudReplayFrame {
            frame: Some(Frame::PageEnd(v1::CloudPageEnd {
                through_cursor: through,
                has_more: more,
            })),
        });
        Ok(frames)
    }
}
