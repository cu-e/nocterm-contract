//! The runner's chat directory: summary publication and hole-tolerant replay (bit 256).
use super::*;
use nocterm_hub_model::cloud::{relay::RelayKind, summary::SummaryContext};
use nocterm_hub_proto::v1::{self, cloud_publication_origin::Issuer, cloud_replay_frame::Frame};

fn context(
    cloud: &CloudClient,
    revision: u64,
) -> Result<SummaryContext, Box<dyn std::error::Error>> {
    let chat = ChatCoordinate::new(
        cloud.namespace().clone(),
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        [4; 16],
        1,
    )?;
    Ok(SummaryContext::new(chat, revision)?)
}
fn record(context: &SummaryContext, cursor: u64, body: &[u8]) -> Vec<v1::CloudReplayFrame> {
    let header = v1::CloudDeliveredRecord {
        publication: Some(v1::CloudPublication {
            publication_id: context.publication_id().unwrap_or_default().to_vec(),
            binding: RelayBinding::summary(context.clone())
                .canonical_bytes()
                .unwrap_or_default(),
            total_bytes: u32::try_from(body.len()).unwrap_or_default(),
            ciphertext_sha256: Sha256::digest(body).to_vec(),
            retry_until_ms: 0,
        }),
        cursor,
        origin: Some(v1::CloudPublicationOrigin {
            account_id: context.chat().namespace().account_id.as_str().to_owned(),
            signing_key: DeviceKey::from_seed(&[0x72; 32]).public_key().to_vec(),
            issuer: Some(Issuer::RunnerId(vec![2; 16])),
        }),
    };
    vec![
        v1::CloudReplayFrame {
            frame: Some(Frame::Header(header)),
        },
        v1::CloudReplayFrame {
            frame: Some(Frame::Data(body.to_vec())),
        },
        v1::CloudReplayFrame {
            frame: Some(Frame::EndRecord(v1::CloudRecordEnd {
                publication_id: context.publication_id().unwrap_or_default().to_vec(),
            })),
        },
    ]
}
fn directory() -> CloudSelector {
    CloudSelector::Directory(RunnerCoordinate {
        id: [2; 16],
        key_epoch: 3,
    })
}

#[tokio::test]
async fn without_bit_256_a_runner_neither_publishes_nor_reads_a_directory() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud, runner) = enrolled(&hub).await?;
    assert!(!runner.supports_chat_directory());
    assert!(matches!(
        runner
            .publish_summary(&context(&cloud, 1)?, &[7; 100])
            .await,
        Err(CloudError::Unsupported)
    ));
    assert!(matches!(
        cloud.replay(directory(), 0, 64, 65_536).await,
        Err(CloudError::Unsupported)
    ));
    assert!(hub.cloud().ok_or("fixture")?.publications().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_runner_publishes_summaries_under_their_stable_id_only_to_its_directory() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let harness = hub.cloud().ok_or("fixture")?;
    harness.enable_chat_directory();
    let (_, cloud, runner) = enrolled(&hub).await?;
    let summary = context(&cloud, 3)?;
    runner.publish_summary(&summary, &[7; 300]).await?;
    let (metadata, body) = harness.publications().pop().ok_or("published")?;
    assert_eq!(metadata.binding().kind(), RelayKind::Summary);
    assert_eq!(metadata.id(), summary.publication_id()?);
    assert_eq!(body, [7; 300]);
    // A device cannot publish a summary, nor a runner one of another runner.
    let device = PublicationMetadata::new(
        [1; 16],
        RelayBinding::summary(summary.clone()),
        1,
        Sha256::digest([1]).into(),
    )?;
    assert!(cloud.begin_publication(device).is_err());
    let elsewhere = SummaryContext::new(
        ChatCoordinate::new(
            cloud.namespace().clone(),
            RunnerCoordinate {
                id: [9; 16],
                key_epoch: 3,
            },
            [4; 16],
            1,
        )?,
        1,
    )?;
    assert!(matches!(
        runner.publish_summary(&elsewhere, &[7; 10]).await,
        Err(CloudError::Protocol)
    ));
    Ok(())
}

#[tokio::test]
async fn a_directory_replay_accepts_cursor_holes_and_refuses_a_gap() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let harness = hub.cloud().ok_or("fixture")?;
    harness.enable_chat_directory();
    let (_, cloud, _) = enrolled(&hub).await?;
    let mut frames = record(&context(&cloud, 1)?, 3, &[1; 40]);
    frames.extend(record(&context(&cloud, 2)?, 7, &[2; 40]));
    frames.push(v1::CloudReplayFrame {
        frame: Some(Frame::PageEnd(v1::CloudPageEnd {
            through_cursor: 7,
            has_more: false,
        })),
    });
    harness.replay(frames);
    let mut replay = cloud.replay(directory(), 1, 64, 65_536).await?;
    let mut cursors = Vec::new();
    loop {
        match replay.next_record().await? {
            nocterm_hub_client::cloud::CloudReplayItem::Record(mut record) => {
                cursors.push(record.cursor());
                while record.next_chunk().await?.is_some() {}
            }
            nocterm_hub_client::cloud::CloudReplayItem::End { through, has_more } => {
                assert_eq!((through, has_more), (7, false));
                break;
            }
            nocterm_hub_client::cloud::CloudReplayItem::Gap { .. } => return Err("gap".into()),
        }
    }
    assert_eq!(cursors, [3, 7]);
    harness.replay(vec![v1::CloudReplayFrame {
        frame: Some(Frame::Gap(v1::CloudReplayGap {
            retained_from_cursor: 5,
            snapshot_publication_id: vec![],
        })),
    }]);
    let mut replay = cloud.replay(directory(), 0, 64, 65_536).await?;
    assert!(replay.next_record().await.is_err());
    Ok(())
}
