//! Actual gRPC framing, immutable source capture and ciphertext-only publication.
mod support;

use nocterm_hub_client::{
    cloud::{CloudClient, CloudError, CloudReplayItem, CloudSelector},
    now_ms,
};
use nocterm_hub_model::cloud::{
    CloudRoute, CommandContext, CommandKind, RunnerCoordinate,
    relay::{MAX_RELAY_FRAME_BYTES, PublicationMetadata, RelayBinding},
};
use nocterm_hub_proto::v1::{self, cloud_replay_frame::Frame};
use nocterm_keys::{
    KdfParams, UnlockKdf, UnlockKey,
    cloud::{RunnerEncryptionKey, open_command},
};
use sha2::{Digest, Sha256};
use support::FakeHub;

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[tokio::test]
async fn a_cancelled_backpressured_write_cannot_finish_a_publication() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, client) = cloud(&hub).await?;
    let harness = hub.cloud().ok_or("fixture")?;
    harness.hold_upload();
    let chunk = vec![0x51; MAX_RELAY_FRAME_BYTES];
    let mut hash = Sha256::new();
    for _ in 0..1024 {
        hash.update(&chunk);
    }
    let meta = PublicationMetadata::new(
        [6; 16],
        RelayBinding::command(route(&client))?,
        16 * 1024 * 1024,
        hash.finalize().into(),
    )?;
    let mut upload = client.begin_publication(meta)?;
    let mut cancelled = false;
    for _ in 0..1024 {
        if let Ok(result) =
            tokio::time::timeout(std::time::Duration::from_millis(50), upload.write(&chunk)).await
        {
            result?;
        } else {
            cancelled = true;
            break;
        }
    }
    assert!(
        cancelled,
        "bounded upload must propagate a stopped reader's backpressure"
    );
    assert!(matches!(
        upload.finish().await,
        Err(CloudError::Interrupted)
    ));
    harness.release_receipt();
    assert!(harness.publications().is_empty());
    Ok(())
}
async fn cloud(
    hub: &FakeHub,
) -> Result<(nocterm_hub_client::HubClient, CloudClient), Box<dyn std::error::Error>> {
    let client = hub.signed_in_client().await;
    let authority = hub.cloud().ok_or("Cloud fixture missing")?.authority();
    let cloud = client.cloud_offer().await?.accept(&authority)?;
    Ok((client, cloud))
}
fn route(client: &CloudClient) -> CloudRoute {
    CloudRoute {
        namespace: client.namespace().clone(),
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat_id: [4; 16],
        command_id: [5; 16],
    }
}
fn metadata(
    client: &CloudClient,
    bytes: &[u8],
) -> Result<PublicationMetadata, Box<dyn std::error::Error>> {
    Ok(PublicationMetadata::new(
        [6; 16],
        RelayBinding::command(route(client))?,
        u32::try_from(bytes.len())?,
        Sha256::digest(bytes).into(),
    )?)
}
fn delivered(
    meta: &PublicationMetadata,
    body: &[u8],
    cursor: u64,
) -> Result<Vec<v1::CloudReplayFrame>, Box<dyn std::error::Error>> {
    let header = v1::CloudDeliveredRecord {
        publication: Some(v1::CloudPublication {
            publication_id: meta.id().to_vec(),
            binding: meta.binding().canonical_bytes()?,
            total_bytes: meta.total_bytes(),
            ciphertext_sha256: meta.digest().to_vec(),
        }),
        cursor,
        origin: Some(v1::CloudPublicationOrigin {
            account_id: meta.binding().namespace().account_id.as_str().into(),
            signing_key: vec![9; 32],
            issuer: Some(v1::cloud_publication_origin::Issuer::DeviceId(
                "original-device".into(),
            )),
        }),
    };
    let mut frames = vec![v1::CloudReplayFrame {
        frame: Some(Frame::Header(header)),
    }];
    for bytes in body.chunks(MAX_RELAY_FRAME_BYTES) {
        frames.push(v1::CloudReplayFrame {
            frame: Some(Frame::Data(bytes.to_vec())),
        });
    }
    frames.push(v1::CloudReplayFrame {
        frame: Some(Frame::EndRecord(v1::CloudRecordEnd {
            publication_id: meta.id().to_vec(),
        })),
    });
    frames.push(v1::CloudReplayFrame {
        frame: Some(Frame::PageEnd(v1::CloudPageEnd {
            through_cursor: cursor,
            has_more: false,
        })),
    });
    Ok(frames)
}

#[tokio::test]
async fn old_hub_is_explicitly_unsupported_and_sign_in_still_works() -> TestResult {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;
    assert!(matches!(
        client.cloud_offer().await,
        Err(CloudError::Unsupported)
    ));
    assert_eq!(
        client.session().ok_or("session missing")?.account_id,
        "acc-1"
    );
    Ok(())
}

#[tokio::test]
async fn authority_mismatch_and_logout_fence_the_captured_client() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let client = hub.signed_in_client().await;
    assert!(client.cloud_offer().await?.accept(&[0; 32]).is_err());
    let cloud = client
        .cloud_offer()
        .await?
        .accept(&hub.cloud().ok_or("fixture missing")?.authority())?;
    client.sign_out();
    assert!(matches!(
        cloud.check_source(),
        Err(CloudError::SourceChanged)
    ));
    assert!(matches!(
        cloud.begin_publication(metadata(&cloud, b"x")?),
        Err(CloudError::SourceChanged)
    ));
    assert!(
        hub.cloud()
            .ok_or("fixture missing")?
            .publications()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn publication_streams_bounded_chunks_and_checks_receipt_digest() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud) = cloud(&hub).await?;
    let body = vec![7; 3 * MAX_RELAY_FRAME_BYTES + 1];
    let expected = metadata(&cloud, &body)?;
    let mut upload = cloud.begin_publication(expected.clone())?;
    for bytes in body.chunks(MAX_RELAY_FRAME_BYTES) {
        upload.write(bytes).await?;
    }
    let receipt = upload.finish().await?;
    assert_eq!(receipt.publication_id, expected.id());
    assert_eq!(
        hub.cloud().ok_or("fixture missing")?.publications()[0].1,
        body
    );
    assert_eq!(
        hub.cloud().ok_or("fixture missing")?.frame_sizes(),
        vec![MAX_RELAY_FRAME_BYTES; 3]
            .into_iter()
            .chain([1])
            .collect::<Vec<_>>()
    );
    let changed = metadata(&cloud, b"new")?;
    let mut conflicting = cloud.begin_publication(changed.clone())?;
    conflicting.write(b"new").await?;
    assert!(
        matches!(conflicting.finish().await, Err(CloudError::Hub(error))
        if matches!(*error, nocterm_hub_client::ClientError::Status {code: nocterm_hub_client::StatusCode::AlreadyExists, ..}))
    );
    hub.cloud().ok_or("fixture missing")?.wrong_receipt();
    let fresh = PublicationMetadata::new(
        [7; 16],
        changed.binding().clone(),
        changed.total_bytes(),
        changed.digest(),
    )?;
    let mut upload = cloud.begin_publication(fresh)?;
    upload.write(b"new").await?;
    assert!(matches!(upload.finish().await, Err(CloudError::Protocol)));
    Ok(())
}

#[tokio::test]
async fn device_command_signature_comes_from_actual_sdk_subject_and_plaintext_stays_sealed()
-> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (client, cloud) = cloud(&hub).await?;
    let kdf = UnlockKdf::new(KdfParams::MINIMUM, vec![4; 16])?;
    let unlock = UnlockKey::from_vault_password("correct horse battery", &kdf)?;
    let keyset = client.create_keyset("acc-1", &unlock, &kdf).await?.keyset;
    let runner = RunnerEncryptionKey::generate()?;
    let context = CommandContext {
        nonce: [8; 16],
        expected_chat_revision: 0,
        run: None,
        kind: CommandKind::SubmitPrompt,
        issued_at_ms: now_ms(),
        accept_before_ms: now_ms() + 60_000,
    };
    let payload = b"private user prompt";
    let prepared = cloud.prepare_command(
        &keyset,
        &runner.public_key(),
        route(&cloud),
        context,
        payload,
    )?;
    let opened = open_command(
        &runner,
        &keyset.public_key(),
        &route(&cloud),
        prepared.ciphertext(),
    )?;
    assert_eq!(opened.command()?.payload(), payload);
    assert_eq!(
        opened.command()?.header().issuer().device_id,
        *cloud.subject().device()
    );
    assert_eq!(
        opened.command()?.header().issuer().signing_key,
        cloud.subject().signing_key()
    );
    assert_eq!(
        opened.command()?.header().issuer().access_token_digest,
        <[u8; 32]>::from(Sha256::digest(b"access"))
    );
    assert!(
        !prepared
            .ciphertext()
            .windows(payload.len())
            .any(|part| part == payload)
    );
    let receipt = cloud.publish_prepared(&prepared).await?;
    assert_eq!(receipt.publication_id, prepared.metadata().id());
    client.sign_out();
    assert!(matches!(
        cloud.publish_prepared(&prepared).await,
        Err(CloudError::SourceChanged)
    ));
    Ok(())
}

#[tokio::test]
async fn replay_borrows_one_verified_ciphertext_record_then_requires_page_eof() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud) = cloud(&hub).await?;
    let body = vec![3; MAX_RELAY_FRAME_BYTES + 1];
    let meta = metadata(&cloud, &body)?;
    hub.cloud()
        .ok_or("fixture missing")?
        .replay(delivered(&meta, &body, 1)?);
    let mut replay = cloud
        .replay(
            CloudSelector::RunnerInbox(route(&cloud).runner),
            0,
            4,
            100_000,
        )
        .await?;
    let CloudReplayItem::Record(mut record) = replay.next_record().await? else {
        return Err("record missing".into());
    };
    assert_eq!(record.metadata(), &meta);
    let mut actual = Vec::new();
    while let Some(bytes) = record.next_chunk().await? {
        actual.extend_from_slice(&bytes);
    }
    assert_eq!(actual, body);
    drop(record);
    assert!(matches!(
        replay.next_record().await?,
        CloudReplayItem::End {
            through: 1,
            has_more: false
        }
    ));
    Ok(())
}

#[tokio::test]
async fn abandoned_or_corrupted_record_cannot_advance_replay_cursor() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud) = cloud(&hub).await?;
    let meta = metadata(&cloud, b"hello")?;
    let harness = hub.cloud().ok_or("fixture missing")?;
    harness.replay(delivered(&meta, b"hello", 1)?);
    let mut replay = cloud
        .replay(CloudSelector::RunnerInbox(route(&cloud).runner), 0, 4, 100)
        .await?;
    drop(replay.next_record().await?);
    assert!(matches!(
        replay.next_record().await,
        Err(CloudError::Protocol)
    ));
    harness.replay(delivered(&meta, b"jello", 1)?);
    let mut replay = cloud
        .replay(CloudSelector::RunnerInbox(route(&cloud).runner), 0, 4, 100)
        .await?;
    let CloudReplayItem::Record(mut record) = replay.next_record().await? else {
        return Err("record missing".into());
    };
    assert!(record.next_chunk().await?.is_some());
    assert!(record.next_chunk().await.is_err());
    assert!(record.next_chunk().await.is_err());
    drop(record);
    assert!(replay.next_record().await.is_err());
    Ok(())
}

#[tokio::test]
async fn missing_end_bad_cursor_and_frames_after_page_end_fail_closed() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud) = cloud(&hub).await?;
    let meta = metadata(&cloud, b"hello")?;
    let harness = hub.cloud().ok_or("fixture missing")?;
    harness.replay(delivered(&meta, b"hello", 2)?);
    let mut replay = cloud
        .replay(CloudSelector::RunnerInbox(route(&cloud).runner), 0, 4, 100)
        .await?;
    assert!(replay.next_record().await.is_err());
    let mut frames = delivered(&meta, b"hello", 1)?;
    frames.remove(2);
    harness.replay(frames);
    let mut replay = cloud
        .replay(CloudSelector::RunnerInbox(route(&cloud).runner), 0, 4, 100)
        .await?;
    let CloudReplayItem::Record(mut record) = replay.next_record().await? else {
        return Err("record missing".into());
    };
    record.next_chunk().await?;
    assert!(record.next_chunk().await.is_err());
    drop(record);
    harness.replay(vec![
        v1::CloudReplayFrame {
            frame: Some(Frame::PageEnd(v1::CloudPageEnd {
                through_cursor: 0,
                has_more: false,
            })),
        },
        v1::CloudReplayFrame {
            frame: Some(Frame::Data(vec![1])),
        },
    ]);
    let mut replay = cloud
        .replay(CloudSelector::RunnerInbox(route(&cloud).runner), 0, 4, 100)
        .await?;
    assert!(replay.next_record().await.is_err());
    Ok(())
}

#[tokio::test]
async fn guarded_acquisition_keeps_capability_and_store_source_owners_with_closed_limits()
-> TestResult {
    use nocterm_hub_client::{
        ClientError, StatusCode,
        cloud::{capability_resident_bytes, capability_work_bytes},
        store_work_bytes,
    };
    use std::{sync::Arc, time::Duration};
    let hub = FakeHub::start_cloud().await;
    let client = hub.signed_in_client().await;
    assert!(std::ptr::eq(client.info(), client.clone().info()));
    client.require_cloud_metadata()?;
    assert_eq!(
        client.account_subject(),
        Some(("acc-1".into(), "dev-1".into()))
    );
    assert!(capability_resident_bytes() <= 16 * 1024);
    assert!(capability_work_bytes() > capability_resident_bytes());
    guarded_offer_transition(&client, &hub.cloud().ok_or("fixture")?.authority()).await?;
    assert!(store_work_bytes(0).is_err());
    assert!(store_work_bytes(4 * 1024 * 1024 + 1).is_err());
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    let mut store = client.store_with_residency(owner, 16 * 1024)?;
    assert!(store_work_bytes(16 * 1024)? >= 32 * 1024);
    assert_eq!(keyset_code(&mut store).await, tonic::Code::NotFound);
    assert_eq!(
        store
            .watch_changes(v1::WatchChangesRequest {
                collection_ids: vec!["c".into()],
            })
            .await
            .err()
            .ok_or("Store watch scope")?
            .code(),
        tonic::Code::PermissionDenied
    );
    hub.seen.hold_keyset_reply();
    let task = tokio::spawn(async move {
        store
            .get_account_keyset(v1::GetAccountKeysetRequest {})
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), hub.seen.wait_keyset_request()).await?;
    assert!(weak.upgrade().is_some());
    task.abort();
    let _ = task.await;
    hub.seen.release_keyset_reply();
    tokio::time::timeout(Duration::from_secs(5), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    hub.cloud()
        .ok_or("fixture")?
        .oversized_capability_reply(true);
    let response = client.cloud_offer_with_residency(Arc::new(())).await;
    assert!(
        matches!(response,Err(CloudError::Hub(error)) if matches!(*error,ClientError::Status {code:StatusCode::OutOfRange,..}))
    );
    hub.cloud()
        .ok_or("fixture")?
        .oversized_capability_reply(false);
    let mut old_store = client.store_with_residency(Arc::new(()), 16 * 1024)?;
    client.sign_out();
    assert!(client.account_subject().is_none());
    assert!(client.require_cloud_metadata().is_err());
    assert_eq!(
        keyset_code(&mut old_store).await,
        tonic::Code::Unauthenticated
    );
    Ok(())
}

async fn guarded_offer_transition(
    client: &nocterm_hub_client::HubClient,
    authority: &[u8; 32],
) -> TestResult {
    use std::{sync::Arc, time::Duration};
    let work = Arc::new(());
    let old = Arc::downgrade(&work);
    let offer = client.cloud_offer_with_residency(work).await?;
    assert!(old.upgrade().is_some());
    let resident = Arc::new(());
    let small = Arc::downgrade(&resident);
    let cloud = offer.accept_with_residency(authority, resident)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while old.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let cloned = cloud.clone();
    assert!(std::ptr::eq(cloud.namespace(), cloned.namespace()));
    assert!(std::ptr::eq(cloud.subject(), cloned.subject()));
    assert!(small.upgrade().is_some());
    drop(cloud);
    assert!(small.upgrade().is_some());
    drop(cloned);
    assert!(small.upgrade().is_none());
    Ok(())
}
async fn keyset_code(store: &mut nocterm_hub_client::ResidentStoreClient) -> tonic::Code {
    match store
        .get_account_keyset(v1::GetAccountKeysetRequest {})
        .await
    {
        Ok(_) => tonic::Code::Ok,
        Err(error) => error.code(),
    }
}
