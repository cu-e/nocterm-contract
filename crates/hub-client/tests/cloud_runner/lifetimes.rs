//! Private restore and actual asynchronous upload residency boundaries.
use super::*;
use nocterm_hub_client::{cloud::CloudUpload, now_ms};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn stored_runner_with_expired_access_requires_explicit_refresh_before_rpc() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, _, runner) = enrolled(&hub).await?;
    let mut stored = runner.session()?.into_response();
    stored.access_expires_at_ms = now_ms() - 1;
    assert!(RunnerSession::from_response(stored.clone(), runner.subject()).is_err());
    let session = RunnerSession::from_stored_response(stored.clone(), runner.subject())?;
    let restored = CloudRunner::restore(
        &hub.endpoint(),
        runner.subject().clone(),
        hub.cloud().ok_or("fixture")?.authority(),
        DeviceKey::from_seed(&[0x72; 32]),
        session,
    )
    .await?;
    assert!(restored.heartbeat(vec![1]).await.is_err());
    restored.refresh().await?;
    assert!(restored.heartbeat(vec![2]).await? > 0);
    for invalid in 0..7 {
        let mut value = stored.clone();
        match invalid {
            0 => value.account_id = "other".into(),
            1 => value.runner_id = vec![9; 16],
            2 => value.access_expires_at_ms = 0,
            3 => value.refresh_expires_at_ms = now_ms() - 1,
            4 => value.access_token.clear(),
            5 => value.refresh_token = "x".repeat(257),
            _ => value.capability_version = 0,
        }
        assert!(RunnerSession::from_stored_response(value, runner.subject()).is_err());
    }
    Ok(())
}

struct Residency(Arc<AtomicUsize>);
impl Drop for Residency {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn runner_upload_residency_survives_cancel_until_actual_rpc_task_drop() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud, runner) = enrolled(&hub).await?;
    let harness = hub.cloud().ok_or("fixture")?;
    harness.hold_receipt();
    let body = [7; 128];
    let metadata = PublicationMetadata::new(
        [31; 16],
        RelayBinding::event(record_context(&cloud, [4; 16], 1)?),
        u32::try_from(body.len())?,
        Sha256::digest(body).into(),
    )?;
    let released = Arc::new(AtomicUsize::new(0));
    let residency = Arc::new(Residency(released.clone()));
    let mut upload = runner.begin_publication_with_residency(metadata, residency.clone())?;
    drop(residency);
    upload.write(&body).await?;
    let mut pending = Box::pin(upload.finish());
    tokio::select! {
        result = &mut pending => return Err(format!("unexpected early receipt: {result:?}").into()),
        _ = harness.wait_published() => {}
    }
    drop(pending);
    // The current-thread runtime has not polled the aborted SDK task yet.
    assert_eq!(released.load(Ordering::SeqCst), 0);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while released.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(released.load(Ordering::SeqCst), 1);
    harness.release_receipt();
    Ok(())
}

#[tokio::test]
async fn runner_upload_uses_smaller_signed_frame_limit_and_clamped_work_budget() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    hub.cloud().ok_or("fixture")?.set_max_frame_bytes(1024);
    let (_, cloud, runner) = enrolled(&hub).await?;
    let body = vec![9; 5000];
    let metadata = PublicationMetadata::new(
        [32; 16],
        RelayBinding::event(record_context(&cloud, [4; 16], 1)?),
        u32::try_from(body.len())?,
        Sha256::digest(&body).into(),
    )?;
    let mut upload = runner.begin_publication(metadata)?;
    assert_eq!(upload.max_frame_bytes(), 1024);
    for chunk in body.chunks(usize::try_from(upload.max_frame_bytes())?) {
        upload.write(chunk).await?;
    }
    assert!(upload.finish().await?.cursor > 0);
    let frames = hub.cloud().ok_or("fixture")?.frame_sizes();
    assert!(frames.len() > 1 && frames.iter().all(|size| *size <= 1024));
    assert!(CloudUpload::buffer_work_bytes(1)? < CloudUpload::buffer_work_bytes(body.len())?);
    assert!(CloudUpload::buffer_work_bytes(0).is_err());
    assert!(
        CloudUpload::buffer_work_bytes(nocterm_hub_model::cloud::MAX_ENVELOPE_BYTES + 1).is_err()
    );
    Ok(())
}

#[tokio::test]
async fn guarded_runner_and_device_replay_and_ack_keep_original_stream_data() -> TestResult {
    use nocterm_hub_client::cloud::{CloudReplay, CloudReplayItem, acknowledgement_work_bytes};
    let hub = FakeHub::start_cloud().await;
    let (_, cloud, runner) = enrolled(&hub).await?;
    let body = vec![42; 5000];
    let context = record_context(&cloud, [4; 16], 1)?;
    assert_eq!(
        publish_record(&runner, [45; 16], RelayBinding::event(context), &body).await?,
        1
    );
    let selector = CloudSelector::Chat {
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat: [4; 16],
    };
    assert!(acknowledgement_work_bytes() <= 16 * 1024);
    assert!(CloudReplay::buffer_work_bytes() > acknowledgement_work_bytes());
    for device in [false, true] {
        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        let mut replay = if device {
            cloud
                .replay_with_residency(selector.clone(), 0, 1, 8192, owner.clone())
                .await?
        } else {
            runner
                .replay_with_residency(selector.clone(), 0, 1, 8192, owner.clone())
                .await?
        };
        drop(owner);
        assert!(weak.upgrade().is_some());
        let CloudReplayItem::Record(mut record) = replay.next_record().await? else {
            return Err("record missing".into());
        };
        let mut received = Vec::new();
        while let Some(chunk) = record.next_chunk().await? {
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, body);
        drop(record);
        assert!(matches!(
            replay.next_record().await?,
            CloudReplayItem::End {
                through: 1,
                has_more: false
            }
        ));
        assert!(weak.upgrade().is_some());
        drop(replay);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let owner = Arc::new(());
        let acknowledged = if device {
            cloud
                .acknowledge_with_residency(&selector, 1, owner)
                .await?
        } else {
            runner
                .acknowledge_with_residency(&selector, 1, owner)
                .await?
        };
        assert_eq!(acknowledged, 1);
    }
    Ok(())
}
