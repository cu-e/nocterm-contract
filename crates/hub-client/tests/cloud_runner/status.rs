//! Real unary bodies, captured sources and bounded decoded status ownership.
use super::*;
use nocterm_hub_client::cloud::{MAX_STATUS_BYTES, MAX_STATUS_WIRE_BYTES, status_work_bytes};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn guarded_status_retains_result_and_refuses_oversized_or_replaced_source() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (client, cloud, runner) = enrolled(&hub).await?;
    let peer = hub.cloud().ok_or("fixture")?;
    assert!(status_work_bytes() >= 3 * MAX_STATUS_WIRE_BYTES);
    let body = vec![9; MAX_STATUS_BYTES];
    assert!(
        runner
            .heartbeat_with_residency(body.clone(), Arc::new(()))
            .await?
            > 0
    );
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    let status = cloud.runner_status_with_residency([2; 16], owner).await?;
    assert_eq!(status.signed_status(), body);
    assert!(status.received_at_ms() > 0);
    assert!(weak.upgrade().is_some());
    drop(status);
    wait_released(&weak).await?;
    peer.status_bytes(vec![0; MAX_STATUS_WIRE_BYTES * 2]);
    let oversized = cloud
        .runner_status_with_residency([2; 16], Arc::new(()))
        .await;
    assert!(matches!(oversized, Err(CloudError::Hub(error))
        if matches!(*error, nocterm_hub_client::ClientError::Status {code:nocterm_hub_client::StatusCode::OutOfRange,..})));
    peer.status_bytes(vec![1]);
    let before = peer.status_calls();
    peer.hold_status_reply();
    let mut pending = Box::pin(cloud.runner_status_with_residency([2; 16], Arc::new(())));
    tokio::select! { result=&mut pending => return Err(format!("early status {result:?}").into()),
    ()=peer.wait_status_after(before)=>{} }
    client.sign_out();
    peer.release_status_reply();
    assert!(matches!(pending.await, Err(CloudError::SourceChanged)));
    Ok(())
}

#[tokio::test]
async fn guarded_heartbeat_cancellation_and_deadlines_preserve_original_runner_source() -> TestResult
{
    let hub = FakeHub::start_cloud().await;
    let (_, _, runner) = enrolled(&hub).await?;
    let peer = hub.cloud().ok_or("fixture")?;
    let (access, refresh) = runner.credential_deadlines()?;
    assert!(access > nocterm_hub_client::now_ms() && refresh >= access);
    let before = peer.status_calls();
    peer.hold_status_reply();
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    let mut pending = Box::pin(runner.heartbeat_with_residency(vec![7; 4096], owner));
    tokio::select! { result=&mut pending => return Err(format!("early heartbeat {result:?}").into()),
    ()=peer.wait_status_after(before)=>{} }
    assert!(weak.upgrade().is_some());
    drop(pending);
    peer.release_status_reply();
    wait_released(&weak).await?;
    let before = peer.status_calls();
    assert!(matches!(
        runner
            .heartbeat_with_residency(vec![0; 4097], Arc::new(()))
            .await,
        Err(CloudError::Protocol)
    ));
    assert_eq!(peer.status_calls(), before);
    let before = peer.status_calls();
    peer.hold_status_reply();
    let mut revoked = Box::pin(runner.heartbeat_with_residency(vec![2], Arc::new(())));
    tokio::select! { result=&mut revoked => return Err(format!("early heartbeat {result:?}").into()),
    ()=peer.wait_status_after(before)=>{} }
    runner.revoke_local();
    peer.release_status_reply();
    assert!(matches!(revoked.await, Err(CloudError::SourceChanged)));
    assert!(matches!(
        runner.credential_deadlines(),
        Err(CloudError::SourceChanged)
    ));
    assert!(matches!(
        runner.heartbeat_with_residency(vec![1], Arc::new(())).await,
        Err(CloudError::SourceChanged)
    ));
    Ok(())
}
async fn wait_released(weak: &std::sync::Weak<()>) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}
