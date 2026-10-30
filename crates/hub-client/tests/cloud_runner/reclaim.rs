//! A runner signs the deletion of its own chat and announces it without a session proof.
use super::*;
use nocterm_hub_client::cloud::{RetireChatError, SignedChatDeletion};

fn sealed_body() -> (Vec<u8>, [u8; 32]) {
    let body = b"sealed".to_vec();
    let digest = Sha256::digest(&body).into();
    (body, digest)
}

#[tokio::test]
async fn runner_retirement_is_signed_by_the_proof_key_and_carries_no_session() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let peer = hub.cloud().ok_or("fixture")?;
    peer.enable_receipt_reclaim();
    let (_, cloud, runner) = enrolled(&hub).await?;
    assert!(runner.supports_receipt_reclaim());
    let requested_by = CloudTextId::new("device-1")?;
    let deletion = runner.sign_chat_deletion(3, [4; 16], requested_by, 1_000)?;
    assert_eq!(deletion.tombstone().namespace, *cloud.namespace());
    assert_eq!(deletion.tombstone().runner.id, [2; 16]);
    let answer = runner.retire_chat(&deletion).await?;
    assert!(answer.compacted);
    let seen = peer.retirements();
    let key = DeviceKey::from_seed(&[0x72; 32]);
    seen[0]
        .tombstone
        .verify(&key.public_key(), &seen[0].signature)?;
    assert!(!seen[0].runner_claim && !seen[0].device_session);
    assert_eq!(
        SignedChatDeletion::from_parts(
            seen[0].tombstone.clone(),
            deletion.signature(),
            &key.public_key(),
        )?,
        deletion
    );
    Ok(())
}

#[tokio::test]
async fn runner_retirement_and_horizon_need_the_negotiated_capability() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud, runner) = enrolled(&hub).await?;
    assert!(!runner.supports_receipt_reclaim());
    let deletion = runner.sign_chat_deletion(3, [4; 16], CloudTextId::new("device-1")?, 1_000)?;
    assert!(matches!(
        runner.retire_chat(&deletion).await,
        Err(RetireChatError::Unsupported)
    ));
    let (body, digest) = sealed_body();
    let route = nocterm_hub_model::cloud::CloudRoute {
        namespace: cloud.namespace().clone(),
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat_id: [4; 16],
        command_id: [5; 16],
    };
    let meta = PublicationMetadata::new(
        [6; 16],
        RelayBinding::command(route)?,
        u32::try_from(body.len())?,
        digest,
    )?;
    let at = nocterm_hub_client::now_ms() + 60_000;
    assert!(matches!(
        runner.begin_publication_with_retry_until(meta, at),
        Err(CloudError::Unsupported)
    ));
    Ok(())
}
