//! Receipt reclaim: negotiation of bit 64, the retry horizon of a publication and the
//! runner-signed deletion of a chat, over the actual gRPC peer.
mod support;

use nocterm_hub_client::{
    cloud::{
        ChatRetirement, CloudClient, CloudError, RetireChatError, SignedChatDeletion,
        chat_deletion, receipt_reclaim_negotiated,
    },
    now_ms,
};
use nocterm_hub_model::cloud::{
    CloudRoute, CloudTextId, RunnerCoordinate,
    capabilities::{CLOUD_FEATURE_RECEIPT_RECLAIM, CapabilityLimits},
    reclaim::{MAX_RETRY_HORIZON_MS, ReclaimError},
    relay::{PublicationMetadata, RelayBinding},
};
use nocterm_keys::DeviceKey;
use sha2::{Digest, Sha256};
use std::error::Error;
use support::{FakeHub, cloud::Retirement};

type TestResult = Result<(), Box<dyn Error>>;
const HOUR: i64 = 60 * 60 * 1000;

async fn cloud(hub: &FakeHub) -> Result<CloudClient, Box<dyn Error>> {
    let client = hub.signed_in_client().await;
    let authority = hub.cloud().ok_or("fixture")?.authority();
    Ok(client.cloud_offer().await?.accept(&authority)?)
}
fn metadata(client: &CloudClient, bytes: &[u8]) -> Result<PublicationMetadata, Box<dyn Error>> {
    let route = CloudRoute {
        namespace: client.namespace().clone(),
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat_id: [4; 16],
        command_id: [5; 16],
    };
    Ok(PublicationMetadata::new(
        [6; 16],
        RelayBinding::command(route)?,
        u32::try_from(bytes.len())?,
        Sha256::digest(bytes).into(),
    )?)
}
fn signed(client: &CloudClient, key: &DeviceKey) -> Result<SignedChatDeletion, Box<dyn Error>> {
    let tombstone = chat_deletion(
        client.namespace().clone(),
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        [4; 16],
        CloudTextId::new("device-1")?,
        now_ms(),
    );
    Ok(SignedChatDeletion::sign(tombstone, key)?)
}
async fn publish(client: &CloudClient, horizon: Option<i64>) -> Result<(), Box<dyn Error>> {
    let body = b"sealed";
    let meta = metadata(client, body)?;
    let mut upload = match horizon {
        Some(at) => client.begin_publication_with_retry_until(meta, at)?,
        None => client.begin_publication(meta)?,
    };
    upload.write(body).await?;
    upload.finish().await?;
    Ok(())
}

#[tokio::test]
async fn bit_64_is_negotiated_only_when_the_hub_advertises_it() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let old = cloud(&hub).await?;
    assert!(!old.supports_receipt_reclaim());
    assert!(!receipt_reclaim_negotiated(CapabilityLimits::v1()));
    hub.cloud().ok_or("fixture")?.enable_receipt_reclaim();
    let new = cloud(&hub).await?;
    assert!(new.supports_receipt_reclaim());
    let mut limits = CapabilityLimits::v1();
    limits.features |= CLOUD_FEATURE_RECEIPT_RECLAIM;
    assert!(receipt_reclaim_negotiated(limits));
    Ok(())
}

#[tokio::test]
async fn publication_keeps_no_horizon_by_default_and_sends_a_negotiated_one() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let peer = hub.cloud().ok_or("fixture")?;
    peer.enable_receipt_reclaim();
    let client = cloud(&hub).await?;
    publish(&client, None).await?;
    let horizon = now_ms() + HOUR;
    publish(&client, Some(horizon)).await?;
    publish(&client, Some(0)).await?;
    assert_eq!(peer.retry_horizons(), vec![0, horizon, 0]);
    Ok(())
}

#[tokio::test]
async fn an_invalid_or_unnegotiated_horizon_is_refused_before_anything_is_sent() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let peer = hub.cloud().ok_or("fixture")?;
    let old = cloud(&hub).await?;
    let meta = metadata(&old, b"sealed")?;
    assert!(matches!(
        old.begin_publication_with_retry_until(meta.clone(), now_ms() + HOUR),
        Err(CloudError::Unsupported)
    ));
    peer.enable_receipt_reclaim();
    let client = cloud(&hub).await?;
    for horizon in [
        now_ms() - HOUR,
        now_ms() + MAX_RETRY_HORIZON_MS + HOUR,
        i64::MIN,
    ] {
        assert!(matches!(
            client.begin_publication_with_retry_until(meta.clone(), horizon),
            Err(CloudError::Reclaim(ReclaimError::Horizon))
        ));
    }
    assert!(peer.retry_horizons().is_empty());
    Ok(())
}

#[tokio::test]
async fn retiring_a_chat_sends_the_runner_signed_tombstone_and_reports_compaction() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let peer = hub.cloud().ok_or("fixture")?;
    peer.enable_receipt_reclaim();
    let client = cloud(&hub).await?;
    let key = DeviceKey::from_seed(&[0x72; 32]);
    let deletion = signed(&client, &key)?;
    peer.script_retirement(Retirement::Pending);
    assert_eq!(
        client.retire_chat(&deletion).await?,
        ChatRetirement { compacted: false }
    );
    peer.script_retirement(Retirement::Compacted);
    assert!(client.retire_chat(&deletion).await?.compacted);
    let seen = peer.retirements();
    assert_eq!(seen.len(), 2);
    assert_eq!(&seen[1].tombstone, deletion.tombstone());
    seen[1]
        .tombstone
        .verify(&key.public_key(), &seen[1].signature)?;
    assert_eq!(seen[1].signature, deletion.signature());
    Ok(())
}

#[tokio::test]
async fn retirement_refusals_are_typed() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let peer = hub.cloud().ok_or("fixture")?;
    let old = cloud(&hub).await?;
    let key = DeviceKey::from_seed(&[0x72; 32]);
    let deletion = signed(&old, &key)?;
    assert!(matches!(
        old.retire_chat(&deletion).await,
        Err(RetireChatError::Unsupported)
    ));
    peer.enable_receipt_reclaim();
    let client = cloud(&hub).await?;
    peer.script_retirement(Retirement::AlreadyRetired);
    assert!(matches!(
        client.retire_chat(&deletion).await,
        Err(RetireChatError::Retired)
    ));
    peer.script_retirement(Retirement::OutOfBounds);
    assert!(matches!(
        client.retire_chat(&deletion).await,
        Err(RetireChatError::Bounds)
    ));
    // A tombstone of another account's namespace never leaves the client.
    let mut tombstone = deletion.tombstone().clone();
    tombstone.namespace.account_id = CloudTextId::new("another-account")?;
    let foreign = SignedChatDeletion::sign(tombstone, &key)?;
    let before = peer.retirements().len();
    assert!(matches!(
        client.retire_chat(&foreign).await,
        Err(RetireChatError::Namespace)
    ));
    assert_eq!(peer.retirements().len(), before);
    Ok(())
}

#[test]
fn a_stored_deletion_is_rebound_only_with_a_valid_runner_signature() -> TestResult {
    let key = DeviceKey::from_seed(&[0x72; 32]);
    let tombstone = chat_deletion(
        nocterm_hub_model::cloud::CloudNamespace {
            hub_instance_id: CloudTextId::new("hub")?,
            account_id: CloudTextId::new("account")?,
        },
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        [4; 16],
        CloudTextId::new("device-1")?,
        1_000,
    );
    let good = SignedChatDeletion::sign(tombstone.clone(), &key)?;
    let rebound =
        SignedChatDeletion::from_parts(tombstone.clone(), good.signature(), &key.public_key())?;
    assert_eq!(rebound, good);
    assert!(matches!(
        SignedChatDeletion::from_parts(tombstone.clone(), [0; 64], &key.public_key()),
        Err(ReclaimError::Signature(_))
    ));
    let other = DeviceKey::from_seed(&[0x73; 32]);
    assert!(matches!(
        SignedChatDeletion::from_parts(tombstone, good.signature(), &other.public_key()),
        Err(ReclaimError::Signature(_))
    ));
    Ok(())
}
