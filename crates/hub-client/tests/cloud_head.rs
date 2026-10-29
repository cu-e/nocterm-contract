//! Actual tonic framing, pinned witness verification and original login fences.
mod support;
use nocterm_hub_client::{
    HubClient, Keyset,
    cloud::{CloudClient, CloudError, CloudRunner, DeviceHeadProbes, RunnerHeadProbes},
    now_ms,
};
use nocterm_hub_model::cloud::{
    CloudTextId, RunnerCoordinate,
    head::{
        CatalogHeadPage, ChatHead, HeadProbeKeys, HeadProbeScope, HeadTarget, HeadValue,
        HeadWitness, MAX_HEAD_REPLY_ENVELOPE_BYTES,
    },
    runner_auth::RunnerProofSubject,
};
use nocterm_keys::{
    DeviceKey, KdfParams, UnlockKdf, UnlockKey,
    cloud::{RunnerEncryptionKey, RunnerSigningKey, seal_head_witness},
};
use std::time::Duration;
use support::FakeHub;
use zeroize::Zeroizing;
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Setup {
    client: HubClient,
    cloud: CloudClient,
    runner: CloudRunner,
    keyset: Keyset,
    encryption: RunnerEncryptionKey,
    signing: RunnerSigningKey,
    scope: HeadProbeScope,
}
impl Setup {
    async fn new(hub: &FakeHub) -> Result<Self, Box<dyn std::error::Error>> {
        let harness = hub.cloud().ok_or("fixture")?;
        harness.enable_head_probes();
        let client = hub.signed_in_client().await;
        let cloud = client.cloud_offer().await?.accept(&harness.authority())?;
        let kdf = UnlockKdf::new(KdfParams::MINIMUM, vec![4; 16])?;
        let unlock = UnlockKey::from_vault_password("fixture password", &kdf)?;
        let keyset = client.create_keyset("acc-1", &unlock, &kdf).await?.keyset;
        let proof = DeviceKey::from_seed(&[0x72; 32]);
        let ticket = cloud
            .create_runner_grant([2; 16], proof.public_key())
            .await?;
        let subject = RunnerProofSubject {
            raw_hub_id: CloudTextId::new(support::HUB_ID)?,
            namespace: cloud.namespace().clone(),
            runner_id: [2; 16],
            proof_key: proof.public_key(),
        };
        let runner = CloudRunner::redeem(
            &hub.endpoint(),
            subject,
            harness.authority(),
            proof,
            Zeroizing::new(ticket.token().to_owned()),
        )
        .await?;
        let encryption = RunnerEncryptionKey::generate()?;
        let signing = RunnerSigningKey::generate()?;
        let scope = HeadProbeScope {
            namespace: cloud.namespace().clone(),
            runner: RunnerCoordinate {
                id: [2; 16],
                key_epoch: 3,
            },
            keys: HeadProbeKeys {
                account: keyset.public_key().to_bytes(),
                runner_encryption: encryption.public_key().to_bytes(),
                runner_signing: signing.public_key(),
            },
        };
        Ok(Self {
            client,
            cloud,
            runner,
            keyset,
            encryption,
            signing,
            scope,
        })
    }
    fn ports(&self) -> Result<(DeviceHeadProbes, RunnerHeadProbes), CloudError> {
        Ok((
            self.cloud.head_probes()?,
            self.runner.head_probes(self.scope.clone())?,
        ))
    }
    async fn answer(&self, peer: &RunnerHeadProbes, value: HeadValue) -> TestResult {
        let incoming = peer.next(Duration::from_secs(2)).await?.ok_or("query")?;
        let signed = incoming.open(&self.encryption, &self.scope, now_ms())?;
        let witness = self.signing.attest_head(HeadWitness {
            query: signed.query().clone(),
            observed_at_ms: now_ms(),
            value,
        })?;
        incoming
            .reply(seal_head_witness(&self.encryption, &witness)?)
            .await?;
        Ok(())
    }
}
fn empty_catalog() -> HeadValue {
    HeadValue::Catalog(Box::new(CatalogHeadPage {
        revision: 1,
        digest: [3; 32],
        total_chats: 0,
        after: None,
        chats: vec![],
        has_more: false,
    }))
}
#[tokio::test]
async fn fresh_catalog_crosses_real_tonic_without_chat_key_or_ordinary_publication() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let (device, runner) = setup.ports()?;
    let prepared = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    let expected = prepared.query().clone();
    let (response, answer) = tokio::join!(
        device.request(prepared),
        setup.answer(&runner, empty_catalog())
    );
    answer?;
    let verified = response?.open(&setup.keyset, now_ms())?;
    assert_eq!(&verified.witness().query, &expected);
    assert_eq!(verified.witness().value, empty_catalog());
    assert!(hub.cloud().ok_or("fixture")?.publications().is_empty());
    Ok(())
}
#[tokio::test]
async fn pending_and_completed_probes_cannot_publish_after_original_logout() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let (device, runner) = setup.ports()?;
    let prepared = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    let (response, answer) = tokio::join!(
        device.request(prepared),
        setup.answer(&runner, empty_catalog())
    );
    answer?;
    let completed = response?;
    let unpolled = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    setup.client.sign_out();
    assert!(matches!(
        completed.open(&setup.keyset, now_ms()),
        Err(CloudError::SourceChanged)
    ));
    assert!(matches!(
        device.request(unpolled).await,
        Err(CloudError::SourceChanged)
    ));
    // Independent runner authentication survives the observing device logout.
    assert!(setup.runner.heartbeat(vec![1]).await? > 0);
    Ok(())
}
#[tokio::test]
async fn another_device_offer_cannot_send_the_original_pending_probe() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let (device, _) = setup.ports()?;
    let prepared = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    let next = hub.signed_in_client().await;
    let next = next
        .cloud_offer()
        .await?
        .accept(&hub.cloud().ok_or("fixture")?.authority())?
        .head_probes()?;
    assert!(matches!(
        next.request(prepared).await,
        Err(CloudError::SourceChanged)
    ));
    Ok(())
}
#[tokio::test]
async fn omitted_fresh_head_capability_is_explicitly_unsupported() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let client = hub.signed_in_client().await;
    let old = client
        .cloud_offer()
        .await?
        .accept(&hub.cloud().ok_or("fixture")?.authority())?;
    assert!(matches!(old.head_probes(), Err(CloudError::Unsupported)));
    Ok(())
}
#[tokio::test]
async fn original_challenge_and_real_pins_reject_signed_reply_to_another_request() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let (device, runner) = setup.ports()?;
    let prepared = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    let serve = async {
        let incoming = runner.next(Duration::from_secs(2)).await?.ok_or("query")?;
        let signed = incoming.open(&setup.encryption, &setup.scope, now_ms())?;
        let mut changed = signed.query().clone();
        changed.challenge[0] ^= 1;
        let witness = setup.signing.attest_head(HeadWitness {
            query: changed,
            observed_at_ms: now_ms(),
            value: empty_catalog(),
        })?;
        incoming
            .reply(seal_head_witness(&setup.encryption, &witness)?)
            .await?;
        TestResult::Ok(())
    };
    let (response, answer) = tokio::join!(device.request(prepared), serve);
    answer?;
    assert!(response?.open(&setup.keyset, now_ms()).is_err());
    Ok(())
}
#[tokio::test]
async fn zero_event_chat_has_no_fabricated_event_and_current_writer_is_separate() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let (device, runner) = setup.ports()?;
    let prepared = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Chat {
            chat_id: [4; 16],
            chat_key_epoch: 1,
        },
        now_ms(),
    )?;
    let value = HeadValue::Chat(Box::new(ChatHead {
        chat_id: [4; 16],
        chat_key_epoch: 1,
        current_writer: Some(2),
        control_revision: 0,
        deleted: false,
        head: None,
        retained_from: 0,
        snapshot: None,
    }));
    let (response, answer) = tokio::join!(
        device.request(prepared),
        setup.answer(&runner, value.clone())
    );
    answer?;
    assert_eq!(
        response?.open(&setup.keyset, now_ms())?.witness().value,
        value
    );
    Ok(())
}
#[tokio::test]
async fn reply_full_message_limit_includes_scope_and_envelope_through_real_tonic() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let (device, runner) = setup.ports()?;
    let scope_bytes = setup.scope.canonical_bytes()?;
    let maximum = MAX_HEAD_REPLY_ENVELOPE_BYTES - scope_bytes.len() - 128;
    let prepared = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    let serve = async {
        let incoming = runner.next(Duration::from_secs(2)).await?.ok_or("query")?;
        // This malicious payload reaches the real bounded tonic reply; it can
        // never pass the account opener's pinned box/signature verification.
        incoming.reply(vec![1; maximum]).await?;
        TestResult::Ok(())
    };
    let (response, answer) = tokio::join!(device.request(prepared), serve);
    answer?;
    assert!(response?.open(&setup.keyset, now_ms()).is_err());
    let prepared = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    let pending = tokio::spawn(async move { device.request(prepared).await });
    let incoming = runner.next(Duration::from_secs(2)).await?.ok_or("query")?;
    assert!(matches!(
        incoming.reply(vec![1; maximum + 1]).await,
        Err(CloudError::Protocol)
    ));
    pending.abort();
    let _ = pending.await;
    tokio::time::timeout(
        Duration::from_secs(2),
        hub.cloud().ok_or("fixture")?.wait_head_probes(0),
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn per_account_probe_capacity_is_bounded_and_cancellation_releases_slots() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let (device, _) = setup.ports()?;
    let harness = hub.cloud().ok_or("fixture")?;
    let mut tasks = vec![];
    for count in 1..=32 {
        let prepared = device.prepare(
            &setup.keyset,
            setup.scope.clone(),
            HeadTarget::Catalog { after: None },
            now_ms(),
        )?;
        let source = device.clone();
        tasks.push(tokio::spawn(async move { source.request(prepared).await }));
        tokio::time::timeout(Duration::from_secs(2), harness.wait_head_probes(count)).await?;
    }
    let extra = device.prepare(
        &setup.keyset,
        setup.scope.clone(),
        HeadTarget::Catalog { after: None },
        now_ms(),
    )?;
    assert!(
        matches!(device.request(extra).await,Err(CloudError::Hub(error)) if matches!(*error,nocterm_hub_client::ClientError::Status {code:nocterm_hub_client::StatusCode::ResourceExhausted,..}))
    );
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    tokio::time::timeout(Duration::from_secs(2), harness.wait_head_probes(0)).await?;
    Ok(())
}
