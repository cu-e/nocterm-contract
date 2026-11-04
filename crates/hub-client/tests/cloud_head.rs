//! Actual tonic framing of fresh-head probes: a device sends the core's sealed query
//! (`nocterm-cloud-device`, `HubClient::probe_head`) and the runner answers it with
//! `RunnerHeadProbes`; the account opens the pinned witness.
mod support;
use nocterm_cloud_device::{
    AccountScope,
    flow::Input,
    probe::{ProbeTarget, SealedHeadProbe, UnsignedHeadProbe},
    records::{RunnerPins, TrustedRunner},
};
use nocterm_hub_client::{
    ClientError, CloudCallError, HubClient, Keyset, StatusCode,
    cloud::{CloudRunner, RunnerHeadProbes},
    now_ms,
};
use nocterm_hub_model::cloud::{
    CloudTextId, RunnerCoordinate,
    head::{
        CatalogHeadPage, ChatHead, HeadProbeKeys, HeadProbeScope, HeadValue, HeadWitness,
        MAX_HEAD_REPLY_ENVELOPE_BYTES,
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
const RUNNER: RunnerCoordinate = RunnerCoordinate {
    id: [2; 16],
    key_epoch: 3,
};
struct Setup {
    client: HubClient,
    runner: CloudRunner,
    keyset: Keyset,
    account: AccountScope,
    trusted: TrustedRunner,
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
            .create_runner_grant(RUNNER.id, proof.public_key())
            .await?;
        let subject = RunnerProofSubject {
            raw_hub_id: CloudTextId::new(support::HUB_ID)?,
            namespace: cloud.namespace().clone(),
            runner_id: RUNNER.id,
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
        let account = AccountScope::derive(
            support::HUB_ID,
            harness.authority(),
            "acc-1",
            keyset.public_key().to_bytes(),
        )?;
        let pins = RunnerPins {
            encryption: encryption.public_key().to_bytes(),
            signing: signing.public_key(),
            proof: [0x72; 32],
        };
        let trusted = TrustedRunner::new(RUNNER, pins, "build box")?;
        let scope = HeadProbeScope {
            namespace: cloud.namespace().clone(),
            runner: RUNNER,
            keys: HeadProbeKeys {
                account: keyset.public_key().to_bytes(),
                runner_encryption: pins.encryption,
                runner_signing: pins.signing,
            },
        };
        Ok(Self {
            client,
            runner,
            keyset,
            account,
            trusted,
            encryption,
            signing,
            scope,
        })
    }
    fn port(&self) -> Result<RunnerHeadProbes, Box<dyn std::error::Error>> {
        Ok(self.runner.head_probes(self.scope.clone())?)
    }
    /// The core's sealed query, signed by this client's device key.
    fn probe(&self, target: ProbeTarget) -> Result<SealedHeadProbe, Box<dyn std::error::Error>> {
        let probe = UnsignedHeadProbe::new(
            &self.account,
            self.keyset.public_key().to_bytes(),
            &self.trusted,
            &self.client.cloud_device()?,
            target,
            now_ms(),
        )?;
        let signature = self.client.sign_cloud(&probe.sign_request()?)?;
        Ok(probe.seal(self.keyset.key_pair(), &signature)?)
    }
    async fn send(&self, sealed: &SealedHeadProbe) -> Result<Input, CloudCallError> {
        self.client.probe_head(&sealed.request()).await
    }
    fn open(
        &self,
        sealed: &SealedHeadProbe,
        reply: Input,
    ) -> Result<HeadValue, Box<dyn std::error::Error>> {
        let Input::ProbeReply {
            scope,
            probe_id,
            ciphertext,
        } = reply
        else {
            return Err("no reply".into());
        };
        Ok(sealed.open_reply(
            self.keyset.key_pair(),
            &scope,
            &probe_id,
            &ciphertext,
            now_ms(),
        )?)
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
    let runner = setup.port()?;
    let sealed = setup.probe(ProbeTarget::Catalog(None))?;
    let (response, answer) =
        tokio::join!(setup.send(&sealed), setup.answer(&runner, empty_catalog()));
    answer?;
    assert_eq!(setup.open(&sealed, response?)?, empty_catalog());
    assert!(hub.cloud().ok_or("fixture")?.publications().is_empty());
    Ok(())
}
#[tokio::test]
async fn a_signed_out_device_sends_no_probe_and_the_runner_keeps_its_own_authentication()
-> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let sealed = setup.probe(ProbeTarget::Catalog(None))?;
    setup.client.sign_out();
    assert!(matches!(
        setup.send(&sealed).await,
        Err(CloudCallError::Session(ClientError::NotSignedIn))
    ));
    tokio::time::timeout(
        Duration::from_secs(2),
        hub.cloud().ok_or("fixture")?.wait_head_probes(0),
    )
    .await?;
    // Independent runner authentication survives the observing device logout.
    assert!(setup.runner.heartbeat(vec![1]).await? > 0);
    Ok(())
}
#[tokio::test]
async fn original_challenge_and_real_pins_reject_signed_reply_to_another_request() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let runner = setup.port()?;
    let sealed = setup.probe(ProbeTarget::Catalog(None))?;
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
    let (response, answer) = tokio::join!(setup.send(&sealed), serve);
    answer?;
    assert!(setup.open(&sealed, response?).is_err());
    Ok(())
}
#[tokio::test]
async fn zero_event_chat_has_no_fabricated_event_and_current_writer_is_separate() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let runner = setup.port()?;
    let sealed = setup.probe(ProbeTarget::Chat {
        chat_id: [4; 16],
        key_epoch: 1,
    })?;
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
    let (response, answer) =
        tokio::join!(setup.send(&sealed), setup.answer(&runner, value.clone()));
    answer?;
    assert_eq!(setup.open(&sealed, response?)?, value);
    Ok(())
}
#[tokio::test]
async fn reply_full_message_limit_includes_scope_and_envelope_through_real_tonic() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    let runner = setup.port()?;
    let scope_bytes = setup.scope.canonical_bytes()?;
    let maximum = MAX_HEAD_REPLY_ENVELOPE_BYTES - scope_bytes.len() - 128;
    let sealed = setup.probe(ProbeTarget::Catalog(None))?;
    let serve = async {
        let incoming = runner.next(Duration::from_secs(2)).await?.ok_or("query")?;
        // This malicious payload reaches the real bounded tonic reply; it can
        // never pass the account opener's pinned box/signature verification.
        incoming.reply(vec![1; maximum]).await?;
        TestResult::Ok(())
    };
    let (response, answer) = tokio::join!(setup.send(&sealed), serve);
    answer?;
    assert!(setup.open(&sealed, response?).is_err());
    let sealed = setup.probe(ProbeTarget::Catalog(None))?;
    let client = setup.client.clone();
    let request = sealed.request();
    let pending = tokio::spawn(async move { client.probe_head(&request).await });
    let incoming = runner.next(Duration::from_secs(2)).await?.ok_or("query")?;
    assert!(matches!(
        incoming.reply(vec![1; maximum + 1]).await,
        Err(nocterm_hub_client::cloud::CloudError::Protocol)
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
    let harness = hub.cloud().ok_or("fixture")?;
    let mut tasks = vec![];
    for count in 1..=32 {
        let request = setup.probe(ProbeTarget::Catalog(None))?.request();
        let client = setup.client.clone();
        tasks.push(tokio::spawn(
            async move { client.probe_head(&request).await },
        ));
        tokio::time::timeout(Duration::from_secs(2), harness.wait_head_probes(count)).await?;
    }
    let extra = setup.probe(ProbeTarget::Catalog(None))?;
    assert!(matches!(
        setup.send(&extra).await,
        Err(CloudCallError::Hub {
            error: ClientError::Status {
                code: StatusCode::ResourceExhausted,
                ..
            },
            ..
        })
    ));
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    tokio::time::timeout(Duration::from_secs(2), harness.wait_head_probes(0)).await?;
    Ok(())
}

#[tokio::test]
async fn guarded_runner_head_owners_follow_a_real_fresh_probe_and_decoded_query() -> TestResult {
    use nocterm_hub_client::cloud::{
        head_decoded_metadata_bytes, head_query_work_bytes, head_reply_work_bytes,
    };
    use std::sync::Arc;
    let hub = FakeHub::start_cloud().await;
    let setup = Setup::new(&hub).await?;
    assert!(
        head_query_work_bytes() > nocterm_hub_model::cloud::head::MAX_HEAD_QUERY_ENVELOPE_BYTES
    );
    assert!(head_reply_work_bytes() > MAX_HEAD_REPLY_ENVELOPE_BYTES);
    assert!(head_decoded_metadata_bytes() > 64 * std::mem::size_of::<ChatHead>());
    let sealed = setup.probe(ProbeTarget::Catalog(None))?;
    let client = setup.client.clone();
    let request = sealed.request();
    let pending = tokio::spawn(async move { client.probe_head(&request).await });
    let runner_owner = Arc::new(());
    let runner_weak = Arc::downgrade(&runner_owner);
    let runner = setup
        .runner
        .head_probes_with_residency(setup.scope.clone(), runner_owner)?;
    let mut incoming = runner.next(Duration::from_secs(2)).await?.ok_or("query")?;
    drop(runner);
    assert!(runner_weak.upgrade().is_some());
    assert!(matches!(
        incoming.open(&setup.encryption, &setup.scope, now_ms()),
        Err(nocterm_hub_client::cloud::CloudError::Protocol)
    ));
    let opened = incoming.open_resident(&setup.encryption, &setup.scope, now_ms())?;
    assert_eq!(opened.query().query().probe_id, sealed.probe_id());
    assert!(matches!(
        incoming.open_resident(&setup.encryption, &setup.scope, now_ms()),
        Err(nocterm_hub_client::cloud::CloudError::Protocol)
    ));
    // This explicit caller clone/seal is a separate native generation; the
    // SDK guard only claims its own returned query and transport buffers.
    let response = setup.signing.attest_head(HeadWitness {
        query: opened.query().query().clone(),
        observed_at_ms: now_ms(),
        value: empty_catalog(),
    })?;
    let ciphertext = seal_head_witness(&setup.encryption, &response)?;
    drop(response);
    incoming.reply(ciphertext).await?;
    assert!(runner_weak.upgrade().is_some());
    drop(opened);
    assert_eq!(setup.open(&sealed, pending.await??)?, empty_catalog());
    tokio::time::timeout(Duration::from_secs(5), async {
        while runner_weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(hub.cloud().ok_or("fixture")?.publications().is_empty());
    Ok(())
}
