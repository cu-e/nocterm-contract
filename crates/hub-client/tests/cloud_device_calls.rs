//! The device core's effects sent over a hub under this client's own signer (contract ADR 0010).
#![allow(clippy::expect_used, reason = "test fixtures fail loudly")]

mod support;

use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nocterm_cloud_device::{
    command::{CommandAction, UnsignedCommand},
    flow::{EffectFailure, Frame, Input, ProbeRequest, StreamKind, StreamSelector},
    probe::{ProbeTarget, UnsignedHeadProbe},
    records::{ChatSelector, HubTrustRecord, RunnerPins, TrustedRunner},
    trust::{HubCapabilities, TrustedHub},
};
use nocterm_hub_client::{CloudCallError, HubClient, cloud::CloudRunner, now_ms};
use nocterm_hub_model::cloud::{
    CloudTextId, RunCoordinate, RunnerCoordinate,
    head::{CatalogHeadPage, HeadValue, HeadWitness},
    runner_auth::RunnerProofSubject,
};
use nocterm_hub_proto::v1;
use nocterm_keys::{
    AccountKeyPair, DeviceKey,
    cloud::{RunnerEncryptionKey, RunnerSigningKey, open_command, seal_head_witness},
};
use sha2::{Digest, Sha256};
use support::{FakeHub, HUB_ID, cloud::DeviceProof};
use tokio_stream::StreamExt;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const RUNNER: RunnerCoordinate = RunnerCoordinate {
    id: [2; 16],
    key_epoch: 1,
};

/// A signed-in device that trusts the fake hub, with the hub's verified capabilities.
struct Device {
    client: HubClient,
    pair: AccountKeyPair,
    hub: TrustedHub,
    capabilities: HubCapabilities,
}
async fn device(hub: &FakeHub) -> Result<Device, Box<dyn std::error::Error>> {
    let harness = hub.cloud().ok_or("fixture")?;
    harness.enable_head_probes();
    harness.enable_unary_publish();
    let client = hub.signed_in_client().await;
    let pair = AccountKeyPair::generate()?;
    let public = pair.public_key().to_bytes();
    let record = HubTrustRecord::new(
        "",
        HUB_ID,
        "acc-1",
        Sha256::digest(public).into(),
        harness.authority(),
    )?;
    let trusted = TrustedHub::new(record, HUB_ID, "acc-1", &public)?;
    let nonce = [7; 16];
    let Input::Capabilities { claim, signature } = client.capabilities(nonce).await? else {
        return Err("capabilities".into());
    };
    let capabilities = trusted.verify_capabilities(&claim, &signature, &nonce, now_ms())?;
    Ok(Device {
        client,
        pair,
        hub: trusted,
        capabilities,
    })
}
/// Checks that `proof` is this device's signature over its call.
fn proven(client: &HubClient, proof: &DeviceProof) -> bool {
    let key = client.cloud_device().expect("identity").signing_key();
    let Ok(signature) = Signature::from_slice(&proof.proof) else {
        return false;
    };
    proof.token == "access"
        && proof.device == "dev-1"
        && VerifyingKey::from_bytes(&key)
            .is_ok_and(|key| key.verify(&proof.message(), &signature).is_ok())
}
fn pins(encryption: &RunnerEncryptionKey, signing: &RunnerSigningKey) -> RunnerPins {
    RunnerPins {
        encryption: encryption.public_key().to_bytes(),
        signing: signing.public_key(),
        proof: [0x71; 32],
    }
}

#[tokio::test]
async fn a_core_command_is_published_with_exactly_its_bytes_under_this_devices_proof() -> TestResult
{
    let hub = FakeHub::start_cloud().await;
    let device = device(&hub).await?;
    let runner = RunnerEncryptionKey::generate()?;
    let selector = ChatSelector::new(
        device.hub.scope().clone(),
        RUNNER,
        [5; 16],
        1,
        RunnerPins {
            encryption: runner.public_key().to_bytes(),
            signing: [0x51; 32],
            proof: [0x71; 32],
        },
    )?;
    let identity = device.client.cloud_device()?;
    let run = RunCoordinate {
        id: [0x21; 16],
        expected_epoch: 1,
    };
    let command = UnsignedCommand::prepare(
        &selector,
        device.pair.public_key().to_bytes(),
        &identity,
        CommandAction::Stop { run },
        0,
        now_ms(),
    )?;
    let signature = device.client.sign_cloud(&command.sign_request()?)?;
    let sealed = command.seal(&device.pair, &signature, &device.capabilities)?;
    let publication = sealed.publication();
    let Input::Receipt {
        publication_id,
        cursor,
        ciphertext_sha256,
    } = device.client.publish_one(publication).await?
    else {
        return Err("receipt".into());
    };
    assert!(publication.is_receipt(&publication_id, cursor, &ciphertext_sha256));
    let stored = hub.cloud().ok_or("fixture")?.publications();
    assert_eq!(stored[0].1, publication.ciphertext());
    // Only the pinned runner opens it, and it names this device's session as its issuer.
    let route = stored[0]
        .0
        .binding()
        .command_route()
        .ok_or("a command")?
        .clone();
    let opened = open_command(
        &runner,
        &device.pair.public_key(),
        &route,
        publication.ciphertext(),
    )?;
    let issuer = opened.command()?.header().issuer().clone();
    assert_eq!(issuer.device_id.as_str(), "dev-1");
    assert_eq!(issuer.signing_key, identity.signing_key());
    assert_eq!(
        issuer.access_token_digest,
        <[u8; 32]>::from(Sha256::digest(b"access"))
    );
    let proofs = hub.cloud().ok_or("fixture")?.proofs();
    let methods: Vec<_> = proofs.iter().map(|proof| proof.method).collect();
    assert_eq!(methods, ["Capabilities", "PublishOne"]);
    assert!(proofs.iter().all(|proof| proven(&device.client, proof)));
    Ok(())
}

#[tokio::test]
async fn a_core_probe_reaches_the_runner_and_its_witness_opens_for_the_account() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let device = device(&hub).await?;
    let harness = hub.cloud().ok_or("fixture")?;
    let cloud = device
        .client
        .cloud_offer()
        .await?
        .accept(&harness.authority())?;
    let proof = DeviceKey::from_seed(&[0x72; 32]);
    let ticket = cloud
        .create_runner_grant(RUNNER.id, proof.public_key())
        .await?;
    let subject = RunnerProofSubject {
        raw_hub_id: CloudTextId::new(HUB_ID)?,
        namespace: device.hub.scope().namespace(),
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
    let (encryption, signing) = (
        RunnerEncryptionKey::generate()?,
        RunnerSigningKey::generate()?,
    );
    let trusted = TrustedRunner::new(RUNNER, pins(&encryption, &signing), "build box")?;
    let probe = UnsignedHeadProbe::new(
        device.hub.scope(),
        device.pair.public_key().to_bytes(),
        &trusted,
        &device.client.cloud_device()?,
        ProbeTarget::Catalog(None),
        now_ms(),
    )?;
    let signature = device.client.sign_cloud(&probe.sign_request()?)?;
    let sealed = probe.seal(&device.pair, &signature)?;
    let scope =
        nocterm_hub_model::cloud::head::HeadProbeScope::from_canonical_bytes(sealed.scope())?;
    let probes = runner.head_probes(scope.clone())?;
    let catalog = HeadValue::Catalog(Box::new(CatalogHeadPage {
        revision: 1,
        digest: [3; 32],
        total_chats: 0,
        after: None,
        chats: vec![],
        has_more: false,
    }));
    let answer = async {
        let incoming = probes.next(Duration::from_secs(2)).await?.ok_or("query")?;
        let query = incoming.open(&encryption, &scope, now_ms())?;
        let witness = signing.attest_head(HeadWitness {
            query: query.query().clone(),
            observed_at_ms: now_ms(),
            value: catalog.clone(),
        })?;
        incoming
            .reply(seal_head_witness(&encryption, &witness)?)
            .await?;
        TestResult::Ok(())
    };
    let request = sealed.request();
    let (reply, answered) = tokio::join!(device.client.probe_head(&request), answer);
    answered?;
    let Input::ProbeReply {
        scope,
        probe_id,
        ciphertext,
    } = reply?
    else {
        return Err("reply".into());
    };
    let value = sealed.open_reply(&device.pair, &scope, &probe_id, &ciphertext, now_ms())?;
    assert_eq!(value, catalog);
    let proofs = harness.proofs();
    let probe_proof = proofs.iter().find(|proof| proof.method == "ProbeHead");
    assert!(probe_proof.is_some_and(|proof| proven(&device.client, proof)));
    Ok(())
}

#[tokio::test]
async fn a_probe_nobody_answers_is_unanswered_once_it_expires() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let device = device(&hub).await?;
    let (encryption, signing) = (
        RunnerEncryptionKey::generate()?,
        RunnerSigningKey::generate()?,
    );
    let trusted = TrustedRunner::new(RUNNER, pins(&encryption, &signing), "asleep")?;
    let probe = UnsignedHeadProbe::new(
        device.hub.scope(),
        device.pair.public_key().to_bytes(),
        &trusted,
        &device.client.cloud_device()?,
        ProbeTarget::Catalog(None),
        now_ms(),
    )?;
    let signature = device.client.sign_cloud(&probe.sign_request()?)?;
    let sealed = probe.seal(&device.pair, &signature)?;
    let soon = ProbeRequest {
        expires_at_ms: now_ms() + 200,
        ..sealed.request()
    };
    let error = device
        .client
        .probe_head(&soon)
        .await
        .err()
        .ok_or("unanswered")?;
    assert!(matches!(error, CloudCallError::Unanswered));
    assert_eq!(error.failure(), EffectFailure::Unavailable);
    let expired = ProbeRequest {
        expires_at_ms: now_ms() - 1,
        ..sealed.request()
    };
    assert!(matches!(
        device.client.probe_head(&expired).await,
        Err(CloudCallError::Unanswered)
    ));
    Ok(())
}

#[tokio::test]
async fn replay_and_watch_frames_reach_the_flow_as_core_frames_and_a_bad_frame_ends_them()
-> TestResult {
    use v1::cloud_replay_frame::Frame as Wire;
    let hub = FakeHub::start_cloud().await;
    let device = device(&hub).await?;
    let harness = hub.cloud().ok_or("fixture")?;
    let frame = |frame| v1::CloudReplayFrame { frame: Some(frame) };
    harness.replay(vec![
        frame(Wire::Data(vec![1, 2])),
        frame(Wire::PageEnd(v1::CloudPageEnd {
            through_cursor: 4,
            has_more: false,
        })),
    ]);
    let selector = StreamSelector {
        runner_id: RUNNER.id,
        runner_key_epoch: RUNNER.key_epoch,
        stream: StreamKind::Chat([5; 16]),
    };
    let frames: Vec<_> = device
        .client
        .replay(selector, 3, 8, 65_536)
        .await?
        .collect::<Result<_, _>>()
        .await?;
    assert_eq!(
        frames,
        [
            Frame::Data(vec![1, 2]),
            Frame::PageEnd {
                through_cursor: 4,
                has_more: false
            }
        ]
    );
    harness.replay(vec![
        v1::CloudReplayFrame { frame: None },
        frame(Wire::Data(vec![3])),
    ]);
    let mut bad = device.client.replay(selector, 0, 8, 65_536).await?;
    assert!(matches!(
        bad.next_frame().await,
        Some(Err(CloudCallError::Protocol))
    ));
    assert!(
        bad.next_frame().await.is_none(),
        "nothing after a bad frame"
    );
    assert!(matches!(
        device.client.replay(selector, 0, 0, 65_536).await,
        Err(CloudCallError::Protocol)
    ));

    harness.hints(vec![5, 6]);
    let hints: Vec<_> = device
        .client
        .watch(selector, 4)
        .await?
        .collect::<Result<_, _>>()
        .await?;
    assert_eq!(
        hints,
        [
            Frame::Hint { head_cursor: 5 },
            Frame::Hint { head_cursor: 6 }
        ]
    );
    let methods: Vec<_> = harness.proofs().iter().map(|proof| proof.method).collect();
    assert_eq!(methods, ["Capabilities", "Replay", "Replay", "Watch"]);
    Ok(())
}

#[tokio::test]
async fn runner_status_returns_the_signed_status_and_a_signed_out_device_sends_nothing()
-> TestResult {
    let hub = FakeHub::start_cloud().await;
    let device = device(&hub).await?;
    let missing = device
        .client
        .runner_status([9; 16])
        .await
        .err()
        .ok_or("refused")?;
    assert_eq!(missing.failure(), EffectFailure::NotFound);
    device.client.sign_out();
    let before = hub.cloud().ok_or("fixture")?.proofs().len();
    let refused = device
        .client
        .capabilities([1; 16])
        .await
        .err()
        .ok_or("refused")?;
    assert!(matches!(refused, CloudCallError::Session(_)));
    assert_eq!(refused.failure(), EffectFailure::Refused);
    assert_eq!(hub.cloud().ok_or("fixture")?.proofs().len(), before);
    Ok(())
}
