//! Typed authority cannot exceed the actual captured SDK session deadline.
mod support;
use nocterm_hub_client::{HubClient, Session, cloud::CloudError, now_ms};
use nocterm_hub_model::cloud::{
    CloudRoute, CloudTextId, CommandContext, CommandKind, RunCoordinate, RunnerCoordinate,
    payload::{
        ApprovalChoice, CloudCommandPayload, InferenceLimits, ModelSelection, PromptPart,
        PromptPayload,
    },
};
use nocterm_keys::{
    DeviceKey, KdfParams, UnlockKdf, UnlockKey,
    cloud::{RunnerEncryptionKey, open_command},
};
use support::FakeHub;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[tokio::test]
async fn command_invocation_refuses_oversized_original_credential_metadata() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let now = now_ms();
    let client = HubClient::connect(
        &hub.endpoint(),
        DeviceKey::generate()?,
        Some(Session {
            account_id: "acc-1".into(),
            device_id: "dev-1".into(),
            access_token: "x".repeat(2048),
            access_expires_at_ms: now + 30_000,
            refresh_token: "refresh".into(),
            refresh_expires_at_ms: now + 45_000,
        }),
    )
    .await?;
    let authority = hub.cloud().ok_or("fixture")?.authority();
    let cloud = client.cloud_offer().await?.accept(&authority)?;
    assert!(matches!(
        cloud.command_invocation(),
        Err(CloudError::Protocol)
    ));
    Ok(())
}
#[tokio::test]
async fn reconciliation_fingerprint_survives_actual_signed_encrypted_command_and_exact_retry()
-> TestResult {
    let hub = FakeHub::start_cloud().await;
    let now = now_ms();
    let client = short_lived_client(&hub, now).await?;
    let authority = hub.cloud().ok_or("fixture")?.authority();
    let cloud = client.cloud_offer().await?.accept(&authority)?;
    let kdf = UnlockKdf::new(KdfParams::MINIMUM, vec![4; 16])?;
    let unlock = UnlockKey::from_vault_password("fixture password", &kdf)?;
    let keyset = client.create_keyset("acc-1", &unlock, &kdf).await?.keyset;
    let runner = RunnerEncryptionKey::generate()?;
    let bytes =
        hex::decode(include_str!("../../../fixtures/cloud-payload-v1/reconcile-known.hex").trim())?;
    let payload = CloudCommandPayload::from_canonical_bytes(CommandKind::ResolveApproval, &bytes)?;
    let CloudCommandPayload::ResolveApproval(answer) = &payload else {
        return Err("approval".into());
    };
    let route = CloudRoute {
        namespace: cloud.namespace().clone(),
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat_id: [4; 16],
        command_id: [5; 16],
    };
    let prepared = cloud.prepare_payload(
        &keyset,
        &runner.public_key(),
        route.clone(),
        CommandContext {
            nonce: [6; 16],
            expected_chat_revision: 12,
            run: Some(answer.execution.run),
            kind: CommandKind::ResolveApproval,
            issued_at_ms: now,
            accept_before_ms: now + 30_000,
        },
        &payload,
    )?;
    let opened = open_command(&runner, &keyset.public_key(), &route, prepared.ciphertext())?;
    let original = opened.command()?;
    assert_eq!(CloudCommandPayload::from_command(&original)?, payload);
    assert_eq!(
        answer.choice,
        ApprovalChoice::ReconcileKnown {
            result_digest: [0x13; 32]
        }
    );
    // In-memory delivery retry reuses this exact prepared signature/ciphertext.
    // Loading a durable native outbox remains a separate consumer responsibility.
    let first = cloud.publish_prepared(&prepared).await?;
    let repeated = cloud.publish_prepared(&prepared).await?;
    assert_eq!(first, repeated);
    // The authenticated native outbox supplies exactly these original M bytes.
    // A new SDK login only captures delivery authority, without rewriting issuer,
    // publication ID, command ID, signature, deadlines or original ciphertext.
    let next_client = hub.signed_in_client().await;
    let next = next_client.cloud_offer().await?.accept(&authority)?;
    let stored = next.stage_stored_command(
        prepared.metadata().clone(),
        prepared.ciphertext().to_vec(),
        prepared.semantic_digest(),
    )?;
    assert_eq!(stored.metadata(), prepared.metadata());
    assert_eq!(stored.ciphertext(), prepared.ciphertext());
    assert_eq!(stored.semantic_digest(), prepared.semantic_digest());
    assert!(matches!(
        next.publish_prepared(&prepared).await,
        Err(CloudError::SourceChanged)
    ));
    assert_eq!(next.publish_prepared(&stored).await?, first);
    let mut corrupted = prepared.ciphertext().to_vec();
    corrupted[0] ^= 1;
    assert!(
        next.stage_stored_command(
            prepared.metadata().clone(),
            corrupted,
            prepared.semantic_digest()
        )
        .is_err()
    );
    client.sign_out();
    assert!(matches!(
        cloud.stage_stored_command(
            prepared.metadata().clone(),
            prepared.ciphertext().to_vec(),
            prepared.semantic_digest()
        ),
        Err(CloudError::SourceChanged)
    ));
    let reopened = open_command(&runner, &keyset.public_key(), &route, prepared.ciphertext())?;
    assert_eq!(
        reopened.command()?.plaintext_bytes()?,
        original.plaintext_bytes()?
    );
    Ok(())
}
fn prompt(deadline: i64) -> Result<CloudCommandPayload<'static>, Box<dyn std::error::Error>> {
    Ok(CloudCommandPayload::SubmitPrompt(Box::new(PromptPayload {
        content: vec![PromptPart::Text("private typed prompt")],
        model: ModelSelection {
            provider: CloudTextId::new("openai")?,
            model: CloudTextId::new("model")?,
            pricing_policy: CloudTextId::new("policy")?,
        },
        target: None,
        existing_session: None,
        inference: InferenceLimits {
            calls: 1,
            turns: 1,
            request_bytes: 1024,
            output_bytes: 1024,
            output_tokens: 128,
            spend_micros: 1000,
            deadline_ms: deadline,
        },
    })))
}
async fn short_lived_client(
    hub: &FakeHub,
    now: i64,
) -> Result<HubClient, Box<dyn std::error::Error>> {
    Ok(HubClient::connect(
        &hub.endpoint(),
        DeviceKey::generate()?,
        Some(Session {
            account_id: "acc-1".into(),
            device_id: "dev-1".into(),
            access_token: "access".into(),
            access_expires_at_ms: now + 30_000,
            refresh_token: "refresh".into(),
            refresh_expires_at_ms: now + 45_000,
        }),
    )
    .await?)
}
#[tokio::test]
async fn typed_sealing_binds_purpose_run_and_original_hard_session_deadline() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let now = now_ms();
    let client = short_lived_client(&hub, now).await?;
    let authority = hub.cloud().ok_or("fixture")?.authority();
    let cloud = client.cloud_offer().await?.accept(&authority)?;
    let kdf = UnlockKdf::new(KdfParams::MINIMUM, vec![4; 16])?;
    let unlock = UnlockKey::from_vault_password("fixture password", &kdf)?;
    let keyset = client.create_keyset("acc-1", &unlock, &kdf).await?.keyset;
    let runner = RunnerEncryptionKey::generate()?;
    let route = CloudRoute {
        namespace: cloud.namespace().clone(),
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat_id: [4; 16],
        command_id: [5; 16],
    };
    let context = CommandContext {
        nonce: [6; 16],
        expected_chat_revision: 1,
        run: None,
        kind: CommandKind::SubmitPrompt,
        issued_at_ms: now,
        accept_before_ms: now + 30_000,
    };
    assert!(matches!(
        cloud.prepare_payload(
            &keyset,
            &runner.public_key(),
            route.clone(),
            context,
            &prompt(now + 60_000)?
        ),
        Err(CloudError::Protocol)
    ));
    let prepared = cloud.prepare_payload(
        &keyset,
        &runner.public_key(),
        route.clone(),
        context,
        &prompt(now + 30_000)?,
    )?;
    let opened = open_command(&runner, &keyset.public_key(), &route, prepared.ciphertext())?;
    let command = opened.command()?;
    assert_eq!(
        CloudCommandPayload::from_command(&command)?,
        prompt(now + 30_000)?
    );
    let stop = CommandContext {
        kind: CommandKind::Stop,
        ..context
    };
    assert!(
        cloud
            .prepare_payload(
                &keyset,
                &runner.public_key(),
                route.clone(),
                stop,
                &CloudCommandPayload::Stop
            )
            .is_err()
    );
    let stop = CommandContext {
        run: Some(RunCoordinate {
            id: [7; 16],
            expected_epoch: 1,
        }),
        ..stop
    };
    cloud.prepare_payload(
        &keyset,
        &runner.public_key(),
        route.clone(),
        stop,
        &CloudCommandPayload::Stop,
    )?;
    assert!(
        cloud
            .prepare_payload(
                &keyset,
                &runner.public_key(),
                route,
                stop,
                &CloudCommandPayload::DeleteChat
            )
            .is_err()
    );
    Ok(())
}
