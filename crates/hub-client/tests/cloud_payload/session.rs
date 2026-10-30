use super::*;
use nocterm_hub_model::cloud::payload::BeginSession;

fn begin_window(start: &mut BeginSession<'_>, now: i64, duration: u64) {
    match start {
        BeginSession::Local { binding, .. } => {
            binding.issued_ms = now.cast_unsigned();
            binding.expires_ms = now.cast_unsigned() + duration;
        }
        BeginSession::Ssh { binding, .. } => {
            binding.issued_ms = now.cast_unsigned();
            binding.expires_ms = now.cast_unsigned() + duration;
        }
    }
}

#[tokio::test]
async fn session_start_sealing_requires_negotiation_and_actual_original_hard_deadline() -> TestResult
{
    let hub = FakeHub::start_cloud().await;
    let now = now_ms();
    let client = short_lived_client(&hub, now).await?;
    let peer = hub.cloud().ok_or("fixture")?;
    let authority = peer.authority();
    let old = client.cloud_offer().await?.accept(&authority)?;
    let kdf = UnlockKdf::new(KdfParams::MINIMUM, vec![4; 16])?;
    let unlock = UnlockKey::from_vault_password("fixture password", &kdf)?;
    let keyset = client.create_keyset("acc-1", &unlock, &kdf).await?.keyset;
    let runner = RunnerEncryptionKey::generate()?;
    peer.enable_session_start();
    let cloud = client.cloud_offer().await?.accept(&authority)?;
    let invocation = cloud.command_invocation()?;
    assert_eq!(
        invocation.subject().hard_refresh_expires_at_ms(),
        now + 45_000
    );
    for fixture in [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/cloud-session-v1/begin-local.hex"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/cloud-session-v1/begin-ssh.hex"
        )),
    ] {
        let bytes = hex::decode(fixture.trim())?;
        let route = CloudRoute {
            namespace: cloud.namespace().clone(),
            runner: RunnerCoordinate {
                id: [2; 16],
                key_epoch: 3,
            },
            chat_id: [4; 16],
            command_id: [5; 16],
        };
        check_start_boundaries(&invocation, &old, &keyset, &runner, &route, now, &bytes)?;
    }
    client.sign_out();
    assert!(matches!(
        cloud.command_invocation(),
        Err(CloudError::SourceChanged)
    ));
    Ok(())
}

fn check_start_boundaries(
    invocation: &nocterm_hub_client::cloud::CloudCommandInvocation,
    old: &nocterm_hub_client::cloud::CloudClient,
    keyset: &nocterm_hub_client::Keyset,
    runner: &RunnerEncryptionKey,
    route: &CloudRoute,
    now: i64,
    bytes: &[u8],
) -> TestResult {
    let CloudCommandPayload::BeginSession(mut start) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::BeginSession, bytes)?
    else {
        return Err("start".into());
    };
    begin_window(&mut start, now, 30_000);
    let context = CommandContext {
        nonce: [6; 16],
        expected_chat_revision: 1,
        run: Some(start.run()),
        kind: CommandKind::BeginSession,
        issued_at_ms: now,
        accept_before_ms: now + 30_000,
    };
    let payload = CloudCommandPayload::BeginSession(start.clone());
    assert!(matches!(
        old.prepare_payload(
            keyset,
            &runner.public_key(),
            route.clone(),
            context,
            &payload
        ),
        Err(CloudError::Unsupported)
    ));
    let prepared = invocation.seal_payload(
        keyset,
        &runner.public_key(),
        route.clone(),
        context,
        &payload,
    )?;
    let opened = open_command(runner, &keyset.public_key(), route, prepared.ciphertext())?;
    assert_eq!(
        CloudCommandPayload::from_command(&opened.command()?)?,
        payload
    );
    begin_window(&mut start, now, 60_000);
    let excessive = CloudCommandPayload::BeginSession(start);
    assert!(matches!(
        invocation.seal_payload(
            keyset,
            &runner.public_key(),
            route.clone(),
            context,
            &excessive
        ),
        Err(CloudError::Protocol)
    ));
    let wrong = CommandContext {
        run: Some(RunCoordinate {
            expected_epoch: context.run.ok_or("run")?.expected_epoch + 1,
            ..context.run.ok_or("run")?
        }),
        ..context
    };
    assert!(
        invocation
            .seal_payload(keyset, &runner.public_key(), route.clone(), wrong, &payload)
            .is_err()
    );
    Ok(())
}
