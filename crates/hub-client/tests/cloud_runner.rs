//! A runner keeps only its scoped credential; account logout and late refresh are separate.
mod support;
use nocterm_hub_client::{
    HubClient,
    cloud::{CloudClient, CloudError, CloudRunner, CloudSelector, RunnerSession},
};
use nocterm_hub_model::cloud::{
    ChatCoordinate, CloudTextId, RecordContext, RecordPosition, RunnerCoordinate,
    relay::{PublicationMetadata, RelayBinding},
    runner_auth::RunnerProofSubject,
};
use nocterm_keys::DeviceKey;
use sha2::{Digest, Sha256};
use support::FakeHub;
use zeroize::Zeroizing;
type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn enrolled(
    hub: &FakeHub,
) -> Result<(HubClient, CloudClient, CloudRunner), Box<dyn std::error::Error>> {
    let client = hub.signed_in_client().await;
    let authority = hub.cloud().ok_or("fixture")?.authority();
    let cloud = client.cloud_offer().await?.accept(&authority)?;
    let key = DeviceKey::from_seed(&[0x72; 32]);
    let ticket = cloud.create_runner_grant([2; 16], key.public_key()).await?;
    let subject = RunnerProofSubject {
        raw_hub_id: CloudTextId::new(support::HUB_ID)?,
        namespace: cloud.namespace().clone(),
        runner_id: [2; 16],
        proof_key: key.public_key(),
    };
    let runner = CloudRunner::redeem(
        &hub.endpoint(),
        subject,
        authority,
        key,
        Zeroizing::new(ticket.token().to_owned()),
    )
    .await?;
    Ok((client, cloud, runner))
}

#[tokio::test]
async fn runner_proof_survives_device_logout_and_rotates_without_becoming_a_device_session()
-> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (client, _cloud, runner) = enrolled(&hub).await?;
    assert!(runner.heartbeat(vec![1]).await? > 0);
    client.sign_out();
    assert!(runner.heartbeat(vec![2]).await? > 0);
    let fresh = runner.refresh().await?;
    assert_eq!(fresh.into_response().access_token, "runner-access-2");
    assert!(runner.heartbeat(vec![3]).await? > 0);
    runner.revoke_local();
    assert!(matches!(
        runner.heartbeat(vec![4]).await,
        Err(CloudError::SourceChanged)
    ));
    Ok(())
}

#[tokio::test]
async fn local_runner_revoke_wins_over_a_completed_remote_refresh() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, _, runner) = enrolled(&hub).await?;
    let harness = hub.cloud().ok_or("fixture")?;
    harness.hold_runner_refresh();
    let clone = runner.clone();
    let pending = tokio::spawn(async move { clone.refresh().await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        harness.wait_runner_refresh(),
    )
    .await?;
    runner.revoke_local();
    harness.release_runner_refresh();
    assert!(matches!(pending.await?, Err(CloudError::SourceChanged)));
    assert!(runner.session().is_err());
    assert!(runner.heartbeat(vec![1]).await.is_err());
    Ok(())
}

#[tokio::test]
async fn runner_transport_rejects_commands_and_other_runners_before_publication() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, cloud, runner) = enrolled(&hub).await?;
    let route = nocterm_hub_model::cloud::CloudRoute {
        namespace: cloud.namespace().clone(),
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat_id: [4; 16],
        command_id: [5; 16],
    };
    let command = PublicationMetadata::new(
        [7; 16],
        RelayBinding::command(route)?,
        1,
        Sha256::digest([1]).into(),
    )?;
    assert!(runner.begin_publication(command).is_err());
    for id in [[2; 16], [9; 16]] {
        let chat = ChatCoordinate::new(
            cloud.namespace().clone(),
            RunnerCoordinate { id, key_epoch: 3 },
            [4; 16],
            5,
        )?;
        let context = RecordContext::new(
            chat,
            RecordPosition {
                writer_epoch: 1,
                sequence: 1,
                journal_sequence: 1,
                revision: 1,
            },
            [6; 16],
            None,
        )?;
        let event = PublicationMetadata::new(
            [7; 16],
            RelayBinding::event(context),
            1,
            Sha256::digest([1]).into(),
        )?;
        assert!(cloud.begin_publication(event.clone()).is_err());
        let result = runner.begin_publication(event);
        assert_eq!(result.is_ok(), id == [2; 16]);
    }
    assert!(
        runner
            .replay(
                CloudSelector::RunnerInbox(RunnerCoordinate {
                    id: [9; 16],
                    key_epoch: 3
                }),
                0,
                1,
                1024
            )
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn restored_runner_tokens_cannot_be_relabelled_as_another_account_or_runner() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, _, runner) = enrolled(&hub).await?;
    let mut response = runner.session()?.into_response();
    response.account_id = "other".into();
    assert!(RunnerSession::from_response(response, runner.subject()).is_err());
    let session = runner.session()?;
    let mut changed = runner.subject().clone();
    changed.runner_id = [9; 16];
    let restored = CloudRunner::restore(
        &hub.endpoint(),
        changed,
        hub.cloud().ok_or("fixture")?.authority(),
        DeviceKey::from_seed(&[0x72; 32]),
        session,
    )
    .await;
    assert!(restored.is_err());
    Ok(())
}

fn record_context(
    cloud: &CloudClient,
    chat_id: [u8; 16],
    sequence: u64,
) -> Result<RecordContext, Box<dyn std::error::Error>> {
    Ok(RecordContext::new(
        ChatCoordinate::new(
            cloud.namespace().clone(),
            RunnerCoordinate {
                id: [2; 16],
                key_epoch: 3,
            },
            chat_id,
            1,
        )?,
        RecordPosition {
            writer_epoch: 1,
            sequence,
            journal_sequence: sequence,
            revision: sequence,
        },
        [u8::try_from(sequence)?; 16],
        None,
    )?)
}
async fn publish_record(
    runner: &CloudRunner,
    id: [u8; 16],
    binding: RelayBinding,
    body: &[u8],
) -> Result<u64, Box<dyn std::error::Error>> {
    let metadata = PublicationMetadata::new(
        id,
        binding,
        u32::try_from(body.len())?,
        Sha256::digest(body).into(),
    )?;
    let mut upload = runner.begin_publication(metadata)?;
    for chunk in body.chunks(nocterm_hub_model::cloud::relay::MAX_RELAY_FRAME_BYTES) {
        upload.write(chunk).await?;
    }
    Ok(upload.finish().await?.cursor)
}
struct SnapshotHistory {
    selector: CloudSelector,
    key: nocterm_keys::cloud::ChatKey,
    signer: nocterm_keys::cloud::RunnerSigningKey,
    context: RecordContext,
    payload: Vec<u8>,
}
async fn publish_snapshot_history(
    cloud: &CloudClient,
    runner: &CloudRunner,
) -> Result<SnapshotHistory, Box<dyn std::error::Error>> {
    use nocterm_keys::cloud::{ChatKey, RunnerSigningKey, seal_snapshot};
    let selector = CloudSelector::Chat {
        runner: RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        chat: [4; 16],
    };
    let key = ChatKey::generate()?;
    let signer = RunnerSigningKey::generate()?;
    let context = record_context(cloud, [4; 16], 2)?;
    let payload = vec![0x51; 20_000];
    let sealed = seal_snapshot(&key, &signer, context.clone(), &payload)?;
    assert_eq!(
        publish_record(
            runner,
            [1; 16],
            RelayBinding::event(record_context(cloud, [4; 16], 1)?),
            b"old event"
        )
        .await?,
        1
    );
    assert_eq!(
        publish_record(
            runner,
            [2; 16],
            RelayBinding::snapshot(context.clone()),
            &sealed
        )
        .await?,
        2
    );
    assert_eq!(
        publish_record(
            runner,
            [3; 16],
            RelayBinding::event(record_context(cloud, [4; 16], 3)?),
            b"next event"
        )
        .await?,
        3
    );
    assert_eq!(
        publish_record(
            runner,
            [4; 16],
            RelayBinding::snapshot(record_context(cloud, [4; 16], 4)?),
            b"later snapshot"
        )
        .await?,
        4
    );
    assert_eq!(
        publish_record(
            runner,
            [9; 16],
            RelayBinding::snapshot(record_context(cloud, [9; 16], 1)?),
            b"other chat"
        )
        .await?,
        1
    );
    Ok(SnapshotHistory {
        selector,
        key,
        signer,
        context,
        payload,
    })
}
#[tokio::test]
async fn purge_gap_recovers_the_first_retained_signed_snapshot_in_a_bounded_replay() -> TestResult {
    use nocterm_hub_client::cloud::CloudReplayItem;
    use nocterm_hub_model::cloud::relay::RelayKind;
    use nocterm_keys::cloud::open_snapshot;
    let hub = FakeHub::start_cloud().await;
    let (_, cloud, runner) = enrolled(&hub).await?;
    let SnapshotHistory {
        selector,
        key,
        signer,
        context,
        payload,
    } = publish_snapshot_history(&cloud, &runner).await?;
    // Every rejected anchor leaves the original replay prefix available.
    for (through, id) in [
        (0, [1; 16]),
        (2, [2; 16]),
        (0, [9; 16]),
        (1, [8; 16]),
        (u64::MAX, [2; 16]),
    ] {
        assert!(runner.purge(&selector, through, id).await.is_err());
    }
    let mut unchanged = cloud.replay(selector.clone(), 0, 1, 65_536).await?;
    let CloudReplayItem::Record(record) = unchanged.next_record().await? else {
        return Err("prefix changed on rejection".into());
    };
    assert_eq!(record.cursor(), 1);
    drop(record);
    assert_eq!(runner.purge(&selector, 1, [2; 16]).await?, 1);
    let mut stale = cloud.replay(selector.clone(), 0, 1, 65_536).await?;
    let CloudReplayItem::Gap {
        retained_from,
        snapshot: Some(snapshot),
    } = stale.next_record().await?
    else {
        return Err("gap missing".into());
    };
    assert_eq!((retained_from, snapshot), (2, [2; 16]));
    let mut recovered = cloud
        .replay(
            selector.clone(),
            retained_from.checked_sub(1).ok_or("floor")?,
            1,
            65_536,
        )
        .await?;
    let CloudReplayItem::Record(mut record) = recovered.next_record().await? else {
        return Err("snapshot missing".into());
    };
    assert_eq!(record.cursor(), retained_from);
    assert_eq!(record.metadata().id(), snapshot);
    assert_eq!(record.metadata().binding().kind(), RelayKind::Snapshot);
    assert_eq!(record.metadata().binding().record_context(), Some(&context));
    let mut ciphertext = Vec::new();
    while let Some(chunk) = record.next_chunk().await? {
        assert!(chunk.len() <= nocterm_hub_model::cloud::relay::MAX_RELAY_FRAME_BYTES);
        ciphertext.extend_from_slice(&chunk);
    }
    drop(record);
    assert!(matches!(
        recovered.next_record().await?,
        CloudReplayItem::End {
            through: 2,
            has_more: true
        }
    ));
    // Hub routing metadata never replaces pinned signature/context verification.
    assert!(open_snapshot(&key, &[0; 32], &context, &ciphertext).is_err());
    assert!(
        open_snapshot(
            &key,
            &signer.public_key(),
            &record_context(&cloud, [9; 16], 2)?,
            &ciphertext
        )
        .is_err()
    );
    assert_eq!(
        open_snapshot(&key, &signer.public_key(), &context, &ciphertext)?
            .record()?
            .payload(),
        payload
    );
    assert_eq!(runner.purge(&selector, 3, [4; 16]).await?, 3);
    assert!(runner.purge(&selector, 1, [2; 16]).await.is_err());
    let mut stale = cloud.replay(selector, 0, 1, 65_536).await?;
    assert!(
        matches!(stale.next_record().await?, CloudReplayItem::Gap { retained_from: 4, snapshot: Some(id) } if id == [4; 16])
    );
    Ok(())
}
#[tokio::test]
async fn runner_retention_refuses_inbox_and_cursor_overflow_before_rpc() -> TestResult {
    let hub = FakeHub::start_cloud().await;
    let (_, _, runner) = enrolled(&hub).await?;
    let coordinate = RunnerCoordinate {
        id: [2; 16],
        key_epoch: 3,
    };
    assert!(matches!(
        runner
            .purge(&CloudSelector::RunnerInbox(coordinate), 1, [2; 16])
            .await,
        Err(CloudError::Protocol)
    ));
    let chat = CloudSelector::Chat {
        runner: coordinate,
        chat: [4; 16],
    };
    assert!(matches!(
        runner.purge(&chat, u64::MAX, [2; 16]).await,
        Err(CloudError::Protocol)
    ));
    assert!(hub.cloud().ok_or("fixture")?.publications().is_empty());
    Ok(())
}
#[tokio::test]
async fn gap_snapshot_shape_and_terminal_eof_are_required_before_recovery() -> TestResult {
    use nocterm_hub_proto::v1::{self, cloud_replay_frame::Frame};
    let hub = FakeHub::start_cloud().await;
    let (_, cloud, _) = enrolled(&hub).await?;
    let harness = hub.cloud().ok_or("fixture")?;
    let runner = RunnerCoordinate {
        id: [2; 16],
        key_epoch: 3,
    };
    let chat = CloudSelector::Chat {
        runner,
        chat: [4; 16],
    };
    for (selector, pointer) in [
        (chat.clone(), vec![]),
        (chat.clone(), vec![2; 15]),
        (CloudSelector::RunnerInbox(runner), vec![2; 16]),
    ] {
        harness.replay(vec![v1::CloudReplayFrame {
            frame: Some(Frame::Gap(v1::CloudReplayGap {
                retained_from_cursor: 2,
                snapshot_publication_id: pointer,
            })),
        }]);
        let mut replay = cloud.replay(selector, 0, 1, 65_536).await?;
        assert!(replay.next_record().await.is_err());
    }
    harness.replay(vec![
        v1::CloudReplayFrame {
            frame: Some(Frame::Gap(v1::CloudReplayGap {
                retained_from_cursor: 2,
                snapshot_publication_id: vec![2; 16],
            })),
        },
        v1::CloudReplayFrame {
            frame: Some(Frame::Data(vec![1])),
        },
    ]);
    let mut replay = cloud.replay(chat, 0, 1, 65_536).await?;
    assert!(replay.next_record().await.is_err());
    assert!(replay.next_record().await.is_err());
    // Inbox loss remains explicit and cannot carry chat-baseline authority.
    harness.replay(vec![v1::CloudReplayFrame {
        frame: Some(Frame::Gap(v1::CloudReplayGap {
            retained_from_cursor: 2,
            snapshot_publication_id: vec![],
        })),
    }]);
    let mut replay = cloud
        .replay(CloudSelector::RunnerInbox(runner), 0, 1, 65_536)
        .await?;
    assert!(matches!(
        replay.next_record().await?,
        nocterm_hub_client::cloud::CloudReplayItem::Gap {
            retained_from: 2,
            snapshot: None
        }
    ));
    Ok(())
}

async fn read_chat_key_grant(
    client: &CloudRunner,
    chat: &ChatCoordinate,
    expected: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use nocterm_hub_client::cloud::CloudReplayItem;
    // Replay gives material with the exact key generation, not an execution command.
    let mut replay = client
        .replay(CloudSelector::RunnerInbox(chat.runner()), 0, 1, 256)
        .await?;
    let CloudReplayItem::Record(mut record) = replay.next_record().await? else {
        return Err("material missing".into());
    };
    assert_eq!(
        record.metadata().binding().material_coordinate(),
        Some(chat)
    );
    let mut sealed = Vec::new();
    while let Some(chunk) = record.next_chunk().await? {
        sealed.extend_from_slice(&chunk);
    }
    drop(record);
    assert!(matches!(
        replay.next_record().await?,
        CloudReplayItem::End { through: 1, .. }
    ));
    assert_eq!(sealed, expected);
    Ok(sealed)
}
async fn verify_material_transfer(
    next_client: &HubClient,
    runner: &CloudRunner,
    keyset: &nocterm_hub_client::Keyset,
    unlock: &nocterm_keys::UnlockKey,
    runner_key: &nocterm_keys::cloud::RunnerEncryptionKey,
    wrapped: &[u8],
    grant: &nocterm_hub_client::cloud::PreparedChatKeyGrant,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use nocterm_hub_model::cloud::{JournalClass, JournalCoordinate};
    use nocterm_keys::cloud::{ChatKey, RunnerEncryptionKey, open_chat_key_from_account};
    let chat = grant
        .metadata()
        .binding()
        .material_coordinate()
        .ok_or("material coordinate")?;
    let next_keyset = next_client
        .open_keyset("acc-1", unlock)
        .await?
        .ok_or("keyset")?;
    // Same account root from normal keyset opening decrypts historical chat material.
    let next_key = ChatKey::open_for_account(next_keyset.account_key(), chat, wrapped)?;
    let journal_slot =
        JournalCoordinate::new(chat.clone(), JournalClass::Header, [0; 16], 0, 0, 1)?;
    let journal_cipher =
        next_key.seal_journal(&journal_slot, b"only this chat's private journal")?;
    let sealed = read_chat_key_grant(runner, chat, grant.ciphertext()).await?;
    let opened = open_chat_key_from_account(runner_key, &keyset.public_key(), chat, &sealed)?;
    assert_eq!(
        opened
            .open_journal(&journal_slot, &journal_cipher)?
            .as_slice(),
        b"only this chat's private journal"
    );
    assert!(
        open_chat_key_from_account(
            &RunnerEncryptionKey::generate()?,
            &keyset.public_key(),
            chat,
            &sealed
        )
        .is_err()
    );
    let foreign = ChatCoordinate::new(
        chat.namespace().clone(),
        chat.runner(),
        [9; 16],
        chat.key_epoch(),
    )?;
    assert!(
        open_chat_key_from_account(runner_key, &keyset.public_key(), &foreign, &sealed).is_err()
    );
    Ok(sealed)
}
#[tokio::test]
async fn chat_key_material_requires_capability_and_original_account_source_without_task_authority()
-> TestResult {
    use nocterm_hub_model::cloud::relay::RelayKind;
    use nocterm_keys::{
        KdfParams, UnlockKdf, UnlockKey,
        cloud::{ChatKey, RunnerEncryptionKey},
    };
    let hub = FakeHub::start_cloud().await;
    let client = hub.signed_in_client().await;
    let old_cloud = client
        .cloud_offer()
        .await?
        .accept(&hub.cloud().ok_or("fixture")?.authority())?;
    let kdf = UnlockKdf::new(KdfParams::MINIMUM, vec![4; 16])?;
    let unlock = UnlockKey::from_vault_password("correct horse battery", &kdf)?;
    let keyset = client.create_keyset("acc-1", &unlock, &kdf).await?.keyset;
    let chat = record_context(&old_cloud, [4; 16], 1)?.chat().clone();
    let key = ChatKey::generate()?;
    let runner_key = RunnerEncryptionKey::generate()?;
    assert!(matches!(
        old_cloud.prepare_chat_key_grant(
            &keyset,
            &runner_key.public_key(),
            chat.clone(),
            &key,
            [0x31; 16]
        ),
        Err(CloudError::Unsupported)
    ));
    let harness = hub.cloud().ok_or("fixture")?;
    assert!(harness.publications().is_empty());
    harness.enable_key_material();
    let (_, _, runner) = enrolled(&hub).await?;
    let cloud = client.cloud_offer().await?.accept(&harness.authority())?;
    let grant = cloud.prepare_chat_key_grant(
        &keyset,
        &runner_key.public_key(),
        chat.clone(),
        &key,
        [0x31; 16],
    )?;
    assert_eq!(grant.metadata().binding().kind(), RelayKind::ChatKeyGrant);
    assert!(grant.metadata().binding().command_route().is_none());
    assert!(grant.metadata().binding().record_context().is_none());
    assert_eq!(grant.ciphertext().len(), 106);
    assert!(runner.begin_publication(grant.metadata().clone()).is_err());
    assert_eq!(cloud.publish_chat_key_grant(&grant).await?.cursor, 1);
    // A separately signed-in SDK client cannot publish a prepared object from A.
    let next_client = hub.signed_in_client().await;
    let next = next_client
        .cloud_offer()
        .await?
        .accept(&harness.authority())?;
    assert!(matches!(
        next.publish_chat_key_grant(&grant).await,
        Err(CloudError::SourceChanged)
    ));
    let wrapped = key.seal_for_account(keyset.account_key(), &chat)?;
    let sealed = verify_material_transfer(
        &next_client,
        &runner,
        &keyset,
        &unlock,
        &runner_key,
        &wrapped,
        &grant,
    )
    .await?;
    let restored = next.stage_chat_key_grant(chat.clone(), grant.metadata().id(), sealed)?;
    assert_eq!(restored.metadata(), grant.metadata());
    client.sign_out();
    assert!(matches!(
        cloud.publish_chat_key_grant(&grant).await,
        Err(CloudError::SourceChanged)
    ));
    assert!(next.publish_chat_key_grant(&restored).await.is_ok());
    assert!(
        next.stage_chat_key_grant(chat, [1; 16], vec![0; 257])
            .is_err()
    );
    Ok(())
}
