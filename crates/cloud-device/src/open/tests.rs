#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::{
    records::CHAT_MATERIAL_KIND,
    testing::{
        NOW, World,
        hub::{Ended, FakeHub},
    },
};
use nocterm_hub_model::cloud::{
    CloudTextId, CommandIssuer, CommandKind,
    events::{AcceptedCommand, AcceptedPrompt, CloudEvent, CloudEventPayload, CloudTextChannel},
    payload::{ModelSelection, PromptPart},
};
use nocterm_keys::cloud::ChatKey;
use sha2::{Digest, Sha256};

const RUN: RunCoordinate = RunCoordinate {
    id: [0x21; 16],
    expected_epoch: 1,
};

/// A hub holding the chat's wrapped key, and the chat key.
fn chat_hub() -> (FakeHub, ChatKey) {
    let world = World::new();
    let key = ChatKey::generate().unwrap();
    let mut hub = FakeHub::new(world);
    let selector = hub.world.selector.clone();
    let collection = ChatMaterialRecord::collection_id(selector.scope()).unwrap();
    let collection_key = hub.collection(&collection, CHAT_MATERIAL_KIND);
    let material = ChatMaterialRecord::wrap(selector.clone(), &key, &hub.world.account).unwrap();
    hub.object(
        &collection,
        &selector.object_id().unwrap(),
        CHAT_MATERIAL_KIND,
        material.seal(&collection_key).unwrap(),
    );
    (hub, key)
}
fn text(revision: u64, value: &'static str) -> CloudEvent<'static> {
    CloudEvent {
        control_revision: revision,
        timestamp_ms: 1_000 + revision,
        payload: CloudEventPayload::Text {
            run: RUN,
            step: Some([u8::try_from(revision).unwrap(); 16]),
            channel: CloudTextChannel::Assistant,
            text: value,
        },
    }
}
fn texts(hub: &mut FakeHub, key: &ChatKey, count: u64) {
    let selector = hub.world.selector.clone();
    for _ in 0..count {
        let revision = hub.chat.len() as u64 + 1;
        hub.event(&selector, key, &text(revision, "hi "), Some(RUN));
    }
}
fn open(hub: &FakeHub, checkpoint: Option<&VerifiedChat>) -> OpenChat {
    OpenChat::new(
        hub.world.session(),
        hub.world.device.clone(),
        &ChatRef::of(&hub.world.selector),
        checkpoint,
    )
    .unwrap()
}
fn freshness(updates: &[ChatUpdate]) -> Vec<Freshness> {
    updates
        .iter()
        .filter_map(|update| match update {
            ChatUpdate::Freshness(freshness) => Some(*freshness),
            _ => None,
        })
        .collect()
}
fn deltas(updates: &[ChatUpdate]) -> Vec<&TranscriptDelta> {
    updates
        .iter()
        .filter_map(|update| match update {
            ChatUpdate::Transcript(delta) => Some(delta),
            _ => None,
        })
        .collect()
}
fn checkpoint(updates: Vec<ChatUpdate>) -> VerifiedChat {
    updates
        .into_iter()
        .rev()
        .find_map(|update| match update {
            ChatUpdate::Checkpoint(checkpoint) => Some(checkpoint),
            _ => None,
        })
        .unwrap()
}

#[test]
fn an_open_chat_with_an_awake_runner_is_current_and_hands_out_a_checkpoint() {
    let (mut hub, key) = chat_hub();
    texts(&mut hub, &key, 2);
    let mut chat = open(&hub, None);
    let (updates, ended) = hub.run(&mut chat, NOW);
    assert!(matches!(ended, Ended::Idle(None)), "{ended:?}");
    assert_eq!(
        freshness(&updates),
        [Freshness::Current {
            witnessed_at_ms: NOW
        }]
    );
    let delta = deltas(&updates)[0];
    assert_eq!(delta.changed_from, Some(0));
    assert_eq!(delta.rows.len(), 2);
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, ChatUpdate::Checkpoint(_)))
    );
    assert_eq!(chat.transcript().rows().len(), 2);
    assert_eq!(hub.watches.len(), 1, "the chat is watched");
    // Nothing happens while nothing changes: no periodic probe.
    let before = hub.effects.len();
    let (updates, _) = hub.run(&mut chat, NOW + 60_000);
    assert!(updates.is_empty());
    assert_eq!(hub.effects.len(), before);
}

#[test]
fn a_sleeping_seat_shows_its_stored_history_unconfirmed() {
    let (mut hub, key) = chat_hub();
    texts(&mut hub, &key, 2);
    hub.awake = false;
    let mut chat = open(&hub, None);
    let (updates, _) = hub.run(&mut chat, NOW);
    assert_eq!(
        freshness(&updates),
        [Freshness::Unconfirmed {
            last_witnessed_at_ms: None
        }]
    );
    assert_eq!(chat.transcript().rows().len(), 2);
    // Refresh probes again; the runner woke up meanwhile.
    hub.awake = true;
    chat.refresh();
    let (updates, _) = hub.run(&mut chat, NOW + 5_000);
    assert_eq!(
        freshness(&updates),
        [Freshness::Current {
            witnessed_at_ms: NOW + 5_000
        }]
    );
}

#[test]
fn a_hub_that_hides_witnessed_records_is_withheld() {
    let (mut hub, key) = chat_hub();
    texts(&mut hub, &key, 3);
    hub.hidden = 1;
    let mut chat = open(&hub, None);
    let (updates, _) = hub.run(&mut chat, NOW);
    assert_eq!(
        freshness(&updates),
        [Freshness::Withheld {
            witnessed_at_ms: NOW
        }]
    );
    assert_eq!(chat.transcript().rows().len(), 2, "the verified prefix");
}

#[test]
fn a_watch_hint_replays_only_the_new_records() {
    let (mut hub, key) = chat_hub();
    texts(&mut hub, &key, 2);
    let mut chat = open(&hub, None);
    hub.run(&mut chat, NOW);
    texts(&mut hub, &key, 1);
    hub.hint(&mut chat);
    let (updates, _) = hub.run(&mut chat, NOW + 1);
    assert_eq!(hub.replayed_from.last(), Some(&2));
    let delta = deltas(&updates)[0];
    assert!(!delta.reset);
    assert_eq!(delta.changed_from, Some(2));
    assert_eq!(delta.rows.len(), 1);
    assert!(freshness(&updates).is_empty(), "still current");
    assert_eq!(hub.effects.iter().filter(|e| **e == "probe").count(), 1);
}

#[test]
fn a_restored_checkpoint_shows_at_once_and_resumes_at_its_cursor() {
    let (mut hub, key) = chat_hub();
    texts(&mut hub, &key, 2);
    let mut first = open(&hub, None);
    let (updates, _) = hub.run(&mut first, NOW);
    let saved = checkpoint(updates);
    texts(&mut hub, &key, 1);
    let mut chat = open(&hub, Some(&saved));
    assert_eq!(chat.transcript().rows().len(), 2, "shown before any effect");
    assert_eq!(
        chat.freshness(),
        Freshness::Unconfirmed {
            last_witnessed_at_ms: Some(NOW)
        }
    );
    let (updates, _) = hub.run(&mut chat, NOW + 10);
    assert_eq!(hub.replayed_from.last(), Some(&2));
    assert!(deltas(&updates)[0].reset);
    assert_eq!(chat.transcript().rows().len(), 3);
}

#[test]
fn a_hub_that_rolls_back_behind_the_checkpoint_fails_the_chat() {
    let (mut hub, key) = chat_hub();
    texts(&mut hub, &key, 2);
    let mut first = open(&hub, None);
    let (updates, _) = hub.run(&mut first, NOW);
    let saved = checkpoint(updates);
    hub.chat.truncate(1);
    let mut chat = open(&hub, Some(&saved));
    let (_, ended) = hub.run(&mut chat, NOW + 10);
    assert!(matches!(ended, Ended::Failed(CloudDeviceError::Rollback)));
}

#[test]
fn an_unusable_checkpoint_is_ignored_and_the_chat_is_read_from_the_start() {
    let (mut hub, key) = chat_hub();
    texts(&mut hub, &key, 1);
    let mut chat = open(&hub, Some(&VerifiedChat::from_bytes(vec![1; 64])));
    hub.run(&mut chat, NOW);
    assert_eq!(hub.replayed_from, [0]);
    assert_eq!(chat.transcript().rows().len(), 1);
}

fn prompt_accepted(hub: &FakeHub, command: [u8; 16], revision: u64) -> CloudEvent<'static> {
    let device = &hub.world.device;
    CloudEvent {
        control_revision: revision,
        timestamp_ms: 5_000,
        payload: CloudEventPayload::PromptAccepted {
            command: AcceptedCommand {
                id: command,
                kind: CommandKind::SubmitPrompt,
                signed_message_digest: [0x12; 32],
                issuer: CommandIssuer {
                    device_id: CloudTextId::new(device.device_id()).unwrap(),
                    signing_key: device.signing_key(),
                    access_token_digest: Sha256::digest(b"access").into(),
                },
                expected_control_revision: revision - 1,
            },
            run: RUN,
            prompt: Box::new(AcceptedPrompt {
                content: vec![PromptPart::Text("hello")],
                model: ModelSelection {
                    provider: CloudTextId::new("managed").unwrap(),
                    model: CloudTextId::new("m").unwrap(),
                    pricing_policy: CloudTextId::new("managed-v1").unwrap(),
                },
                target: None,
                existing_session: None,
            }),
        },
    }
}

#[test]
fn a_delivered_prompt_is_pending_until_accepted_and_then_asks_for_its_model_grant() {
    let (mut hub, key) = chat_hub();
    let mut chat = open(&hub, None);
    hub.run(&mut chat, NOW);
    let action = ChatAction::Prompt {
        text: "hello".to_owned(),
        model: Some(ModelChoice {
            provider: MANAGED_PROVIDER.to_owned(),
            model: "m".to_owned(),
        }),
    };
    let mut delivery = chat.deliver(&action, None, NOW).unwrap();
    let command = delivery.command_id();
    assert_eq!(
        chat.transcript().pending_commands()[0].state,
        CommandState::Sending
    );
    let (updates, ended) = hub.run(&mut delivery, NOW + 1);
    assert!(matches!(ended, Ended::Done));
    assert_eq!(updates[0].state, CommandState::Delivered);
    let probes = hub.effects.iter().filter(|e| **e == "probe").count();
    chat.delivery(&updates[0]);
    let selector = hub.world.selector.clone();
    hub.event(
        &selector,
        &key,
        &prompt_accepted(&hub, command, 1),
        Some(RUN),
    );
    hub.hint(&mut chat);
    let (updates, _) = hub.run(&mut chat, NOW + 2);
    assert_eq!(
        hub.effects.iter().filter(|e| **e == "probe").count(),
        probes + 1,
        "a receipt probes the runner again"
    );
    assert!(
        updates
            .iter()
            .any(|u| matches!(u, ChatUpdate::AllowRun { run } if *run == RUN))
    );
    assert_eq!(
        chat.transcript().pending_commands()[0].state,
        CommandState::Accepted
    );
    let mut allow = chat
        .deliver(&ChatAction::Allow { run: RUN.id }, None, NOW + 3)
        .unwrap();
    let (updates, _) = hub.run(&mut allow, NOW + 3);
    assert_eq!(updates[0].state, CommandState::Delivered);
    // The grant is asked for once.
    hub.hint(&mut chat);
    let (updates, _) = hub.run(&mut chat, NOW + 4);
    assert!(
        !updates
            .iter()
            .any(|u| matches!(u, ChatUpdate::AllowRun { .. }))
    );
}

#[test]
fn commands_need_their_subject_in_the_verified_transcript() {
    let (mut hub, _) = chat_hub();
    let mut chat = open(&hub, None);
    hub.run(&mut chat, NOW);
    let prompt = ChatAction::Prompt {
        text: "hi".to_owned(),
        model: None,
    };
    assert!(matches!(
        chat.deliver(&prompt, None, NOW),
        Err(CloudDeviceError::NoModel)
    ));
    assert!(matches!(
        chat.deliver(&ChatAction::Stop { run: None }, None, NOW),
        Err(CloudDeviceError::NoRun)
    ));
    assert!(matches!(
        chat.deliver(&ChatAction::Allow { run: [9; 16] }, None, NOW),
        Err(CloudDeviceError::NoRun)
    ));
    let answer = ChatAction::Answer {
        intent: [9; 16],
        approve: true,
    };
    assert!(matches!(
        chat.deliver(&answer, None, NOW),
        Err(CloudDeviceError::NoApproval)
    ));
}

#[test]
fn an_answer_for_an_effect_never_asked_for_fails_the_flow() {
    let (hub, _) = chat_hub();
    let mut chat = open(&hub, None);
    chat.resolve(999, Input::Done);
    assert!(matches!(
        chat.next(NOW),
        crate::flow::Step::Failed(CloudDeviceError::Protocol)
    ));
    assert!(matches!(
        chat.next(NOW),
        crate::flow::Step::Failed(CloudDeviceError::Ended)
    ));
}

#[test]
fn a_chat_of_an_untrusted_runner_is_refused() {
    let (hub, _) = chat_hub();
    let mut chat = ChatRef::of(&hub.world.selector);
    chat.runner = [9; 16];
    assert!(matches!(
        OpenChat::new(hub.world.session(), hub.world.device.clone(), &chat, None),
        Err(CloudDeviceError::NoRunner)
    ));
    assert_eq!(
        chat.to_string().parse::<ChatRef>().unwrap(),
        chat,
        "a chat reference round-trips as text"
    );
    assert!("x-y-1".parse::<ChatRef>().is_err());
}
