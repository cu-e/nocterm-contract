#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use nocterm_hub_model::cloud::events::CloudSnapshotPayload;

macro_rules! vector {
    ($name:literal) => {
        hex::decode(
            include_str!(concat!(
                "../../../../fixtures/cloud-events-v1/",
                $name,
                ".hex"
            ))
            .trim(),
        )
        .unwrap()
    };
}
const RUN: RunCoordinate = RunCoordinate {
    id: [0x21; 16],
    expected_epoch: 2,
};
const INTENT: [u8; 16] = [8; 16];

fn apply(transcript: &mut Transcript, bytes: &[u8]) {
    transcript.apply(&CloudEvent::from_canonical_bytes(bytes).unwrap());
}
fn tool(transcript: &Transcript) -> &ToolCall {
    transcript
        .rows()
        .iter()
        .find_map(|row| row.tool.as_ref())
        .unwrap()
}

#[test]
fn an_accepted_prompt_opens_a_run_with_a_user_row() {
    let mut transcript = Transcript::new();
    apply(&mut transcript, &vector!("prompt"));
    let row = &transcript.rows()[0];
    assert_eq!(row.role, Role::User);
    assert_eq!(row.text, "public fixture prompt");
    assert_eq!(row.run, Some(RUN));
    let run = transcript.active_run().unwrap();
    assert_eq!(run.run, RUN);
    assert_eq!(run.status, CloudRunStatus::Queued);
    assert_eq!(run.issuer_device, "device");
    assert!(transcript.control_revision() > 0);
}

#[test]
fn status_text_and_usage_update_the_run_and_its_rows() {
    let mut transcript = Transcript::new();
    apply(&mut transcript, &vector!("prompt"));
    apply(&mut transcript, &vector!("status"));
    apply(&mut transcript, &vector!("text"));
    apply(&mut transcript, &vector!("text"));
    apply(&mut transcript, &vector!("usage"));
    let rows = transcript.rows();
    assert_eq!(rows.len(), 2, "consecutive text of one step merges");
    assert_eq!(rows[1].role, Role::Thought);
    assert_eq!(rows[1].text, "sensitive-textsensitive-text");
    let run = transcript.run(&RUN).unwrap();
    assert_ne!(run.status, CloudRunStatus::Queued);
    assert_ne!(run.usage, CloudUsage::default());
}

#[test]
fn a_tool_call_moves_through_approval_answer_and_result() {
    let mut transcript = Transcript::new();
    apply(&mut transcript, &vector!("intent"));
    assert_eq!(tool(&transcript).status, ToolStatus::Running);
    assert_eq!(tool(&transcript).tool, "list_terminals");
    apply(&mut transcript, &vector!("approval"));
    assert!(matches!(
        tool(&transcript).status,
        ToolStatus::AwaitingApproval { .. }
    ));
    let request = transcript.approval(&INTENT).unwrap().clone();
    assert_eq!(request.run(), RUN);
    assert_eq!(request.answer(ApprovalChoice::Approve).intent, INTENT);
    assert_eq!(
        transcript.rows().len(),
        1,
        "the approval updates the same row"
    );
    transcript.apply(&CloudEvent {
        control_revision: 20,
        timestamp_ms: 300_000,
        payload: CloudEventPayload::ApprovalResolved {
            command: [1; 16],
            answer: Box::new(request.answer(ApprovalChoice::Deny)),
        },
    });
    assert!(transcript.pending_approvals().is_empty());
    assert_eq!(tool(&transcript).status, ToolStatus::Denied);
    apply(&mut transcript, &vector!("result"));
    assert_eq!(tool(&transcript).status, ToolStatus::Background);
    assert_eq!(tool(&transcript).output_json.as_deref(), Some("[]"));
    apply(&mut transcript, &vector!("background-exit-failed"));
    assert_eq!(tool(&transcript).status, ToolStatus::Failed);
    apply(&mut transcript, &vector!("background-exit-zero"));
    assert_eq!(tool(&transcript).status, ToolStatus::Succeeded);
}

#[test]
fn a_deletion_marks_the_chat_deleted() {
    let mut transcript = Transcript::new();
    apply(&mut transcript, &vector!("command"));
    assert!(transcript.rows().is_empty());
    apply(&mut transcript, &vector!("deleted"));
    assert!(transcript.deleted());
}

#[test]
fn a_snapshot_replaces_the_transcript_and_keeps_its_window_flag() {
    let mut transcript = Transcript::new();
    apply(&mut transcript, &vector!("text"));
    let bytes = vector!("snapshot");
    let snapshot = CloudSnapshotPayload::from_canonical_bytes(&bytes).unwrap();
    transcript.restore(&snapshot);
    assert!(transcript.omitted_earlier());
    assert_eq!(transcript.control_revision(), 12);
    assert_eq!(transcript.rows()[0].role, Role::User);
    assert!(transcript.deleted());
    assert!(transcript.rows().iter().any(|row| row.tool.is_some()));
}

#[test]
fn rows_beyond_the_bound_drop_the_oldest_and_mark_omitted_history() {
    let mut transcript = Transcript::new();
    let prompt = vector!("prompt");
    for _ in 0..=MAX_TRANSCRIPT_ROWS {
        apply(&mut transcript, &prompt);
    }
    assert_eq!(transcript.rows().len(), MAX_TRANSCRIPT_ROWS);
    assert!(transcript.omitted_earlier());
}

macro_rules! session {
    ($name:literal) => {
        hex::decode(
            include_str!(concat!(
                "../../../../fixtures/cloud-session-v1/",
                $name,
                ".hex"
            ))
            .trim(),
        )
        .unwrap()
    };
}
fn session_row(transcript: &Transcript) -> &SessionCall {
    transcript
        .rows()
        .iter()
        .find_map(|row| row.session.as_ref())
        .unwrap()
}

#[test]
fn a_consent_request_and_its_session_lifecycle_show_as_one_session_row() {
    let mut transcript = Transcript::new();
    apply(&mut transcript, &session!("authentication-requested"));
    let row = session_row(&transcript);
    assert!(row.ssh);
    assert!(matches!(row.status, SessionStatus::AwaitingConsent { .. }));
    assert!(row.terminal.is_some());
    apply(&mut transcript, &session!("session-established"));
    assert_eq!(transcript.rows().len(), 1, "the same attempt");
    assert_eq!(session_row(&transcript).status, SessionStatus::Established);
    apply(&mut transcript, &session!("session-lost"));
    assert!(matches!(
        session_row(&transcript).status,
        SessionStatus::Lost(_)
    ));
    let mut refused = Transcript::new();
    apply(&mut refused, &session!("session-refused"));
    let row = session_row(&refused);
    assert!(matches!(row.status, SessionStatus::Refused(_)));
    assert_eq!(row.terminal, None, "not stated without a consent request");
}

#[test]
fn deltas_carry_only_what_changed_since_the_last_one() {
    let mut transcript = Transcript::new();
    assert_eq!(transcript.take_delta(), None);
    apply(&mut transcript, &vector!("prompt"));
    let first = transcript.take_delta().unwrap();
    assert!(!first.reset);
    assert_eq!(first.changed_from, Some(0));
    assert_eq!(first.rows.len(), 1);
    assert!(first.runs.is_some());
    apply(&mut transcript, &vector!("text"));
    apply(&mut transcript, &vector!("text"));
    let second = transcript.take_delta().unwrap();
    assert_eq!(second.changed_from, Some(1), "only the new, merged row");
    assert_eq!(second.rows.len(), 1);
    assert_eq!(second.rows[0].index, 1);
    assert!(second.runs.is_none());
    let bytes = vector!("snapshot");
    transcript.restore(&CloudSnapshotPayload::from_canonical_bytes(&bytes).unwrap());
    let restored = transcript.take_delta().unwrap();
    assert!(restored.reset);
    assert!(
        restored.rows.iter().all(|row| row.index >= 2),
        "indices keep growing"
    );
    assert_eq!(restored.first_index, restored.rows[0].index);
}

#[test]
fn a_command_of_this_device_is_pending_until_the_runner_accepts_it() {
    let mut transcript = Transcript::new();
    let prompt_bytes = vector!("prompt");
    let prompt = CloudEvent::from_canonical_bytes(&prompt_bytes)
        .unwrap()
        .payload;
    let CloudEventPayload::PromptAccepted { command, .. } = &prompt else {
        panic!("a prompt");
    };
    transcript.track(PendingCommand {
        command_id: command.id,
        kind: PendingKind::Prompt,
        text: "public fixture prompt".to_owned(),
        run: None,
        state: CommandState::Sending,
        at_ms: 1,
    });
    transcript.set_command_state(&command.id, CommandState::Delivered);
    assert_eq!(
        transcript.pending_commands()[0].state,
        CommandState::Delivered
    );
    apply(&mut transcript, &vector!("prompt"));
    assert_eq!(
        transcript.pending_commands()[0].state,
        CommandState::Accepted
    );
    transcript.set_command_state(&command.id, CommandState::Unreachable);
    assert_eq!(
        transcript.pending_commands()[0].state,
        CommandState::Accepted,
        "an accepted command stays accepted"
    );
    for id in 0..=MAX_PENDING_COMMANDS {
        transcript.track(PendingCommand {
            command_id: {
                let mut other = [0xee; 16];
                other[0] = u8::try_from(id).unwrap();
                other
            },
            kind: PendingKind::Stop,
            text: String::new(),
            run: None,
            state: CommandState::Sending,
            at_ms: 2,
        });
    }
    assert_eq!(transcript.pending_commands().len(), MAX_PENDING_COMMANDS);
    assert!(
        transcript
            .pending_commands()
            .iter()
            .all(|pending| pending.command_id != command.id),
        "the settled command went first"
    );
}

#[test]
fn every_event_fixture_round_trips_through_the_checkpoint_codec() {
    let mut transcript = Transcript::new();
    for bytes in [
        vector!("prompt"),
        vector!("status"),
        vector!("text"),
        vector!("usage"),
        vector!("intent"),
        vector!("approval"),
        vector!("result"),
        vector!("background-exit-failed"),
        session!("authentication-requested"),
        session!("session-lost"),
        vector!("deleted"),
    ] {
        apply(&mut transcript, &bytes);
    }
    let mut out = codec::Writer(Vec::new());
    transcript.encode(&mut out).unwrap();
    let mut input = codec::Reader(&out.0);
    let mut decoded = Transcript::decode(&mut input).unwrap();
    input.finish().unwrap();
    transcript.take_delta();
    decoded.take_delta();
    assert_eq!(decoded, transcript);
    for size in [0, out.0.len() / 2, out.0.len() - 1] {
        assert!(Transcript::decode(&mut codec::Reader(&out.0[..size])).is_err());
    }
}
