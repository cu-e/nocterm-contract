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
