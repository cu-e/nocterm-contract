//! The chat stream of the recorded session: the device's prompt, the run, the assistant's text,
//! a tool call waiting for approval, usage and the waiting status, sealed as the runner
//! publishes them, and one later line of text that arrives by Watch.
use nocterm_cloud_device::records::ChatSelector;
use nocterm_hub_model::cloud::{
    CloudTextId, CommandIssuer, CommandKind, RecordContext, RecordKind, RecordPosition,
    RunCoordinate,
    events::{
        AcceptedCommand, AcceptedPrompt, CloudEvent, CloudEventPayload, CloudRunStatus,
        CloudTextChannel, CloudUsage,
    },
    head::HeadRecordAnchor,
    payload::{ModelSelection, PromptPart},
    relay::RelayBinding,
};
use nocterm_keys::{
    DeviceKey,
    cloud::{ChatKey, RunnerSigningKey, seal_event},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    ACCESS_TOKEN, ACCOUNT, ANSWER, DEVICE_ID, DEVICE_SEED, LATER, NOW, PROMPT, RUN, RUNNER_ID,
    RUNNER_PROOF, RUNNER_SIGNING_SEED,
};

/// The chat's events: the device's prompt, the run starting, the assistant's text, a tool call
/// waiting for approval (the public `approval` vector), usage, the waiting status, and one later
/// line of text that arrives by Watch.
fn events(at: u64) -> Vec<Vec<u8>> {
    let issuer = CommandIssuer {
        device_id: CloudTextId::new(DEVICE_ID).unwrap(),
        signing_key: DeviceKey::from_seed(&DEVICE_SEED).public_key(),
        access_token_digest: Sha256::digest(ACCESS_TOKEN.as_bytes()).into(),
    };
    let model = ModelSelection {
        provider: CloudTextId::new("managed").unwrap(),
        model: CloudTextId::new("gpt-5-mini").unwrap(),
        pricing_policy: CloudTextId::new("managed-v1").unwrap(),
    };
    let event = |revision: u64, payload: CloudEventPayload<'static>| {
        CloudEvent {
            control_revision: revision,
            timestamp_ms: at + revision * 1_000,
            payload,
        }
        .canonical_bytes()
        .unwrap()
    };
    let approval_bytes =
        hex::decode(include_str!("../../../../../fixtures/cloud-events-v1/approval.hex").trim())
            .unwrap();
    let mut approval = CloudEvent::from_canonical_bytes(&approval_bytes).unwrap();
    approval.control_revision = 4;
    approval.timestamp_ms = at + 4_000;
    let text = |revision, step, text| {
        event(
            revision,
            CloudEventPayload::Text {
                run: RUN,
                step: Some([step; 16]),
                channel: CloudTextChannel::Assistant,
                text,
            },
        )
    };
    let prompt = CloudEventPayload::PromptAccepted {
        command: AcceptedCommand {
            id: [0x11; 16],
            kind: CommandKind::SubmitPrompt,
            signed_message_digest: [0x12; 32],
            issuer,
            expected_control_revision: 0,
        },
        run: RUN,
        prompt: Box::new(AcceptedPrompt {
            content: vec![PromptPart::Text(PROMPT)],
            model,
            target: None,
            existing_session: None,
        }),
    };
    let usage = CloudUsage {
        input_tokens: Some(812),
        output_tokens: Some(64),
        total_tokens: Some(876),
        cached_input_tokens: None,
        thought_tokens: None,
        cost_micros: Some(1_250),
    };
    let status = |status| CloudEventPayload::Status { run: RUN, status };
    vec![
        event(1, prompt),
        event(2, status(CloudRunStatus::Running)),
        text(3, 0x31, ANSWER),
        approval.canonical_bytes().unwrap(),
        event(5, CloudEventPayload::Usage { run: RUN, usage }),
        event(6, status(CloudRunStatus::WaitingApproval)),
        text(7, 0x32, LATER),
    ]
}

/// The sealed records as the runner publishes them.
pub(super) fn records(selector: &ChatSelector, key: &ChatKey) -> Vec<(Value, HeadRecordAnchor)> {
    let bodies = events(u64::try_from(NOW - 600_000).unwrap());
    bodies
        .iter()
        .enumerate()
        .map(|(index, body)| {
            seal(
                selector,
                key,
                u64::try_from(index + 1).unwrap(),
                Some(RUN),
                body,
            )
        })
        .collect()
}

/// The event `body` sealed and signed as the runner publishes it at `sequence` (also its chat
/// cursor and control revision), in `run` (`None`: chat-scoped), with its head anchor.
pub(super) fn seal(
    selector: &ChatSelector,
    key: &ChatKey,
    sequence: u64,
    run: Option<RunCoordinate>,
    body: &[u8],
) -> (Value, HeadRecordAnchor) {
    let signer = RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED);
    let tag = u8::try_from(sequence).unwrap();
    let position = RecordPosition {
        writer_epoch: 1,
        sequence,
        journal_sequence: sequence,
        revision: sequence,
    };
    let context =
        RecordContext::new(selector.coordinate().unwrap(), position, [tag; 16], run).unwrap();
    let sealed = seal_event(key, &signer, context.clone(), body).unwrap();
    let digest: [u8; 32] = Sha256::digest(&sealed).into();
    let anchor = HeadRecordAnchor {
        kind: RecordKind::Event,
        position: context.position(),
        id: context.id(),
        run: context.run(),
        ciphertext_digest: digest,
    };
    let record = json!({
        "publicationId": hex::encode([0xa0 + tag; 16]),
        "binding": hex::encode(RelayBinding::event(context).canonical_bytes().unwrap()),
        "totalBytes": sealed.len(),
        "ciphertextSha256": hex::encode(digest),
        "cursor": sequence,
        "originAccountId": ACCOUNT,
        "originSigningKey": hex::encode(RUNNER_PROOF),
        "originRunnerId": hex::encode(RUNNER_ID),
        "data": hex::encode(&sealed),
    });
    (record, anchor)
}
