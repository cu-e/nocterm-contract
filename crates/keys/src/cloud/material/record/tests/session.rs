use super::*;
use nocterm_hub_model::cloud::{
    CommandKind,
    events::{CloudEvent, CloudEventPayload, CloudSnapshotPayload},
    payload::{CloudCommandPayload, SessionOutcome},
};

const EVENTS: [&str; 3] = [
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/cloud-session-v1/authentication-requested.hex"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/cloud-session-v1/session-established.hex"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/cloud-session-v1/session-lost.hex"
    )),
];

#[test]
fn session_start_actual_signed_records_keep_original_proof_receipt_and_source() -> TestResult {
    let answer = hex::decode(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/cloud-payload-v1/ssh-approve.hex"
        ))
        .trim(),
    )?;
    let CloudCommandPayload::AnswerSshConsent(answer) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::AnswerSshConsent, &answer)?
    else {
        return Err("answer".into());
    };
    let key = ChatKey::generate()?;
    let signer = RunnerSigningKey::generate()?;
    let wrong = RunnerSigningKey::generate()?;
    let context = RecordContext::new(
        chat()?,
        context()?.position(),
        [9; 16],
        Some(answer.binding.run),
    )?;
    let mut baseline = Vec::new();
    for fixture in EVENTS {
        let bytes = hex::decode(fixture.trim())?;
        let event = CloudEvent::from_canonical_bytes(&bytes)?;
        event.require_context(&context)?;
        let sealed = seal_event(&key, &signer, context.clone(), &bytes)?;
        let opened = open_event(&key, &signer.public_key(), &context, &sealed)?;
        let original = CloudEvent::from_record(&opened.record()?)?;
        assert_eq!(original, event);
        match &original.payload {
            CloudEventPayload::AuthenticationRequested(request) => {
                assert_eq!(request.binding, answer.binding);
                assert_eq!(request.proof, answer.proof);
            }
            CloudEventPayload::SessionState(state) => assert!(matches!(
                state.outcome,
                SessionOutcome::Established(_) | SessionOutcome::Lost { .. }
            )),
            _ => return Err("session observation".into()),
        }
        assert!(open_event(&key, &wrong.public_key(), &context, &sealed).is_err());
        let mut altered = sealed;
        *altered.last_mut().ok_or("ciphertext")? ^= 1;
        assert!(open_event(&key, &signer.public_key(), &context, &altered).is_err());
        let mut changed = context.chat().namespace().clone();
        changed.account_id = nocterm_hub_model::cloud::CloudTextId::new("different-account")?;
        let other_chat = nocterm_hub_model::cloud::ChatCoordinate::new(
            changed,
            context.chat().runner(),
            context.chat().chat_id(),
            context.chat().key_epoch(),
        )?;
        let other =
            RecordContext::new(other_chat, context.position(), context.id(), context.run())?;
        let sealed = seal_event(&key, &signer, context.clone(), &bytes)?;
        assert!(open_event(&key, &signer.public_key(), &other, &sealed).is_err());
        baseline.push(bytes);
    }
    let events = baseline
        .iter()
        .map(|bytes| CloudEvent::from_canonical_bytes(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = CloudSnapshotPayload {
        control_revision: 12,
        timestamp_ms: 120_000,
        omitted_earlier: true,
        events,
    };
    let bytes = snapshot.canonical_bytes()?;
    let sealed = seal_snapshot(&key, &signer, context.clone(), &bytes)?;
    let opened = open_snapshot(&key, &signer.public_key(), &context, &sealed)?;
    assert_eq!(
        CloudSnapshotPayload::from_record(&opened.record()?)?,
        snapshot
    );
    Ok(())
}
