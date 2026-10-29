use super::*;
use crate::cloud::payload::{AuthenticationRequest, SessionFailure, SessionOutcome, SshProof};

const REQUEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cloud-session-v1/authentication-requested.hex"
));
const ESTABLISHED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cloud-session-v1/session-established.hex"
));
const LOST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cloud-session-v1/session-lost.hex"
));
const REFUSED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cloud-session-v1/session-refused.hex"
));

#[test]
fn session_start_observations_preserve_original_context_answer6_and_snapshot_bytes() -> TestResult {
    let answer_bytes = hex::decode(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/cloud-payload-v1/ssh-approve.hex"
        ))
        .trim(),
    )?;
    let CloudCommandPayload::AnswerSshConsent(answer) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::AnswerSshConsent, &answer_bytes)?
    else {
        return Err("answer".into());
    };
    let vectors = [REQUEST, ESTABLISHED, LOST, REFUSED]
        .map(|text| hex::decode(text.trim()))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut events = Vec::new();
    for bytes in &vectors {
        let event = CloudEvent::from_canonical_bytes(bytes)?;
        assert_eq!(event.canonical_bytes()?, *bytes);
        let length = event.canonical_len()?;
        assert_eq!(event.canonical_bytes_exact(length)?, *bytes);
        for wrong in [length - 1, length + 1, usize::MAX] {
            assert!(event.canonical_bytes_exact(wrong).is_err());
        }
        event.require_context(&context(Some(answer.binding.run))?)?;
        assert!(event.require_context(&context(None)?).is_err());
        assert!(event.require_context(&context(Some(run()))?).is_err());
        if let CloudEventPayload::AuthenticationRequested(request) = &event.payload {
            assert_eq!(request.binding, answer.binding);
            assert_eq!(request.proof, answer.proof);
        }
        for size in 0..bytes.len() {
            assert!(CloudEvent::from_canonical_bytes(&bytes[..size]).is_err());
        }
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(CloudEvent::from_canonical_bytes(&suffix).is_err());
        events.push(event);
    }
    let snapshot = CloudSnapshotPayload {
        control_revision: 12,
        timestamp_ms: 120_000,
        omitted_earlier: true,
        events,
    };
    let bytes = snapshot.canonical_bytes()?;
    assert_eq!(
        CloudSnapshotPayload::from_canonical_bytes(&bytes)?,
        snapshot
    );
    assert_eq!(
        snapshot.canonical_bytes_exact(snapshot.canonical_len()?)?,
        bytes
    );
    Ok(())
}

#[test]
fn session_start_proof_fields_are_bounded_and_lifecycle_tags_and_receipts_are_closed() -> TestResult
{
    let bytes = hex::decode(REQUEST.trim())?;
    let event = CloudEvent::from_canonical_bytes(&bytes)?;
    let CloudEventPayload::AuthenticationRequested(request) = event.payload else {
        return Err("request".into());
    };
    for size in [1024, 1025] {
        let key = vec![1; size];
        let mut changed = request.clone();
        changed.binding.user_key_blob = &key;
        let output =
            observation(CloudEventPayload::AuthenticationRequested(changed)).canonical_bytes();
        assert_eq!(output.is_ok(), size == 1024);
    }
    for (host, signature, userauth, valid) in [
        (1024, 1024, 4096, true),
        (1025, 1, 1, false),
        (1, 1025, 1, false),
        (1, 1, 4097, false),
        (0, 1, 1, false),
        (1, 0, 1, false),
        (1, 1, 0, false),
    ] {
        let host = vec![1; host];
        let signature = vec![2; signature];
        let userauth = vec![3; userauth];
        let changed = AuthenticationRequest {
            proof: SshProof {
                host_key_blob: &host,
                host_signature_blob: &signature,
                userauth_payload: &userauth,
            },
            ..*request.clone()
        };
        assert_eq!(
            observation(CloudEventPayload::AuthenticationRequested(Box::new(
                changed
            )))
            .canonical_bytes()
            .is_ok(),
            valid
        );
    }
    Ok(())
}

#[test]
fn session_start_lifecycle_reasons_and_actual_receipt_coordinates_are_closed() -> TestResult {
    let bytes = hex::decode(ESTABLISHED.trim())?;
    let event = CloudEvent::from_canonical_bytes(&bytes)?;
    let CloudEventPayload::SessionState(state) = event.payload else {
        return Err("state".into());
    };
    let SessionOutcome::Established(receipt) = &state.outcome else {
        return Err("receipt".into());
    };
    for reason in [
        SessionFailure::Denied,
        SessionFailure::Expired,
        SessionFailure::Cancelled,
        SessionFailure::SourceChanged,
        SessionFailure::Unavailable,
        SessionFailure::Unsupported,
        SessionFailure::Capacity,
        SessionFailure::ConnectionLost,
    ] {
        for outcome in [
            SessionOutcome::Refused(reason),
            SessionOutcome::Lost {
                session: receipt.clone(),
                reason,
            },
        ] {
            let event = observation(CloudEventPayload::SessionState(Box::new(
                crate::cloud::payload::SessionState {
                    outcome,
                    ..*state.clone()
                },
            )));
            let bytes = event.canonical_bytes()?;
            assert_eq!(CloudEvent::from_canonical_bytes(&bytes)?, event);
        }
    }
    let mut changed = state.clone();
    let SessionOutcome::Established(receipt) = &mut changed.outcome else {
        return Err("receipt".into());
    };
    receipt.epoch = 0;
    assert!(
        observation(CloudEventPayload::SessionState(changed))
            .validate()
            .is_err()
    );
    let mut changed = state.clone();
    let SessionOutcome::Established(receipt) = &mut changed.outcome else {
        return Err("receipt".into());
    };
    receipt.access.target.workspace[0] ^= 1;
    assert!(
        observation(CloudEventPayload::SessionState(changed))
            .validate()
            .is_err()
    );
    for fixture in [LOST, REFUSED] {
        let mut bytes = hex::decode(fixture.trim())?;
        *bytes.last_mut().ok_or("reason")? = 255;
        assert!(CloudEvent::from_canonical_bytes(&bytes).is_err());
    }
    Ok(())
}
