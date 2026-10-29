use super::*;

const LOCAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cloud-session-v1/begin-local.hex"
));
const SSH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cloud-session-v1/begin-ssh.hex"
));
const CONNECT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cloud-session-v1/begin-connect-only.hex"
));

#[test]
fn session_start_vectors_keep_local_distinct_and_ssh_binding_identical_to_answer6() -> TestResult {
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
        return Err("answer fixture".into());
    };
    for (index, fixture) in [LOCAL, SSH, CONNECT].into_iter().enumerate() {
        let bytes = hex::decode(fixture.trim())?;
        let payload = CloudCommandPayload::from_canonical_bytes(CommandKind::BeginSession, &bytes)?;
        assert_eq!(payload.canonical_bytes()?, bytes);
        let CloudCommandPayload::BeginSession(start) = &payload else {
            return Err("start".into());
        };
        match start.as_ref() {
            BeginSession::Local { startup, .. } => {
                assert_eq!(index, 0);
                assert_eq!(startup.capabilities(), 12);
            }
            BeginSession::Ssh { binding, startup } => {
                assert_ne!(index, 0);
                assert_eq!(*binding, answer.binding);
                assert_eq!(startup.capabilities(), if index == 2 { 8 } else { 12 });
            }
        }
        payload.require_header(&header(CommandKind::BeginSession, Some(start.run()))?)?;
        assert!(
            payload
                .require_header(&header(CommandKind::BeginSession, None)?)
                .is_err()
        );
        let wrong = RunCoordinate {
            expected_epoch: start.run().expected_epoch + 1,
            ..start.run()
        };
        assert!(
            payload
                .require_header(&header(CommandKind::BeginSession, Some(wrong))?)
                .is_err()
        );
        assert!(
            payload
                .require_header(&header(CommandKind::Stop, Some(start.run()))?)
                .is_err()
        );
        for size in 0..bytes.len() {
            assert!(
                CloudCommandPayload::from_canonical_bytes(
                    CommandKind::BeginSession,
                    &bytes[..size]
                )
                .is_err()
            );
        }
        let mut suffixed = bytes;
        suffixed.push(0);
        assert!(
            CloudCommandPayload::from_canonical_bytes(CommandKind::BeginSession, &suffixed)
                .is_err()
        );
    }
    // Extracting the old fields into one codec cannot change the existing format.
    assert_eq!(
        CloudCommandPayload::AnswerSshConsent(answer).canonical_bytes()?,
        answer_bytes
    );
    Ok(())
}

#[test]
fn session_start_refuses_unknown_transport_startup_and_invalid_original_attempt() -> TestResult {
    let bytes = hex::decode(LOCAL.trim())?;
    let CloudCommandPayload::BeginSession(start) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::BeginSession, &bytes)?
    else {
        return Err("start".into());
    };
    let BeginSession::Local { binding, startup } = *start else {
        return Err("local".into());
    };
    for (issued_ms, expires_ms, nonce, epoch) in [
        (0, 50_000, binding.nonce, 9),
        (100_000, 100_000, binding.nonce, 9),
        (100_000, 160_001, binding.nonce, 9),
        (100_000, 150_000, [0; 32], 9),
        (100_000, 150_000, binding.nonce, 0),
        (i64::MAX as u64, i64::MAX as u64 + 1, binding.nonce, 9),
    ] {
        let mut changed = binding.clone();
        changed.issued_ms = issued_ms;
        changed.expires_ms = expires_ms;
        changed.nonce = nonce;
        changed.run.expected_epoch = epoch;
        assert!(
            CloudCommandPayload::BeginSession(Box::new(BeginSession::Local {
                binding: changed,
                startup
            }))
            .validate()
            .is_err()
        );
    }
    let mut maximum = binding.clone();
    maximum.expires_ms = maximum.issued_ms + MAX_SESSION_START_MS;
    CloudCommandPayload::BeginSession(Box::new(BeginSession::Local {
        binding: maximum,
        startup,
    }))
    .validate()?;
    let offset = 4 + b"nocterm/cloud-command-payload/v1".len() + 2;
    for (position, values) in [(offset, [0, 3, 255]), (offset + 1, [0, 3, 255])] {
        for value in values {
            let mut changed = bytes.clone();
            changed[position] = value;
            assert!(
                CloudCommandPayload::from_canonical_bytes(CommandKind::BeginSession, &changed)
                    .is_err()
            );
        }
    }
    Ok(())
}
