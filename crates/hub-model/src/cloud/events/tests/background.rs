use super::*;

pub(super) fn lifecycle(
    outcome: BackgroundOutcome,
) -> Result<BackgroundLifecyclePayload<'static>, Box<dyn std::error::Error>> {
    Ok(BackgroundLifecyclePayload {
        job: BackgroundJob {
            intent: [8; 16],
            execution: approval()?.execution,
            terminal: "original-terminal",
            command: "original-job",
            window: None,
        },
        step: [9; 16],
        arguments_digest: ToolArguments::ListTerminals.digest()?,
        mutates: false,
        dispatch_writer_epoch: 1,
        dispatch_revision: 3,
        outcome,
    })
}

#[test]
fn lifecycle_outcomes_match_independent_vectors_and_preserve_original_dispatch() -> TestResult {
    for (outcome, fixture) in [
        (
            BackgroundOutcome::Retained,
            include_str!("../../../../../../fixtures/cloud-events-v1/background-retained.hex"),
        ),
        (
            BackgroundOutcome::ObservedExit(0),
            include_str!("../../../../../../fixtures/cloud-events-v1/background-exit-zero.hex"),
        ),
        (
            BackgroundOutcome::ObservedExit(7),
            include_str!("../../../../../../fixtures/cloud-events-v1/background-exit-failed.hex"),
        ),
        (
            BackgroundOutcome::Unknown,
            include_str!("../../../../../../fixtures/cloud-events-v1/background-unknown.hex"),
        ),
    ] {
        let event = CloudEvent {
            control_revision: 11,
            timestamp_ms: 100_010,
            payload: CloudEventPayload::BackgroundLifecycle(Box::new(lifecycle(outcome)?)),
        };
        let bytes = hex::decode(fixture.trim())?;
        assert_eq!(event.canonical_bytes()?, bytes);
        assert_eq!(CloudEvent::from_canonical_bytes(&bytes)?, event);
        event.require_context(&context(Some(run()))?)?;
        assert_eq!(
            event.require_context(&context(None)?),
            Err(EventPayloadError::Context)
        );
        let mut invalid = bytes.clone();
        invalid.push(0);
        assert!(CloudEvent::from_canonical_bytes(&invalid).is_err());
        for length in 0..bytes.len() {
            assert!(CloudEvent::from_canonical_bytes(&bytes[..length]).is_err());
        }
    }
    Ok(())
}

#[test]
fn original_dispatch_is_not_replaced_by_cleanup_writer_or_a_different_run() -> TestResult {
    let payload =
        CloudEventPayload::BackgroundLifecycle(Box::new(lifecycle(BackgroundOutcome::Unknown)?));
    let event = observation(payload);
    let original = context(Some(run()))?;
    let cleanup = RecordContext::new(
        original.chat().clone(),
        RecordPosition {
            writer_epoch: 4,
            ..original.position()
        },
        original.id(),
        Some(run()),
    )?;
    event.require_context(&cleanup)?;
    let different = RecordContext::new(
        original.chat().clone(),
        cleanup.position(),
        original.id(),
        Some(RunCoordinate {
            id: [0x31; 16],
            expected_epoch: 5,
        }),
    )?;
    assert_eq!(
        event.require_context(&different),
        Err(EventPayloadError::Context)
    );
    let bytes = event.canonical_bytes()?;
    let CloudEventPayload::BackgroundLifecycle(actual) =
        CloudEvent::from_canonical_bytes(&bytes)?.payload
    else {
        return Err("background".into());
    };
    assert_eq!(actual.dispatch_writer_epoch, 1);
    assert_eq!(actual.dispatch_revision, 3);
    assert_eq!(actual.outcome, BackgroundOutcome::Unknown);
    Ok(())
}

#[test]
fn malformed_lifecycle_ids_epochs_and_outcome_tags_are_refused() -> TestResult {
    let mut value = lifecycle(BackgroundOutcome::Retained)?;
    value.dispatch_writer_epoch = 0;
    assert!(
        observation(CloudEventPayload::BackgroundLifecycle(Box::new(value)))
            .validate()
            .is_err()
    );
    let mut value = lifecycle(BackgroundOutcome::Retained)?;
    value.dispatch_revision = 0;
    assert!(
        observation(CloudEventPayload::BackgroundLifecycle(Box::new(value)))
            .validate()
            .is_err()
    );
    let mut value = lifecycle(BackgroundOutcome::Retained)?;
    value.job.terminal = "\0";
    assert!(
        observation(CloudEventPayload::BackgroundLifecycle(Box::new(value)))
            .validate()
            .is_err()
    );
    let mut bytes = observation(CloudEventPayload::BackgroundLifecycle(Box::new(lifecycle(
        BackgroundOutcome::Retained,
    )?)))
    .canonical_bytes()?;
    *bytes.last_mut().ok_or("missing outcome")? = 255;
    assert!(CloudEvent::from_canonical_bytes(&bytes).is_err());
    Ok(())
}
