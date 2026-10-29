use super::*;
use crate::cloud::{
    ChatCoordinate, CloudNamespace, CloudTextId, CommandIssuer, CommandKind, RecordPosition,
    RunCoordinate, RunnerCoordinate,
    payload::{ApprovalPayload, CloudCommandPayload},
    tool_arguments::ToolArguments,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn run() -> RunCoordinate {
    RunCoordinate {
        id: [0x21; 16],
        expected_epoch: 2,
    }
}
fn command() -> Result<AcceptedCommand, Box<dyn std::error::Error>> {
    Ok(AcceptedCommand {
        id: [3; 16],
        kind: CommandKind::SubmitPrompt,
        signed_message_digest: [4; 32],
        issuer: CommandIssuer {
            device_id: CloudTextId::new("device")?,
            signing_key: [5; 32],
            access_token_digest: [6; 32],
        },
        expected_control_revision: 7,
    })
}
fn approval() -> Result<ApprovalPayload, Box<dyn std::error::Error>> {
    let bytes =
        hex::decode(include_str!("../../../../../fixtures/cloud-payload-v1/approval.hex").trim())?;
    match CloudCommandPayload::from_canonical_bytes(CommandKind::ResolveApproval, &bytes)? {
        CloudCommandPayload::ResolveApproval(mut answer) => {
            answer.execution.run = run();
            Ok(*answer)
        }
        _ => Err("approval fixture".into()),
    }
}
fn display() -> ToolPresentation<'static> {
    ToolPresentation {
        tool: "list_terminals",
        arguments_json: "{}",
        destination: None,
        redacted: false,
        outcome: Some(DisplayOutcome::Pending),
    }
}
fn intent() -> Result<ToolIntentPayload<'static>, Box<dyn std::error::Error>> {
    let args = ToolArguments::ListTerminals;
    Ok(ToolIntentPayload {
        id: [8; 16],
        step: [9; 16],
        execution: approval()?.execution,
        arguments_digest: args.digest()?,
        mutates: false,
        arguments: args,
        display: display(),
    })
}
fn background_result() -> Result<CloudEventPayload<'static>, Box<dyn std::error::Error>> {
    Ok(CloudEventPayload::ToolResult {
        run: run(),
        observation: Box::new(ToolObservationPayload {
            intent: [8; 16],
            output_json: "[]",
            display: display(),
            effect: ObservedEffect::Background(Box::new(BackgroundJob {
                intent: [8; 16],
                execution: approval()?.execution,
                terminal: "original-terminal",
                command: "original-job",
                window: None,
            })),
            failed: false,
        }),
    })
}
fn all_events(prompt: &[u8]) -> Result<Vec<CloudEvent<'_>>, Box<dyn std::error::Error>> {
    let CloudCommandPayload::SubmitPrompt(prompt) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::SubmitPrompt, prompt)?
    else {
        return Err("prompt fixture".into());
    };
    let payloads = vec![
        CloudEventPayload::CommandAccepted {
            command: command()?,
            run: Some(run()),
        },
        CloudEventPayload::PromptAccepted {
            command: command()?,
            run: run(),
            prompt: Box::new(AcceptedPrompt {
                content: prompt.content,
                model: prompt.model,
                target: prompt.target,
                existing_session: prompt.existing_session,
            }),
        },
        CloudEventPayload::Status {
            run: run(),
            status: CloudRunStatus::WaitingApproval,
        },
        CloudEventPayload::Text {
            run: run(),
            step: Some([9; 16]),
            channel: CloudTextChannel::Thought,
            text: "sensitive-text",
        },
        CloudEventPayload::Usage {
            run: run(),
            usage: CloudUsage {
                input_tokens: None,
                output_tokens: Some(0),
                ..CloudUsage::default()
            },
        },
        CloudEventPayload::ToolIntent(Box::new(intent()?)),
        CloudEventPayload::Approval {
            intent: Box::new(intent()?),
            expires_at_ms: 200_000,
        },
        CloudEventPayload::ApprovalResolved {
            command: [10; 16],
            answer: Box::new(approval()?),
        },
        background_result()?,
        CloudEventPayload::Deleted { command: [11; 16] },
        CloudEventPayload::BackgroundLifecycle(Box::new(background::lifecycle(
            BackgroundOutcome::Retained,
        )?)),
    ];
    Ok(payloads
        .into_iter()
        .zip(0_u64..)
        .map(|(payload, index)| CloudEvent {
            control_revision: 8 + index / 3,
            timestamp_ms: 100_000 + index,
            payload,
        })
        .collect())
}
fn observation(payload: CloudEventPayload<'_>) -> CloudEvent<'_> {
    CloudEvent {
        control_revision: 8,
        timestamp_ms: 100_000,
        payload,
    }
}
fn context(
    current_run: Option<RunCoordinate>,
) -> Result<RecordContext, Box<dyn std::error::Error>> {
    Ok(RecordContext::new(
        ChatCoordinate::new(
            CloudNamespace {
                hub_instance_id: CloudTextId::new("hub")?,
                account_id: CloudTextId::new("account")?,
            },
            RunnerCoordinate {
                id: [1; 16],
                key_epoch: 1,
            },
            [2; 16],
            1,
        )?,
        RecordPosition {
            writer_epoch: 1,
            sequence: 2,
            journal_sequence: 3,
            revision: 4,
        },
        [12; 16],
        current_run,
    )?)
}
#[test]
fn all_observation_kinds_and_snapshot_preserve_exact_bounded_semantics() -> TestResult {
    let prompt =
        hex::decode(include_str!("../../../../../fixtures/cloud-payload-v1/prompt.hex").trim())?;
    let events = all_events(&prompt)?;
    for event in &events {
        let bytes = event.canonical_bytes()?;
        assert_eq!(CloudEvent::from_canonical_bytes(&bytes)?, *event);
        assert!(!format!("{event:?}").contains("sensitive-text"));
    }
    let snapshot = CloudSnapshotPayload {
        control_revision: 12,
        timestamp_ms: 200_000,
        omitted_earlier: true,
        events,
    };
    let bytes = snapshot.canonical_bytes()?;
    assert_eq!(
        CloudSnapshotPayload::from_canonical_bytes(&bytes)?,
        snapshot
    );
    assert!(!format!("{snapshot:?}").contains("sensitive-text"));
    Ok(())
}
#[test]
fn unknown_tags_truncation_suffixes_and_wrong_run_fail_before_projection() -> TestResult {
    let event = observation(CloudEventPayload::Text {
        run: run(),
        step: None,
        channel: CloudTextChannel::Assistant,
        text: "hello",
    });
    let bytes = event.canonical_bytes()?;
    for size in 0..bytes.len() {
        assert!(CloudEvent::from_canonical_bytes(&bytes[..size]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(CloudEvent::from_canonical_bytes(&extra).is_err());
    let mut kind = bytes;
    kind[4 + b"nocterm/cloud-event-payload/v1".len() + 16] = 255;
    assert!(CloudEvent::from_canonical_bytes(&kind).is_err());
    event.require_context(&context(Some(run()))?)?;
    assert!(event.require_context(&context(None)?).is_err());
    let different = RunCoordinate {
        id: [0; 16],
        ..run()
    };
    assert!(event.require_context(&context(Some(different))?).is_err());
    Ok(())
}
#[test]
fn malformed_display_identity_json_and_excessive_history_are_refused() -> TestResult {
    let mut bad = intent()?;
    bad.arguments_digest = [0; 32];
    assert!(
        CloudEventPayload::ToolIntent(Box::new(bad))
            .validate()
            .is_err()
    );
    let mut bad = intent()?;
    bad.display.tool = "run_command";
    assert!(
        CloudEventPayload::ToolIntent(Box::new(bad))
            .validate()
            .is_err()
    );
    let mut bad = intent()?;
    bad.display.arguments_json = "{";
    assert!(
        CloudEventPayload::ToolIntent(Box::new(bad))
            .validate()
            .is_err()
    );
    let large = "x".repeat(MAX_EVENT_TEXT_BYTES + 1);
    assert!(
        CloudEventPayload::Text {
            run: run(),
            step: None,
            channel: CloudTextChannel::Assistant,
            text: &large
        }
        .validate()
        .is_err()
    );
    let snapshot = CloudSnapshotPayload {
        control_revision: 12,
        timestamp_ms: 200_000,
        omitted_earlier: false,
        events: vec![
            observation(CloudEventPayload::Deleted { command: [1; 16] });
            MAX_SNAPSHOT_EVENTS + 1
        ],
    };
    assert!(snapshot.validate().is_err());
    Ok(())
}

fn event_vectors() -> [&'static str; 11] {
    [
        include_str!("../../../../../fixtures/cloud-events-v1/command.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/prompt.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/status.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/text.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/usage.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/intent.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/approval.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/answer.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/result.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/deleted.hex"),
        include_str!("../../../../../fixtures/cloud-events-v1/background-retained.hex"),
    ]
}

#[test]
fn every_kind_and_snapshot_match_independent_public_python_bytes() -> TestResult {
    let prompt =
        hex::decode(include_str!("../../../../../fixtures/cloud-payload-v1/prompt.hex").trim())?;
    let events = all_events(&prompt)?;
    for (event, vector) in events.iter().zip(event_vectors()) {
        let expected = hex::decode(vector.trim())?;
        assert_eq!(event.canonical_bytes()?, expected);
        assert_eq!(CloudEvent::from_canonical_bytes(&expected)?, *event);
    }
    let expected =
        hex::decode(include_str!("../../../../../fixtures/cloud-events-v1/snapshot.hex").trim())?;
    let snapshot = CloudSnapshotPayload {
        control_revision: 12,
        timestamp_ms: 200_000,
        omitted_earlier: true,
        events,
    };
    assert_eq!(snapshot.canonical_bytes()?, expected);
    assert_eq!(
        CloudSnapshotPayload::from_canonical_bytes(&expected)?,
        snapshot
    );
    Ok(())
}

#[test]
fn snapshot_requires_exact_eof_closed_metadata_and_ordered_heads() -> TestResult {
    let bytes =
        hex::decode(include_str!("../../../../../fixtures/cloud-events-v1/snapshot.hex").trim())?;
    for size in 0..bytes.len() {
        assert!(CloudSnapshotPayload::from_canonical_bytes(&bytes[..size]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(CloudSnapshotPayload::from_canonical_bytes(&extra).is_err());
    let metadata = 4 + b"nocterm/cloud-snapshot-payload/v1".len();
    let mut invalid = bytes.clone();
    invalid[metadata + 16] = 2;
    assert!(CloudSnapshotPayload::from_canonical_bytes(&invalid).is_err());
    let mut invalid = bytes.clone();
    invalid[metadata + 17..metadata + 21].copy_from_slice(&4097_u32.to_be_bytes());
    assert!(CloudSnapshotPayload::from_canonical_bytes(&invalid).is_err());
    let mut snapshot = CloudSnapshotPayload::from_canonical_bytes(&bytes)?;
    snapshot.events[1].control_revision = snapshot.events[0].control_revision - 1;
    assert_eq!(snapshot.validate(), Err(EventPayloadError::SnapshotOrder));
    snapshot.events[1].control_revision = snapshot.events[0].control_revision;
    snapshot.timestamp_ms = snapshot.events.last().ok_or("missing event")?.timestamp_ms - 1;
    assert_eq!(snapshot.validate(), Err(EventPayloadError::SnapshotOrder));
    Ok(())
}

#[test]
fn historical_snapshot_runs_and_original_background_run_remain_distinct() -> TestResult {
    let previous = RunCoordinate {
        id: [0x55; 16],
        expected_epoch: 4,
    };
    let mut result = ToolObservationPayload {
        intent: [8; 16],
        output_json: "null",
        display: display(),
        failed: false,
        effect: ObservedEffect::Background(Box::new(BackgroundJob {
            intent: [8; 16],
            execution: approval()?.execution,
            terminal: "terminal",
            command: "job",
            window: None,
        })),
    };
    assert_eq!(
        observation(CloudEventPayload::ToolResult {
            run: previous,
            observation: Box::new(result.clone()),
        })
        .validate(),
        Err(EventPayloadError::Context)
    );
    result.intent = [99; 16];
    assert_eq!(
        observation(CloudEventPayload::ToolResult {
            run: run(),
            observation: Box::new(result),
        })
        .validate(),
        Err(EventPayloadError::Context)
    );
    let snapshot = CloudSnapshotPayload {
        control_revision: 8,
        timestamp_ms: 100_000,
        omitted_earlier: false,
        events: vec![
            observation(CloudEventPayload::Status {
                run: previous,
                status: CloudRunStatus::Completed,
            }),
            observation(CloudEventPayload::Status {
                run: run(),
                status: CloudRunStatus::Running,
            }),
            observation(CloudEventPayload::Status {
                run: previous,
                status: CloudRunStatus::OutcomeUnknown,
            }),
        ],
    };
    let bytes = snapshot.canonical_bytes()?;
    assert_eq!(
        CloudSnapshotPayload::from_canonical_bytes(&bytes)?,
        snapshot
    );
    Ok(())
}

#[test]
fn publication_metadata_keeps_zero_control_and_unknown_usage_without_inventing_values() -> TestResult
{
    let mut event = observation(CloudEventPayload::Usage {
        run: run(),
        usage: CloudUsage::default(),
    });
    event.control_revision = 0;
    let bytes = event.canonical_bytes()?;
    assert_eq!(CloudEvent::from_canonical_bytes(&bytes)?, event);
    for timestamp in [0, u64::MAX] {
        event.timestamp_ms = timestamp;
        assert_eq!(event.validate(), Err(EventPayloadError::Timestamp));
    }
    let empty = CloudSnapshotPayload {
        control_revision: u64::MAX,
        timestamp_ms: 1,
        omitted_earlier: true,
        events: Vec::new(),
    };
    let bytes = empty.canonical_bytes()?;
    assert_eq!(CloudSnapshotPayload::from_canonical_bytes(&bytes)?, empty);
    Ok(())
}

#[test]
fn aggregate_snapshot_limit_is_shared_by_all_borrowed_text_fields() {
    let text = "x".repeat(MAX_EVENT_TEXT_BYTES);
    let event = observation(CloudEventPayload::Text {
        run: run(),
        step: None,
        channel: CloudTextChannel::Assistant,
        text: &text,
    });
    let snapshot = CloudSnapshotPayload {
        control_revision: 8,
        timestamp_ms: 100_000,
        omitted_earlier: false,
        events: vec![event; 33],
    };
    assert!(snapshot.validate().is_err());
    assert!(
        CloudSnapshotPayload::from_canonical_bytes(&vec![0; crate::cloud::MAX_PLAINTEXT_BYTES + 1])
            .is_err()
    );
}

fn signed_record(
    kind: RecordKind,
    context: RecordContext,
    bytes: &[u8],
) -> Result<SignedRecord<'_>, Box<dyn std::error::Error>> {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let header =
        crate::cloud::RecordHeader::new(context, kind, key.verifying_key().to_bytes(), bytes)?;
    let signature = key.sign(&header.canonical_bytes()?).to_bytes();
    Ok(SignedRecord::new(header, bytes, signature)?)
}

#[test]
fn signed_record_purpose_and_original_run_are_checked_before_returning_observations() -> TestResult
{
    let event = observation(CloudEventPayload::Status {
        run: run(),
        status: CloudRunStatus::Running,
    });
    let bytes = event.canonical_bytes()?;
    let record = signed_record(RecordKind::Event, context(Some(run()))?, &bytes)?;
    assert_eq!(CloudEvent::from_record(&record)?, event);
    assert_eq!(
        CloudSnapshotPayload::from_record(&record),
        Err(EventPayloadError::Kind)
    );
    let wrong = signed_record(RecordKind::Event, context(None)?, &bytes)?;
    assert_eq!(
        CloudEvent::from_record(&wrong),
        Err(EventPayloadError::Context)
    );
    let wrong = signed_record(RecordKind::Snapshot, context(Some(run()))?, &bytes)?;
    assert_eq!(
        CloudEvent::from_record(&wrong),
        Err(EventPayloadError::Kind)
    );
    let snapshot = CloudSnapshotPayload {
        control_revision: 8,
        timestamp_ms: 100_001,
        omitted_earlier: true,
        events: vec![event],
    };
    let bytes = snapshot.canonical_bytes()?;
    let record = signed_record(RecordKind::Snapshot, context(None)?, &bytes)?;
    // Its outer current run is absent; historical events retain their own runs.
    assert_eq!(CloudSnapshotPayload::from_record(&record)?, snapshot);
    Ok(())
}

#[test]
fn each_tool_intent_preserves_its_exact_semantic_argument_digest_and_display_name() -> TestResult {
    let vectors = [
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-list.hex"),
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-open.hex"),
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-read.hex"),
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-input.hex"),
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-run.hex"),
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-exec.hex"),
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-read-command.hex"),
        include_str!("../../../../../fixtures/cloud-payload-v1/tool-cancel.hex"),
    ];
    for vector in vectors {
        let bytes = hex::decode(vector.trim())?;
        let arguments = ToolArguments::from_canonical_bytes(&bytes)?;
        let intent = ToolIntentPayload {
            arguments_digest: arguments.digest()?,
            display: ToolPresentation {
                tool: arguments.name(),
                ..display()
            },
            arguments,
            ..intent()?
        };
        let event = observation(CloudEventPayload::ToolIntent(Box::new(intent)));
        let bytes = event.canonical_bytes()?;
        assert_eq!(CloudEvent::from_canonical_bytes(&bytes)?, event);
    }
    Ok(())
}

#[test]
fn optional_text_step_usage_display_and_actual_job_windows_preserve_their_values() -> TestResult {
    let mut events = vec![observation(CloudEventPayload::Text {
        run: run(),
        step: None,
        channel: CloudTextChannel::Assistant,
        text: "",
    })];
    for status in [
        CloudRunStatus::Queued,
        CloudRunStatus::Running,
        CloudRunStatus::WaitingApproval,
        CloudRunStatus::NeedsGrant,
        CloudRunStatus::NeedsUnlock,
        CloudRunStatus::NeedsProviderAccess,
        CloudRunStatus::OutcomeUnknown,
        CloudRunStatus::Interrupted,
        CloudRunStatus::Stopped,
        CloudRunStatus::Completed,
    ] {
        events.push(observation(CloudEventPayload::Status {
            run: run(),
            status,
        }));
    }
    for outcome in [
        None,
        Some(DisplayOutcome::Ok("null")),
        Some(DisplayOutcome::Err("exact error")),
    ] {
        for effect in [
            ObservedEffect::Observed,
            ObservedEffect::Unknown,
            ObservedEffect::Background(Box::new(BackgroundJob {
                intent: [8; 16],
                execution: approval()?.execution,
                terminal: "t",
                command: "c",
                window: Some(JobWindow {
                    created_at_ms: 100,
                    deadline_ms: 200,
                }),
            })),
        ] {
            events.push(observation(CloudEventPayload::ToolResult {
                run: run(),
                observation: Box::new(ToolObservationPayload {
                    intent: [8; 16],
                    output_json: "[]",
                    failed: true,
                    effect,
                    display: ToolPresentation {
                        outcome: outcome.clone(),
                        destination: Some("original"),
                        redacted: true,
                        ..display()
                    },
                }),
            }));
        }
    }
    events.push(observation(CloudEventPayload::Usage {
        run: run(),
        usage: CloudUsage {
            input_tokens: Some(0),
            output_tokens: Some(1),
            total_tokens: Some(2),
            cached_input_tokens: Some(3),
            thought_tokens: Some(4),
            cost_micros: Some(5),
        },
    }));
    for event in events {
        let bytes = event.canonical_bytes()?;
        assert_eq!(CloudEvent::from_canonical_bytes(&bytes)?, event);
    }
    Ok(())
}

mod background;
mod prompt;
