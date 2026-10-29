use super::*;
use crate::cloud::{
    CloudNamespace, CloudRoute, CloudTextId, CommandContext, CommandIssuer, CommandKeys,
    RunCoordinate, RunnerCoordinate,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn reconciliation_known_preserves_exact_digest_without_reinterpreting_legacy_declarations()
-> TestResult {
    for (fixture, expected) in [
        (
            include_str!("../../../../../fixtures/cloud-payload-v1/reconcile.hex"),
            ApprovalChoice::ReconcileSucceeded,
        ),
        (
            include_str!("../../../../../fixtures/cloud-payload-v1/reconcile-failed.hex"),
            ApprovalChoice::ReconcileFailed,
        ),
        (
            include_str!("../../../../../fixtures/cloud-payload-v1/reconcile-known.hex"),
            ApprovalChoice::ReconcileKnown {
                result_digest: [0x13; 32],
            },
        ),
    ] {
        let bytes = hex::decode(fixture.trim())?;
        let payload =
            CloudCommandPayload::from_canonical_bytes(CommandKind::ResolveApproval, &bytes)?;
        let CloudCommandPayload::ResolveApproval(answer) = &payload else {
            return Err("approval".into());
        };
        assert_eq!(answer.choice, expected);
        assert_eq!(payload.canonical_bytes()?, bytes);
    }
    let mut bytes = hex::decode(
        include_str!("../../../../../fixtures/cloud-payload-v1/reconcile-known.hex").trim(),
    )?;
    let mut changed = bytes.clone();
    *changed.last_mut().ok_or("missing digest")? ^= 1;
    let changed =
        CloudCommandPayload::from_canonical_bytes(CommandKind::ResolveApproval, &changed)?;
    assert_ne!(changed.canonical_bytes()?, bytes);
    bytes.pop();
    assert!(
        CloudCommandPayload::from_canonical_bytes(CommandKind::ResolveApproval, &bytes).is_err()
    );
    Ok(())
}
fn fixtures() -> [(CommandKind, &'static str); 14] {
    [
        (
            CommandKind::SubmitPrompt,
            include_str!("../../../../../fixtures/cloud-payload-v1/prompt.hex"),
        ),
        (
            CommandKind::Stop,
            include_str!("../../../../../fixtures/cloud-payload-v1/stop.hex"),
        ),
        (
            CommandKind::ResolveApproval,
            include_str!("../../../../../fixtures/cloud-payload-v1/approval.hex"),
        ),
        (
            CommandKind::ResolveApproval,
            include_str!("../../../../../fixtures/cloud-payload-v1/reconcile.hex"),
        ),
        (
            CommandKind::ResolveApproval,
            include_str!("../../../../../fixtures/cloud-payload-v1/reconcile-failed.hex"),
        ),
        (
            CommandKind::ResolveApproval,
            include_str!("../../../../../fixtures/cloud-payload-v1/reconcile-known.hex"),
        ),
        (
            CommandKind::IssueGrant,
            include_str!("../../../../../fixtures/cloud-payload-v1/inference.hex"),
        ),
        (
            CommandKind::IssueGrant,
            include_str!("../../../../../fixtures/cloud-payload-v1/tools.hex"),
        ),
        (
            CommandKind::IssueGrant,
            include_str!("../../../../../fixtures/cloud-payload-v1/provider.hex"),
        ),
        (
            CommandKind::RevokeGrant,
            include_str!("../../../../../fixtures/cloud-payload-v1/revoke.hex"),
        ),
        (
            CommandKind::AnswerSshConsent,
            include_str!("../../../../../fixtures/cloud-payload-v1/ssh-approve.hex"),
        ),
        (
            CommandKind::AnswerSshConsent,
            include_str!("../../../../../fixtures/cloud-payload-v1/ssh-deny.hex"),
        ),
        (
            CommandKind::DeleteChat,
            include_str!("../../../../../fixtures/cloud-payload-v1/delete.hex"),
        ),
        (
            CommandKind::RevokeIssuerGrants,
            include_str!("../../../../../fixtures/cloud-payload-v1/issuer.hex"),
        ),
    ]
}
fn header(kind: CommandKind, run: Option<RunCoordinate>) -> Result<CommandHeader, CommandError> {
    CommandHeader::new(
        CloudRoute {
            namespace: CloudNamespace {
                hub_instance_id: CloudTextId::new("hub")?,
                account_id: CloudTextId::new("account")?,
            },
            runner: RunnerCoordinate {
                id: [2; 16],
                key_epoch: 3,
            },
            chat_id: [4; 16],
            command_id: [5; 16],
        },
        CommandKeys {
            account: [1; 32],
            runner: [2; 32],
        },
        CommandIssuer {
            device_id: CloudTextId::new("device")?,
            signing_key: [15; 32],
            access_token_digest: [16; 32],
        },
        CommandContext {
            nonce: [17; 16],
            expected_chat_revision: 12,
            run,
            kind,
            issued_at_ms: 100_000,
            accept_before_ms: 160_000,
        },
        b"body",
    )
}

#[test]
fn all_eight_payload_purposes_match_independent_python_bytes_without_normalization() -> TestResult {
    for (kind, fixture) in fixtures() {
        let bytes = hex::decode(fixture.trim())?;
        let decoded = CloudCommandPayload::from_canonical_bytes(kind, &bytes)?;
        assert_eq!(decoded.kind(), kind);
        assert_eq!(decoded.canonical_bytes()?, bytes);
        for length in 0..bytes.len() {
            assert!(
                CloudCommandPayload::from_canonical_bytes(kind, &bytes[..length]).is_err(),
                "{kind:?} prefix{length}"
            );
        }
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(CloudCommandPayload::from_canonical_bytes(kind, &suffix).is_err());
        let wrong = if kind == CommandKind::Stop {
            CommandKind::DeleteChat
        } else {
            CommandKind::Stop
        };
        assert!(CloudCommandPayload::from_canonical_bytes(wrong, &bytes).is_err());
        if let CloudCommandPayload::SubmitPrompt(prompt) = decoded {
            let PromptPart::Text(text) = prompt.content[0] else {
                return Err("text expected".into());
            };
            assert_eq!(text, "public fixture prompt");
            let offset = text.as_ptr() as usize - bytes.as_ptr() as usize;
            assert_eq!(&bytes[offset..offset + text.len()], text.as_bytes());
            assert!(!format!("{prompt:?}").contains("public fixture prompt"));
        }
    }
    Ok(())
}

#[test]
fn grants_and_approvals_require_the_original_header_run_and_subject() -> TestResult {
    let run = RunCoordinate {
        id: [8; 16],
        expected_epoch: 9,
    };
    for (kind, fixture) in fixtures() {
        let bytes = hex::decode(fixture.trim())?;
        let value = CloudCommandPayload::from_canonical_bytes(kind, &bytes)?;
        value.require_header(&header(kind, Some(run))?)?;
        let needs_run = matches!(
            kind,
            CommandKind::Stop
                | CommandKind::ResolveApproval
                | CommandKind::RevokeGrant
                | CommandKind::AnswerSshConsent
        ) || matches!(&value,CloudCommandPayload::IssueGrant(grant) if !matches!(grant.as_ref(),GrantPayload::Provider {..}));
        assert_eq!(
            value.require_header(&header(kind, None)?).is_err(),
            needs_run
        );
        if matches!(
            kind,
            CommandKind::ResolveApproval | CommandKind::AnswerSshConsent
        ) {
            assert!(
                value
                    .require_header(&header(
                        kind,
                        Some(RunCoordinate {
                            id: [8; 16],
                            expected_epoch: 10
                        })
                    )?)
                    .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn payload_collections_and_epochs_are_checked_before_encoding_or_effect_admission() -> TestResult {
    let bytes =
        hex::decode(include_str!("../../../../../fixtures/cloud-payload-v1/prompt.hex").trim())?;
    let CloudCommandPayload::SubmitPrompt(mut prompt) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::SubmitPrompt, &bytes)?
    else {
        return Err("prompt expected".into());
    };
    prompt.content = vec![PromptPart::Text("part"); 129];
    assert!(
        CloudCommandPayload::SubmitPrompt(prompt.clone())
            .validate()
            .is_err()
    );
    prompt.content = vec![PromptPart::Text("part")];
    prompt.inference.calls = 0;
    assert!(
        CloudCommandPayload::SubmitPrompt(prompt.clone())
            .validate()
            .is_err()
    );
    prompt.inference.calls = 1;
    prompt.target = None;
    assert!(
        CloudCommandPayload::SubmitPrompt(prompt)
            .validate()
            .is_err()
    );
    let bytes =
        hex::decode(include_str!("../../../../../fixtures/cloud-payload-v1/tools.hex").trim())?;
    let CloudCommandPayload::IssueGrant(mut grant) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::IssueGrant, &bytes)?
    else {
        return Err("grant expected".into());
    };
    let GrantPayload::Tools { capabilities, .. } = grant.as_mut() else {
        return Err("tools expected".into());
    };
    *capabilities = 0x80;
    assert!(CloudCommandPayload::IssueGrant(grant).validate().is_err());
    let bytes = hex::decode(
        include_str!("../../../../../fixtures/cloud-payload-v1/ssh-approve.hex").trim(),
    )?;
    let CloudCommandPayload::AnswerSshConsent(mut answer) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::AnswerSshConsent, &bytes)?
    else {
        return Err("SSH expected".into());
    };
    answer.binding.expires_ms = answer.binding.issued_ms + 60_001;
    assert!(
        CloudCommandPayload::AnswerSshConsent(answer)
            .validate()
            .is_err()
    );
    Ok(())
}

#[test]
fn nested_prompt_parts_share_one_aggregate_plaintext_allowance() -> TestResult {
    let bytes =
        hex::decode(include_str!("../../../../../fixtures/cloud-payload-v1/prompt.hex").trim())?;
    let CloudCommandPayload::SubmitPrompt(mut prompt) =
        CloudCommandPayload::from_canonical_bytes(CommandKind::SubmitPrompt, &bytes)?
    else {
        return Err("prompt expected".into());
    };
    let half = "x".repeat(crate::cloud::MAX_PLAINTEXT_BYTES / 2);
    prompt.content = vec![PromptPart::Text(&half), PromptPart::Text(&half)];
    assert!(
        CloudCommandPayload::SubmitPrompt(prompt)
            .validate()
            .is_err()
    );
    Ok(())
}

mod session;
