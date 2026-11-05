#![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
use super::*;
use crate::cloud::ssh::SshServerId;
use crate::cloud::{
    CloudNamespace, RunnerCoordinate,
    relay::{PublicationMetadata, RelayBinding, RelayFormatError, RelayKind},
};
use ed25519_dalek::{Signer, SigningKey};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-summary-v1")
        .join(format!("{name}.hex"));
    hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
}
fn id(text: &str) -> CloudTextId {
    CloudTextId::new(text).unwrap()
}
pub(crate) fn context(revision: u64) -> SummaryContext {
    let chat = ChatCoordinate::new(
        CloudNamespace {
            hub_instance_id: id("hub"),
            account_id: id("acc-1"),
        },
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        [0x81; 16],
        4,
    )
    .unwrap();
    SummaryContext::new(chat, revision).unwrap()
}
fn full() -> ChatSummary {
    ChatSummary {
        head: Some(SummaryHead {
            sequence: 5,
            ciphertext_digest: [0x84; 32],
        }),
        control_revision: 11,
        created_at_ms: 100_000,
        last_activity_ms: 100_500,
        title: "Deploy the cache — fix ünïcode".to_owned(),
        host: SummaryHost::Managed {
            agent_id: id("agent-1"),
        },
        model: Some(SummaryModel {
            provider: id("managed"),
            model: id("claude-x"),
        }),
        state: ChatState::WaitingApproval,
        pending_approvals: 2,
        servers: vec![
            BoundServer {
                server: SshServerId::of_profile("profile-db"),
                host: id("db.example.org"),
                port: 22,
                user: id("deploy"),
                state: ServerState::Active,
                valid_before_ms: Some(200_000),
            },
            BoundServer {
                server: SshServerId::of_profile("profile-cache"),
                host: id("10.0.0.5"),
                port: 2222,
                user: id("root"),
                state: ServerState::AwaitingDevice,
                valid_before_ms: None,
            },
        ],
        features: SUMMARY_FEATURE_SSH_BINDING | SUMMARY_FEATURE_PROVIDER_LEASE,
    }
}
fn minimal() -> ChatSummary {
    ChatSummary {
        head: None,
        control_revision: 0,
        created_at_ms: 100_000,
        last_activity_ms: 100_000,
        title: String::new(),
        host: SummaryHost::Own,
        model: None,
        state: ChatState::Idle,
        pending_approvals: 0,
        servers: Vec::new(),
        features: 0,
    }
}
fn signer() -> SigningKey {
    SigningKey::from_bytes(&[0x51; 32])
}
fn signed(context: SummaryContext, summary: ChatSummary) -> SignedChatSummary {
    let signature = signer().sign(&summary.signing_bytes(&context).unwrap());
    SignedChatSummary::new(
        context,
        summary,
        signature.to_bytes(),
        &signer().verifying_key().to_bytes(),
    )
    .unwrap()
}

#[test]
fn independent_vectors_have_exact_canonical_bytes_and_runner_signatures() -> TestResult {
    let runner = signer().verifying_key().to_bytes();
    assert_eq!(context(7).canonical_bytes()?, fixture("context"));
    assert_eq!(
        context(7).publication_id()?.to_vec(),
        fixture("publication-id")
    );
    for (name, summary) in [("full", full()), ("minimal", minimal())] {
        let bytes = fixture(&format!("summary-{name}"));
        assert_eq!(summary.signing_bytes(&context(7))?, bytes);
        assert_eq!(
            ChatSummary::from_signing_bytes(&bytes)?,
            (context(7), summary.clone())
        );
        let framed = fixture(&format!("signed-{name}"));
        let verified = SignedChatSummary::from_canonical_bytes(&framed, &runner)?;
        assert_eq!(verified.summary(), &summary);
        assert_eq!(verified.canonical_bytes()?, framed);
    }
    let binding = RelayBinding::summary(context(7));
    assert_eq!(binding.canonical_bytes()?, fixture("binding"));
    assert_eq!(
        RelayBinding::from_canonical_bytes(&fixture("binding"))?,
        binding
    );
    Ok(())
}

#[test]
fn a_signature_verifies_only_under_its_runner_and_over_unchanged_bytes() -> TestResult {
    let framed = signed(context(7), full()).canonical_bytes()?;
    let other = SigningKey::from_bytes(&[0x52; 32])
        .verifying_key()
        .to_bytes();
    assert!(matches!(
        SignedChatSummary::from_canonical_bytes(&framed, &other),
        Err(SummaryError::Signature(_))
    ));
    let runner = signer().verifying_key().to_bytes();
    // Change the control revision, a byte inside the signed body.
    let mut tampered = framed.clone();
    let at = framed.len() - 64 - 200;
    tampered[at] ^= 1;
    assert!(SignedChatSummary::from_canonical_bytes(&tampered, &runner).is_err());
    let mut trailing = framed;
    trailing.push(0);
    assert!(SignedChatSummary::from_canonical_bytes(&trailing, &runner).is_err());
    Ok(())
}

#[test]
fn decoding_refuses_unknown_tags_flags_and_suffixes() -> TestResult {
    let bytes = minimal().signing_bytes(&context(7))?;
    // The state tag sits before pending approvals (u16), server count (u8) and features (u32).
    let state = bytes.len() - 8;
    for tag in [0, 9, 0xff] {
        let mut wrong = bytes.clone();
        wrong[state] = tag;
        assert!(matches!(
            ChatSummary::from_signing_bytes(&wrong),
            Err(SummaryError::Value)
        ));
    }
    let mut flag = bytes.clone();
    let head_flag = bytes.len() - 4 - 1 - 2 - 1 - 1 - 1 - 4 - 8 - 8 - 8 - 1;
    flag[head_flag] = 2;
    assert!(ChatSummary::from_signing_bytes(&flag).is_err());
    let mut suffix = bytes.clone();
    suffix.push(0);
    assert!(ChatSummary::from_signing_bytes(&suffix).is_err());
    assert!(ChatSummary::from_signing_bytes(&bytes[..bytes.len() - 1]).is_err());
    Ok(())
}

#[test]
fn values_outside_the_bounds_are_refused() {
    let cases: [fn(&mut ChatSummary); 7] = [
        |s| s.title = "x".repeat(MAX_TITLE_BYTES + 1),
        |s| s.title = "two\nlines".to_owned(),
        |s| s.last_activity_ms = s.created_at_ms - 1,
        |s| s.created_at_ms = 0,
        |s| {
            s.head = Some(SummaryHead {
                sequence: 0,
                ciphertext_digest: [0; 32],
            });
        },
        |s| s.servers[0].port = 0,
        |s| {
            s.servers = (0..=MAX_BOUND_SERVERS)
                .map(|n| BoundServer {
                    server: SshServerId::from_bytes([u8::try_from(n).unwrap(); 16]),
                    ..s.servers[0].clone()
                })
                .collect();
        },
    ];
    for change in cases {
        let mut summary = full();
        change(&mut summary);
        assert!(matches!(
            summary.signing_bytes(&context(7)),
            Err(SummaryError::Value)
        ));
    }
    let mut twice = full();
    twice.servers[1].server = twice.servers[0].server;
    assert!(matches!(
        twice.signing_bytes(&context(7)),
        Err(SummaryError::Value)
    ));
    assert!(matches!(
        SummaryContext::new(context(7).chat().clone(), 0),
        Err(SummaryError::Value)
    ));
}

#[test]
fn a_title_is_the_first_line_cut_at_a_character_boundary() {
    assert_eq!(
        title_from_prompt("\n  Fix the build \nthen test"),
        "Fix the build"
    );
    assert_eq!(title_from_prompt("tab\there"), "tab here");
    assert_eq!(title_from_prompt(""), "");
    let long = "é".repeat(100);
    let title = title_from_prompt(&long);
    assert_eq!(title.len(), MAX_TITLE_BYTES);
    assert!(title.chars().all(|c| c == 'é'));
    let mut summary = minimal();
    summary.title = title_from_prompt(&format!("a{long}"));
    assert_eq!(summary.title.len(), MAX_TITLE_BYTES - 1);
    assert!(summary.validate().is_ok());
}

#[test]
fn a_summary_routes_to_its_runner_directory_with_a_stable_publication_id() -> TestResult {
    let binding = RelayBinding::summary(context(7));
    assert_eq!(binding.kind(), RelayKind::Summary);
    assert_eq!(binding.object_id(), [0x81; 16]);
    assert_eq!(binding.runner().id, [2; 16]);
    assert_eq!(binding.summary_context(), Some(&context(7)));
    assert!(binding.record_context().is_none() && binding.command_route().is_none());
    assert_eq!(context(7).publication_id()?, context(7).publication_id()?);
    assert_ne!(context(7).publication_id()?, context(8).publication_id()?);
    let size = u32::try_from(MAX_SEALED_SUMMARY_BYTES)?;
    assert!(PublicationMetadata::new([1; 16], binding.clone(), size, [0; 32]).is_ok());
    assert!(matches!(
        PublicationMetadata::new([1; 16], binding, size + 1, [0; 32]),
        Err(RelayFormatError::Capacity)
    ));
    Ok(())
}

#[test]
fn sixteen_servers_with_the_longest_names_fit_beside_the_longest_texts() -> TestResult {
    let long = |c: char| id(&c.to_string().repeat(crate::cloud::MAX_ID_BYTES));
    let chat = ChatCoordinate::new(
        CloudNamespace {
            hub_instance_id: long('h'),
            account_id: long('a'),
        },
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: u64::MAX,
        },
        [0x81; 16],
        u64::MAX,
    )?;
    let mut summary = full();
    summary.title = "t".repeat(MAX_TITLE_BYTES);
    summary.host = SummaryHost::Managed {
        agent_id: long('g'),
    };
    summary.model = Some(SummaryModel {
        provider: long('p'),
        model: long('m'),
    });
    summary.servers = (0..MAX_BOUND_SERVERS)
        .map(|n| BoundServer {
            server: SshServerId::from_bytes([u8::try_from(n).unwrap(); 16]),
            host: long('s'),
            port: u16::MAX,
            user: long('u'),
            state: ServerState::Active,
            valid_before_ms: Some(i64::MAX),
        })
        .collect();
    let context = SummaryContext::new(chat, u64::MAX)?;
    let bytes = summary.signing_bytes(&context)?;
    assert!(bytes.len() <= MAX_SUMMARY_BYTES, "{}", bytes.len());
    assert_eq!(ChatSummary::from_signing_bytes(&bytes)?.1, summary);
    Ok(())
}
