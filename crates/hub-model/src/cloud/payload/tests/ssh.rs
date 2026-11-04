//! SSH binding grants, certificates and their revocation are chat-scoped grants (ADR 0009).
use super::*;
use crate::cloud::{
    ChatCoordinate,
    ssh::{BindingWindow, SignedSshBinding, SshBinding, SshFormatError, SshServerId, SshTarget},
};
use ed25519_dalek::{Signer, SigningKey};

/// A binding signed by CA `0x91…` for the chat `header` routes to (or chat `chat_id`).
fn binding(chat_id: [u8; 16]) -> Result<SignedSshBinding, Box<dyn std::error::Error>> {
    let ca = SigningKey::from_bytes(&[0x91; 32]);
    let binding = SshBinding {
        chat: ChatCoordinate::new(
            CloudNamespace {
                hub_instance_id: CloudTextId::new("hub")?,
                account_id: CloudTextId::new("account")?,
            },
            RunnerCoordinate {
                id: [2; 16],
                key_epoch: 3,
            },
            chat_id,
            1,
        )?,
        grant: GrantReference {
            id: [0x33; 16],
            epoch: 7,
        },
        window: BindingWindow {
            issued_at_ms: 100_000,
            expires_at_ms: 100_000 + 86_400_000,
        },
        ca_key: ca.verifying_key().to_bytes(),
        targets: vec![SshTarget {
            server: SshServerId::of_profile("profile-db"),
            host: CloudTextId::new("db.example.org")?,
            port: 22,
            user: CloudTextId::new("deploy")?,
            host_key_sha256: [0xa1; 32],
        }],
    };
    let signature = ca.sign(&binding.signing_bytes()?).to_bytes();
    Ok(SignedSshBinding::new(binding, signature)?)
}
fn round_trip(value: &CloudCommandPayload<'_>) -> TestResult {
    let bytes = value.canonical_bytes()?;
    assert_eq!(
        &CloudCommandPayload::from_canonical_bytes(value.kind(), &bytes)?,
        value
    );
    Ok(())
}
const RUN: RunCoordinate = RunCoordinate {
    id: [8; 16],
    expected_epoch: 9,
};

#[test]
fn a_binding_grant_round_trips_and_names_only_its_own_chat_without_a_run() -> TestResult {
    let value = CloudCommandPayload::IssueGrant(Box::new(GrantPayload::SshBinding {
        binding: binding([4; 16])?,
    }));
    round_trip(&value)?;
    value.require_header(&header(CommandKind::IssueGrant, None)?)?;
    assert_eq!(
        value.require_header(&header(CommandKind::IssueGrant, Some(RUN))?),
        Err(PayloadError::Value)
    );
    let other = CloudCommandPayload::IssueGrant(Box::new(GrantPayload::SshBinding {
        binding: binding([9; 16])?,
    }));
    assert_eq!(
        other.require_header(&header(CommandKind::IssueGrant, None)?),
        Err(PayloadError::Value),
        "a binding moved to another chat"
    );
    assert!(!format!("{value:?}").contains("db.example.org"));
    Ok(())
}

#[test]
fn a_binding_with_a_broken_ca_signature_is_refused_on_decode() -> TestResult {
    let value = CloudCommandPayload::IssueGrant(Box::new(GrantPayload::SshBinding {
        binding: binding([4; 16])?,
    }));
    let mut bytes = value.canonical_bytes()?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        CloudCommandPayload::from_canonical_bytes(CommandKind::IssueGrant, &bytes),
        Err(PayloadError::Ssh(SshFormatError::Signature(_)))
    ));
    Ok(())
}

#[test]
fn a_certificate_answer_is_bounded_and_chat_scoped() -> TestResult {
    let certificate = vec![7u8; 300];
    let answer = |certificate| {
        CloudCommandPayload::IssueGrant(Box::new(GrantPayload::SshCertificate {
            grant: GrantReference {
                id: [0x33; 16],
                epoch: 7,
            },
            request: [0x44; 16],
            certificate,
        }))
    };
    round_trip(&answer(&certificate))?;
    answer(&certificate).require_header(&header(CommandKind::IssueGrant, None)?)?;
    assert_eq!(
        answer(&certificate).require_header(&header(CommandKind::IssueGrant, Some(RUN))?),
        Err(PayloadError::Value)
    );
    let large = vec![7u8; crate::cloud::ssh::MAX_CERTIFICATE_BYTES + 1];
    for bad in [&[][..], &large[..]] {
        assert_eq!(answer(bad).canonical_bytes(), Err(PayloadError::Bounds));
    }
    Ok(())
}

#[test]
fn revoking_a_binding_names_no_run_unlike_the_other_grant_classes() -> TestResult {
    let grant = GrantReference {
        id: [0x33; 16],
        epoch: 7,
    };
    let binding = CloudCommandPayload::RevokeGrant(ScopedGrantReference {
        class: GrantClass::SshBinding,
        grant,
    });
    round_trip(&binding)?;
    binding.require_header(&header(CommandKind::RevokeGrant, None)?)?;
    assert!(
        binding
            .require_header(&header(CommandKind::RevokeGrant, Some(RUN))?)
            .is_err()
    );
    let tools = CloudCommandPayload::RevokeGrant(ScopedGrantReference {
        class: GrantClass::Tools,
        grant,
    });
    assert!(
        tools
            .require_header(&header(CommandKind::RevokeGrant, None)?)
            .is_err()
    );
    Ok(())
}
