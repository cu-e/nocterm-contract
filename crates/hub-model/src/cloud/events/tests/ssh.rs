//! The runner's SSH certificate requests and access states are chat-scoped events (ADR 0009).
use super::*;
use crate::cloud::{
    payload::GrantReference,
    ssh::{
        BindingWindow, SignedSshBinding, SshAccess, SshAccessUpdate, SshBinding,
        SshCertificateRequest, SshServerId, SshServerReach, SshServerStatus, SshTarget,
    },
};
use ed25519_dalek::{Signer, SigningKey};

fn request(chat: ChatCoordinate) -> Result<SshCertificateRequest, Box<dyn std::error::Error>> {
    let ca = SigningKey::from_bytes(&[0x91; 32]);
    let server = SshServerId::of_profile("profile-db");
    let binding = SshBinding {
        chat,
        grant: GrantReference {
            id: [0x33; 16],
            epoch: 7,
        },
        window: BindingWindow {
            issued_at_ms: 90_000,
            expires_at_ms: 90_000 + 86_400_000,
        },
        ca_key: ca.verifying_key().to_bytes(),
        targets: vec![SshTarget {
            server,
            host: CloudTextId::new("db.example.org")?,
            port: 22,
            user: CloudTextId::new("deploy")?,
            host_key_sha256: [0xa1; 32],
        }],
    };
    let signature = ca.sign(&binding.signing_bytes()?).to_bytes();
    Ok(SshCertificateRequest {
        request: [0x44; 16],
        binding: SignedSshBinding::new(binding, signature)?,
        subject_key: [0x55; 32],
        source_addresses: vec!["203.0.113.7/32".into()],
        servers: vec![server],
        not_after_ms: 90_000 + 8 * 3_600_000,
    })
}
fn update() -> SshAccessUpdate {
    SshAccessUpdate {
        grant: GrantReference {
            id: [0x33; 16],
            epoch: 7,
        },
        access: SshAccess::Pending,
        servers: vec![SshServerStatus {
            server: SshServerId::of_profile("profile-db"),
            reach: SshServerReach::Admitted,
        }],
    }
}

#[test]
fn ssh_events_round_trip_in_their_chat_without_a_run() -> TestResult {
    let chat = context(None)?.chat().clone();
    let events = [
        observation(CloudEventPayload::SshCertificateRequested(Box::new(
            request(chat)?,
        ))),
        observation(CloudEventPayload::SshAccessState(Box::new(update()))),
    ];
    for event in &events {
        let bytes = event.canonical_bytes()?;
        assert_eq!(&CloudEvent::from_canonical_bytes(&bytes)?, event);
        assert_eq!(event.canonical_len()?, bytes.len());
        event.require_context(&context(None)?)?;
        assert_eq!(
            event.require_context(&context(Some(run()))?),
            Err(EventPayloadError::Context),
            "an SSH event never names a run"
        );
    }
    Ok(())
}

#[test]
fn a_request_whose_binding_names_another_chat_is_out_of_context() -> TestResult {
    let mut other = context(None)?.chat().clone();
    other = ChatCoordinate::new(
        other.namespace().clone(),
        other.runner(),
        [0x77; 16],
        other.key_epoch(),
    )?;
    let event = observation(CloudEventPayload::SshCertificateRequested(Box::new(
        request(other)?,
    )));
    assert_eq!(
        event.require_context(&context(None)?),
        Err(EventPayloadError::Context)
    );
    Ok(())
}
