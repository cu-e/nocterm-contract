#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use nocterm_cloud_device::{CloudDeviceError, transcript::Transcript};
use nocterm_hub_model::{
    DeviceId,
    cloud::{
        ChatCoordinate, CloudNamespace, CloudTextId, RunnerCoordinate,
        events::{CloudEvent, CloudEventPayload},
        payload::GrantReference,
        ssh::{
            BindingWindow, SshAccessUpdate, SshBinding, SshCertificateRequest, SshServerStatus,
            SshTarget,
        },
    },
};
use nocterm_keys::{
    CollectionKey,
    agents::{
        SshTrustRecord,
        ssh_ca::{CA_OBJECT, CaDocument, UserCa},
    },
};

const KIND: &str = nocterm_cloud_device::records::SSH_TRUST_KIND;

fn opened() -> (WebCollectionKey, CollectionKey) {
    let key = CollectionKey::generate().unwrap();
    let opened = WebCollectionKey {
        collection_id: "trust".to_owned(),
        key: key.clone(),
    };
    (opened, key)
}

#[test]
fn trusted_servers_open_with_their_line_and_the_ca_only_as_its_fingerprint() {
    let (opened, key) = opened();
    let ca = UserCa::from_seed([0x91; 32]);
    let fingerprint = ca.fingerprint();
    let document = CaDocument::new(ca, 5).encode().unwrap();
    let sealed_ca = key
        .seal_object("trust", CA_OBJECT, KIND, &document)
        .unwrap();
    let shown = opened.ssh_trust(CA_OBJECT, &sealed_ca).unwrap();
    assert_eq!(
        shown,
        WireSshTrust::Ca {
            fingerprint: fingerprint.clone(),
            created_at_ms: 5.0,
            retired: 0,
        }
    );
    let json = serde_json::to_string(&shown).unwrap();
    assert!(!json.contains("kZGR") && !json.contains("seed"), "{json}");

    let mut record = SshTrustRecord::installed(
        "profile-db".into(),
        "db.example.org".into(),
        "deploy".into(),
        "SHA256:host".into(),
        fingerprint,
        10,
        DeviceId::new(),
    )
    .unwrap();
    record.set_line(CaLineForm::PerServer, 20);
    let object = SshServerId::of_profile("profile-db").object_id();
    let sealed = key
        .seal_object("trust", &object, KIND, &record.encode().unwrap())
        .unwrap();
    let WireSshTrust::Server {
        server_id,
        host,
        state,
        line,
        ..
    } = opened.ssh_trust(&object, &sealed).unwrap()
    else {
        panic!("a server");
    };
    assert_eq!(object, format!("srv-{server_id}"));
    assert_eq!(
        (host.as_str(), state.as_str(), line.as_str()),
        ("db.example.org", "trusted", "perServer")
    );
    // A record moved to another object, or sealed for another object, is refused.
    let other = SshServerId::of_profile("profile-other").object_id();
    let moved = key
        .seal_object("trust", &other, KIND, &record.encode().unwrap())
        .unwrap();
    assert!(matches!(
        opened.ssh_trust(&other, &moved),
        Err(WebCloudError::Device(CloudDeviceError::Binding))
    ));
    assert!(opened.ssh_trust(&other, &sealed).is_err());
}

#[test]
fn a_chats_bindings_and_requests_cross_as_values() {
    let ca = UserCa::from_seed([0x91; 32]);
    let server = SshServerId::of_profile("profile-db");
    let grant = GrantReference {
        id: [0x33; 16],
        epoch: 7,
    };
    let binding = ca
        .sign_binding(SshBinding {
            chat: ChatCoordinate::new(
                CloudNamespace {
                    hub_instance_id: CloudTextId::new("hub").unwrap(),
                    account_id: CloudTextId::new("acc").unwrap(),
                },
                RunnerCoordinate {
                    id: [2; 16],
                    key_epoch: 3,
                },
                [5; 16],
                1,
            )
            .unwrap(),
            grant,
            window: BindingWindow {
                issued_at_ms: 1_000,
                expires_at_ms: 90_000_000,
            },
            ca_key: ca.public_key(),
            targets: vec![SshTarget {
                server,
                host: CloudTextId::new("db.example.org").unwrap(),
                port: 2222,
                user: CloudTextId::new("deploy").unwrap(),
                host_key_sha256: [0xa1; 32],
            }],
        })
        .unwrap();
    let event = |payload| CloudEvent {
        control_revision: 1,
        timestamp_ms: 2_000,
        payload,
    };
    let mut transcript = Transcript::new();
    transcript.apply(&event(CloudEventPayload::SshCertificateRequested(
        Box::new(SshCertificateRequest {
            request: [0x44; 16],
            binding,
            subject_key: [0x55; 32],
            source_addresses: vec!["203.0.113.7".into()],
            servers: vec![server],
            not_after_ms: 3_000_000,
        }),
    )));
    transcript.apply(&event(CloudEventPayload::SshAccessState(Box::new(
        SshAccessUpdate {
            grant,
            access: SshAccess::Pending,
            servers: vec![SshServerStatus {
                server,
                reach: SshServerReach::Unreachable,
            }],
        },
    ))));
    let wire = WireSsh::from(transcript.ssh());
    let bound = &wire.bindings[0];
    assert_eq!(bound.grant, "33".repeat(16));
    assert_eq!(bound.access.as_deref(), Some("pending"));
    assert_eq!(bound.expires_at_ms, Some(90_000_000.0));
    assert_eq!(bound.servers[0].port, 2222);
    assert_eq!(bound.servers[0].reach.as_deref(), Some("unreachable"));
    assert_eq!(wire.requests[0].request_id, "44".repeat(16));
    assert_eq!(
        wire.requests[0].servers,
        vec![hex::encode(server.as_bytes())]
    );
}

#[test]
fn every_ssh_refusal_has_its_own_stable_code() {
    use SshRefusal as R;
    let all = [
        R::NoCa,
        R::OtherCa,
        R::UntrustedServer,
        R::HostKeyUnknown,
        R::Servers,
        R::Window,
        R::UnknownRequest,
        R::Superseded,
        R::Revoked,
        R::OutsideBinding,
        R::SubjectKeyChanged,
        R::NoTrustedServer,
        R::NotBound,
    ];
    let codes: Vec<&str> = all
        .iter()
        .map(|r| super::super::device_code(&CloudDeviceError::Ssh(*r)))
        .collect();
    assert!(codes.iter().all(|code| code.starts_with("ssh_")));
    let mut unique = codes.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), codes.len());
}
