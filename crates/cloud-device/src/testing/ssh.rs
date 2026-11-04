//! The account's SSH CA, its trusted servers and the runner's SSH events, for the SSH tests.
use super::{NOW, World, hub::FakeHub};
use crate::records::SSH_TRUST_KIND;
use nocterm_hub_model::cloud::{
    events::{CloudEvent, CloudEventPayload},
    payload::GrantReference,
    ssh::{
        BindingWindow, DEFAULT_BINDING_WINDOW_MS, DEFAULT_CERTIFICATE_VALIDITY_MS,
        SignedSshBinding, SshAccess, SshAccessUpdate, SshBinding, SshCertificateRequest,
        SshServerId, SshTarget,
    },
};
use nocterm_hub_model::{DeviceId, cloud::CloudTextId};
use nocterm_keys::agents::{
    CaLineForm, SshTrustRecord,
    ssh_ca::{CA_OBJECT, CaDocument, UserCa, fingerprint_of},
};

pub(crate) const TRUST: &str = "ssh-trust";
pub(crate) const CA_SEED: [u8; 32] = [0x91; 32];
pub(crate) const SUBJECT: [u8; 32] = [0x55; 32];
pub(crate) const HOST_KEY: [u8; 32] = [0xa1; 32];
pub(crate) const GRANT: GrantReference = GrantReference {
    id: [0x33; 16],
    epoch: 7,
};

pub(crate) fn ca() -> UserCa {
    UserCa::from_seed(CA_SEED)
}
pub(crate) fn server(profile: &str) -> SshServerId {
    SshServerId::of_profile(profile)
}
/// `SHA256:<base64>` of a host key whose blob digest is `digest`.
fn fingerprint(digest: [u8; 32]) -> String {
    use base64::Engine as _;
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}
/// A trust record of `profile` (host `<profile>.example.org`, user `deploy`) under `ca`.
pub(crate) fn record(profile: &str, ca: &UserCa, line: CaLineForm) -> SshTrustRecord {
    let mut record = SshTrustRecord::installed(
        profile.to_owned(),
        format!("{profile}.example.org"),
        "deploy".to_owned(),
        fingerprint(HOST_KEY),
        fingerprint_of(&ca.public_key()),
        NOW - 1_000,
        DeviceId::new(),
    )
    .unwrap();
    record.set_line(line, NOW - 1_000);
    record
}
/// Seeds the account's `agent_ssh_trust` collection with `ca` and `records`.
pub(crate) fn trust_store(hub: &mut FakeHub, ca: UserCa, records: &[SshTrustRecord]) {
    let key = hub.collection(TRUST, SSH_TRUST_KIND);
    let document = CaDocument::new(ca, NOW - 10_000).encode().unwrap();
    let sealed = key
        .seal_object(TRUST, CA_OBJECT, SSH_TRUST_KIND, &document)
        .unwrap();
    hub.object(TRUST, CA_OBJECT, SSH_TRUST_KIND, sealed);
    for record in records {
        let object = server(&record.profile_id).object_id();
        let sealed = key
            .seal_object(TRUST, &object, SSH_TRUST_KIND, &record.encode().unwrap())
            .unwrap();
        hub.object(TRUST, &object, SSH_TRUST_KIND, sealed);
    }
}
/// A binding of the world's chat to `profiles` (port 22), signed by `ca`.
pub(crate) fn binding(
    world: &World,
    ca: &UserCa,
    grant: GrantReference,
    profiles: &[&str],
) -> SignedSshBinding {
    let targets = profiles
        .iter()
        .map(|profile| SshTarget {
            server: server(profile),
            host: CloudTextId::new(format!("{profile}.example.org")).unwrap(),
            port: 22,
            user: CloudTextId::new("deploy").unwrap(),
            host_key_sha256: HOST_KEY,
        })
        .collect();
    ca.sign_binding(SshBinding {
        chat: world.selector.coordinate().unwrap(),
        grant,
        window: BindingWindow {
            issued_at_ms: NOW - 1_000,
            expires_at_ms: NOW - 1_000 + DEFAULT_BINDING_WINDOW_MS,
        },
        ca_key: ca.public_key(),
        targets,
    })
    .unwrap()
}
/// The runner's request `id` for `profiles` under `binding`, for eight hours from now.
pub(crate) fn request(
    binding: SignedSshBinding,
    id: u8,
    subject: [u8; 32],
    profiles: &[&str],
) -> SshCertificateRequest {
    SshCertificateRequest {
        request: [id; 16],
        binding,
        subject_key: subject,
        source_addresses: vec!["203.0.113.7/32".into()],
        servers: profiles.iter().map(|profile| server(profile)).collect(),
        not_after_ms: NOW + DEFAULT_CERTIFICATE_VALIDITY_MS,
    }
}
pub(crate) fn requested(revision: u64, request: SshCertificateRequest) -> CloudEvent<'static> {
    CloudEvent {
        control_revision: revision,
        timestamp_ms: u64::try_from(NOW).unwrap() - 500,
        payload: CloudEventPayload::SshCertificateRequested(Box::new(request)),
    }
}
pub(crate) fn reported(
    revision: u64,
    grant: GrantReference,
    access: SshAccess,
) -> CloudEvent<'static> {
    CloudEvent {
        control_revision: revision,
        timestamp_ms: u64::try_from(NOW).unwrap() - 400,
        payload: CloudEventPayload::SshAccessState(Box::new(SshAccessUpdate {
            grant,
            access,
            servers: Vec::new(),
        })),
    }
}
