//! The account's agent SSH CA and trusted servers in the recorded session, and the chat's SSH
//! binding (contract ADR 0009): the device binds the chat to two trusted servers, the runner
//! accepts the command, reports its access pending and asks for a certificate, a reopened chat
//! answers the request, and the runner accepts that command and reports the access active.
use nocterm_cloud_device::records::{ChatSelector, SSH_TRUST_KIND};
use nocterm_hub_model::{
    DeviceId,
    cloud::{
        CloudTextId,
        events::{AcceptedCommand, CloudEvent, CloudEventPayload},
        head::HeadRecordAnchor,
        payload::{CloudCommandPayload, GrantPayload},
        relay::RelayBinding,
        ssh::{
            DEFAULT_CERTIFICATE_VALIDITY_MS, SignedSshBinding, SshAccess, SshAccessUpdate,
            SshCertificateRequest, SshServerId, SshServerReach, SshServerStatus,
        },
        summary::{BoundServer, ServerState},
    },
};
use nocterm_keys::{
    DeviceKey, PublicKey,
    agents::{
        CaLineForm, SshTrustRecord,
        ssh_ca::{CA_OBJECT, CaDocument, CertificateFacts, UserCa, principal_for},
    },
    cloud::{ChatKey, RunnerEncryptionKey, open_command},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    CloudDevice, NOW, NOW_MS, RUNNER_ENCRYPTION_SEED, Recorder, WebChat, chat, directory, drive,
};
use crate::{
    WebAccount,
    cloud::types::{BindOptions, FlowOutput, FlowStep, SshServerInput, WireEffect},
};

/// The account's `agent_ssh_trust` collection.
const TRUST_COLLECTION: &str = "col-ssh";
/// The account's current CA, and the one an earlier server was trusted under.
const CA_SEED: [u8; 32] = [0x5a; 32];
const EARLIER_CA_SEED: [u8; 32] = [0x01; 32];
/// The runner's per-chat SSH key.
const SUBJECT_SEED: [u8; 32] = [0x56; 32];
/// The runner's certificate request and the egress it states.
const REQUEST: [u8; 16] = [0x91; 16];
const SOURCE_ADDRESS: &str = "203.0.113.7/32";

/// A server whose `authorized_keys` trusts a CA of the account, reached through a saved profile.
struct Server {
    profile: &'static str,
    host: &'static str,
    user: &'static str,
    port: u16,
    host_key: &'static str,
    line: CaLineForm,
    ca_seed: [u8; 32],
}
impl Server {
    fn id(&self) -> SshServerId {
        SshServerId::of_profile(self.profile)
    }
    fn hex(&self) -> String {
        hex::encode(self.id().as_bytes())
    }
}

/// `db-1` on the per-server line, `bastion` still on the shared line (it needs a CA update),
/// and a server trusted under an earlier CA. The chat is bound to the first two.
const SERVERS: [Server; 3] = [
    Server {
        profile: "5b0c7f2e-3a41-4d8e-9c6b-0f1e2d3c4b5a",
        host: "10.0.0.5",
        user: "deploy",
        port: 2222,
        host_key: "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M",
        line: CaLineForm::PerServer,
        ca_seed: CA_SEED,
    },
    Server {
        profile: "9d8c7b6a-5f4e-4d3c-8b2a-1a0b9c8d7e6f",
        host: "bastion.acme.io",
        user: "ops",
        port: 22,
        host_key: "SHA256:DZyZLHYkg98LXeBMrWPb1yMuLZRau2MJhzjRAZwPAHU",
        line: CaLineForm::Shared,
        ca_seed: CA_SEED,
    },
    Server {
        profile: "0f0f0f0f-0000-4000-8000-000000000001",
        host: "old.acme.io",
        user: "root",
        port: 22,
        host_key: "SHA256:1cXUHKyIzxrd9QVZLeMUNYlIpLyigpi3pXI0x7TLYeY",
        line: CaLineForm::PerServer,
        ca_seed: EARLIER_CA_SEED,
    },
];

/// Seals the CA document (made a day ago) and the three trust records (an hour ago, read half an
/// hour ago) into the account's `agent_ssh_trust` collection.
pub(super) fn store(recorder: &mut Recorder, account: &WebAccount) {
    let key = recorder.collection(account, TRUST_COLLECTION, SSH_TRUST_KIND);
    let document = CaDocument::new(UserCa::from_seed(CA_SEED), NOW - 86_400_000)
        .encode()
        .unwrap();
    let sealed = key
        .seal_object(TRUST_COLLECTION, CA_OBJECT, SSH_TRUST_KIND, &document)
        .unwrap();
    recorder.object(TRUST_COLLECTION, CA_OBJECT, SSH_TRUST_KIND, sealed);
    for server in &SERVERS {
        let mut record = SshTrustRecord::installed(
            server.profile.to_owned(),
            server.host.to_owned(),
            server.user.to_owned(),
            server.host_key.to_owned(),
            UserCa::from_seed(server.ca_seed).fingerprint(),
            NOW - 3_600_000,
            DeviceId::new(),
        )
        .unwrap();
        record.set_line(server.line, NOW - 1_800_000);
        let object = server.id().object_id();
        let sealed = key
            .seal_object(
                TRUST_COLLECTION,
                &object,
                SSH_TRUST_KIND,
                &record.encode().unwrap(),
            )
            .unwrap();
        recorder.object(TRUST_COLLECTION, &object, SSH_TRUST_KIND, sealed);
    }
}

/// What the runner opens from a device's publication: its `CommandAccepted` value and `read`'s
/// view of the payload.
fn accepted<T>(
    effect: &WireEffect,
    account: &WebAccount,
    read: impl FnOnce(&CloudCommandPayload<'_>) -> T,
) -> (AcceptedCommand, T) {
    let WireEffect::Publish { publication, data } = effect else {
        panic!("a publication");
    };
    let binding = RelayBinding::from_canonical_bytes(&publication.binding).unwrap();
    let opened = open_command(
        &RunnerEncryptionKey::from_seed(&RUNNER_ENCRYPTION_SEED),
        &PublicKey::from_bytes(&account.pair.public_key().to_bytes()).unwrap(),
        binding.command_route().unwrap(),
        data,
    )
    .unwrap();
    let command = opened.command().unwrap();
    let header = command.header();
    let context = header.context();
    let payload =
        CloudCommandPayload::from_canonical_bytes(context.kind, command.payload()).unwrap();
    payload.require_header(header).unwrap();
    let accepted = AcceptedCommand {
        id: header.route().command_id,
        kind: context.kind,
        signed_message_digest: Sha256::digest(command.plaintext_bytes().unwrap()).into(),
        issuer: header.issuer().clone(),
        expected_control_revision: context.expected_chat_revision,
    };
    (accepted, read(&payload))
}

/// The chat-scoped event at control revision `revision`, a second apart from the recorded `now`.
fn event(revision: u64, payload: CloudEventPayload<'_>) -> Vec<u8> {
    CloudEvent {
        control_revision: revision,
        timestamp_ms: u64::try_from(NOW).unwrap() + (revision - 7) * 1_000,
        payload,
    }
    .canonical_bytes()
    .unwrap()
}

/// The runner's reach of the bound servers: `db-1` admitted, `bastion` unreachable.
fn reach() -> Vec<SshServerStatus> {
    vec![
        SshServerStatus {
            server: SERVERS[0].id(),
            reach: SshServerReach::Admitted,
        },
        SshServerStatus {
            server: SERVERS[1].id(),
            reach: SshServerReach::Unreachable,
        },
    ]
}

/// `chat` binds `db-1` and `bastion`; returns the runner's view of the accepted command and the
/// CA-signed binding it carries.
fn bind(
    recorder: &mut Recorder,
    account: &WebAccount,
    chat: &mut WebChat,
) -> (AcceptedCommand, SignedSshBinding) {
    let choices = SERVERS[..2]
        .iter()
        .map(|server| SshServerInput {
            server_id: server.hex(),
            port: server.port,
        })
        .collect();
    let mut bind = chat
        .binding(choices, BindOptions::default(), NOW_MS)
        .unwrap();
    let (outputs, last, _) = drive(&mut bind, recorder, NOW_MS);
    assert!(matches!(last, FlowStep::Done), "{last:?}");
    let Some(FlowOutput::SshBound {
        needs_ca_update, ..
    }) = outputs.first()
    else {
        panic!("bound: {outputs:?}");
    };
    assert_eq!(needs_ca_update, &[SERVERS[1].hex()]);
    accepted(recorder.published.last().unwrap(), account, |payload| {
        let CloudCommandPayload::IssueGrant(grant) = payload else {
            panic!("a grant");
        };
        let GrantPayload::SshBinding { binding } = grant.as_ref() else {
            panic!("a binding");
        };
        binding.clone()
    })
}

/// `chat` answers the runner's request; returns the runner's view of the accepted command and
/// the end of the certificate it checked (Unix milliseconds).
fn answer(
    recorder: &mut Recorder,
    account: &WebAccount,
    chat: &mut WebChat,
    subject: [u8; 32],
) -> (AcceptedCommand, i64) {
    let mut answer = chat.answering(&hex::encode(REQUEST), NOW_MS).unwrap();
    let (outputs, last, _) = drive(&mut answer, recorder, NOW_MS);
    assert!(matches!(last, FlowStep::Done), "{last:?}");
    let Some(FlowOutput::SshCertified { servers, .. }) = outputs.first() else {
        panic!("certified: {outputs:?}");
    };
    assert_eq!(servers, &[SERVERS[0].hex()]);
    let (answered, certificate) =
        accepted(recorder.published.last().unwrap(), account, |payload| {
            let CloudCommandPayload::IssueGrant(grant) = payload else {
                panic!("a grant");
            };
            let GrantPayload::SshCertificate {
                request,
                certificate,
                ..
            } = grant.as_ref()
            else {
                panic!("a certificate");
            };
            assert_eq!(*request, REQUEST);
            certificate.to_vec()
        });
    let ca = UserCa::from_seed(CA_SEED).public_key();
    let facts = CertificateFacts::read(&certificate, &ca).unwrap();
    assert_eq!(facts.principals, vec![principal_for(&ca, &SERVERS[0].id())]);
    assert_eq!(facts.subject_key, subject);
    (answered, i64::try_from(facts.valid_before).unwrap() * 1_000)
}

/// The runner's records of `bodies` from chat cursor `first` on.
fn sealed(
    selector: &ChatSelector,
    key: &ChatKey,
    first: u64,
    bodies: &[Vec<u8>],
) -> Vec<(Value, HeadRecordAnchor)> {
    (first..)
        .zip(bodies)
        .map(|(sequence, body)| chat::seal(selector, key, sequence, None, body))
        .collect()
}
fn accepted_event(revision: u64, command: AcceptedCommand) -> Vec<u8> {
    event(
        revision,
        CloudEventPayload::CommandAccepted { command, run: None },
    )
}
fn access_event(revision: u64, update: SshAccessUpdate) -> Vec<u8> {
    event(
        revision,
        CloudEventPayload::SshAccessState(Box::new(update)),
    )
}

/// The directory summary after the access turned active, naming both bound servers.
fn summary(
    selector: &ChatSelector,
    account: &WebAccount,
    head: &HeadRecordAnchor,
    valid_before_ms: i64,
) -> Value {
    let bound = |server: &Server, state, valid_before_ms| BoundServer {
        host: CloudTextId::new(server.host).unwrap(),
        port: server.port,
        user: CloudTextId::new(server.user).unwrap(),
        state,
        valid_before_ms,
    };
    directory::bound(
        selector,
        account,
        head,
        NOW + 5_000,
        vec![
            bound(&SERVERS[0], ServerState::Active, Some(valid_before_ms)),
            bound(&SERVERS[1], ServerState::Unreachable, None),
        ],
    )
}

/// The trust records as `ssh.servers` describes them.
fn described() -> Vec<Value> {
    SERVERS
        .iter()
        .map(|server| {
            json!({
                "serverId": server.hex(),
                "objectId": server.id().object_id(),
                "profileId": server.profile,
                "host": server.host,
                "user": server.user,
                "port": server.port,
                "hostKeyFingerprint": server.host_key,
                "line": if server.line == CaLineForm::PerServer { "perServer" } else { "shared" },
                "caFingerprint": UserCa::from_seed(server.ca_seed).fingerprint(),
            })
        })
        .collect()
}

/// Records the SSH part of the session after `run_order`, with the later text record already in
/// the stream: `chat` binds `db-1` and `bastion`; the runner's records 8–10 (the accepted
/// binding command, access pending, the certificate request) join the stream; a new open of
/// the chat (its probe draws the next seeded nonces) announces the request and answers it; the
/// runner's records 11–12 (the accepted certificate command, access active) and the directory
/// summary naming the servers are kept for a Watch. Returns the `ssh` part of the session file.
pub(super) fn record(
    recorder: &mut Recorder,
    account: &WebAccount,
    device: &CloudDevice,
    chat: &mut WebChat,
    selector: &ChatSelector,
    key: &ChatKey,
) -> Value {
    let (bound, binding) = bind(recorder, account, chat);
    let grant = binding.binding().grant;
    let window = binding.binding().window;
    let subject = DeviceKey::from_seed(&SUBJECT_SEED).public_key();
    let request = SshCertificateRequest {
        request: REQUEST,
        binding,
        subject_key: subject,
        source_addresses: vec![SOURCE_ADDRESS.to_owned()],
        servers: vec![SERVERS[0].id()],
        not_after_ms: NOW + DEFAULT_CERTIFICATE_VALIDITY_MS,
    };
    let pending = SshAccessUpdate {
        grant,
        access: SshAccess::Pending,
        servers: reach(),
    };
    let requested = CloudEventPayload::SshCertificateRequested(Box::new(request));
    let records = sealed(
        selector,
        key,
        8,
        &[
            accepted_event(8, bound.clone()),
            access_event(9, pending),
            event(10, requested),
        ],
    );
    recorder
        .rows
        .records
        .extend(records.iter().map(|(record, _)| record.clone()));
    recorder.head = Some(records[2].1.clone());

    let chat_id = nocterm_cloud_device::context::ChatRef::of(selector).to_string();
    let mut reopened = device.opened(&chat_id, None).unwrap();
    let (outputs, ..) = drive(&mut reopened, recorder, NOW_MS);
    assert!(
        outputs.iter().any(|output| matches!(
            output,
            FlowOutput::SshRequest { request_id } if *request_id == hex::encode(REQUEST)
        )),
        "{outputs:?}"
    );
    let (answered, valid_before_ms) = answer(recorder, account, &mut reopened, subject);
    let active = SshAccessUpdate {
        grant,
        access: SshAccess::Active {
            request: REQUEST,
            valid_before_ms,
        },
        servers: reach(),
    };
    let later = sealed(
        selector,
        key,
        11,
        &[
            accepted_event(11, answered.clone()),
            access_event(12, active),
        ],
    );
    let summary = summary(selector, account, &later[1].1, valid_before_ms);
    let ca = UserCa::from_seed(CA_SEED);
    json!({
        "caFingerprint": ca.fingerprint(),
        "caPublicKey": hex::encode(ca.public_key()),
        "servers": described(),
        "binding": {
            "grant": hex::encode(grant.id),
            "epoch": grant.epoch,
            "commandId": hex::encode(bound.id),
            "issuedAtMs": window.issued_at_ms,
            "expiresAtMs": window.expires_at_ms,
            "servers": [SERVERS[0].hex(), SERVERS[1].hex()],
            "needsCaUpdate": [SERVERS[1].hex()],
        },
        "request": {
            "requestId": hex::encode(REQUEST),
            "subjectKey": hex::encode(subject),
            "sourceAddresses": [SOURCE_ADDRESS],
            "servers": [SERVERS[0].hex()],
            "notAfterMs": NOW + DEFAULT_CERTIFICATE_VALIDITY_MS,
            "validBeforeMs": valid_before_ms,
            "commandId": hex::encode(answered.id),
        },
        "records": records.into_iter().map(|(record, _)| record).collect::<Vec<_>>(),
        "later": later.into_iter().map(|(record, _)| record).collect::<Vec<_>>(),
        "directory": [summary],
    })
}
