#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::{
    context::ChatRef,
    open::{ChatUpdate, OpenChat},
    records::{CHAT_MATERIAL_KIND, ChatMaterialRecord},
    testing::{
        NOW, World,
        hub::{Ended, FakeHub},
        ssh::{
            GRANT, HOST_KEY, SUBJECT, binding, ca, record, reported, request, requested, server,
            trust_store,
        },
    },
};
use nocterm_hub_model::cloud::{
    payload::{CloudCommandPayload, GrantClass, GrantPayload},
    relay::RelayBinding,
    ssh::{DEFAULT_CERTIFICATE_VALIDITY_MS, SshAccess},
};
use nocterm_keys::{
    PublicKey,
    agents::ssh_ca::{CertificateFacts, UserCa, principal_for},
    cloud::{ChatKey, RunnerSigningKey, open_command},
};

/// A hub with the chat's key material and the account's CA with `records`.
fn ssh_hub(records: &[SshTrustRecord]) -> (FakeHub, ChatKey) {
    let mut hub = FakeHub::new(World::new());
    let key = ChatKey::generate().unwrap();
    let selector = hub.world.selector.clone();
    let collection = ChatMaterialRecord::collection_id(selector.scope()).unwrap();
    let collection_key = hub.collection(&collection, CHAT_MATERIAL_KIND);
    let material = ChatMaterialRecord::wrap(selector.clone(), &key, &hub.world.account).unwrap();
    hub.object(
        &collection,
        &selector.object_id().unwrap(),
        CHAT_MATERIAL_KIND,
        material.seal(&collection_key).unwrap(),
    );
    trust_store(&mut hub, ca(), records);
    (hub, key)
}
fn trusted() -> Vec<SshTrustRecord> {
    vec![
        record("db", &ca(), CaLineForm::PerServer),
        record("cache", &ca(), CaLineForm::Shared),
    ]
}
fn open(hub: &mut FakeHub) -> (OpenChat, Vec<ChatUpdate>) {
    let mut chat = OpenChat::new(
        hub.world.session(),
        hub.world.device.clone(),
        &ChatRef::of(&hub.world.selector),
        None,
    )
    .unwrap();
    let (updates, _) = hub.run(&mut chat, NOW);
    (chat, updates)
}
fn events(hub: &mut FakeHub, key: &ChatKey, events: &[CloudEvent<'_>]) {
    let selector = hub.world.selector.clone();
    for event in events {
        hub.event(&selector, key, event, None);
    }
}
fn announced(updates: &[ChatUpdate]) -> Vec<[u8; 16]> {
    updates
        .iter()
        .filter_map(|update| match update {
            ChatUpdate::SshRequest { request } => Some(*request),
            _ => None,
        })
        .collect()
}
/// What the runner opens from the last publication.
fn published<T>(hub: &FakeHub, read: impl FnOnce(&CloudCommandPayload<'_>) -> T) -> T {
    let publication = hub.published.last().unwrap();
    let binding = RelayBinding::from_canonical_bytes(&publication.binding().unwrap()).unwrap();
    let opened = open_command(
        &hub.world.runner_key,
        &PublicKey::from_bytes(&hub.world.account_public()).unwrap(),
        binding.command_route().unwrap(),
        publication.ciphertext(),
    )
    .unwrap();
    let command = opened.command().unwrap();
    assert_eq!(
        command.header().context().run,
        None,
        "SSH commands are chat-scoped"
    );
    let kind = command.header().context().kind;
    let payload = CloudCommandPayload::from_canonical_bytes(kind, command.payload()).unwrap();
    payload.require_header(command.header()).unwrap();
    read(&payload)
}
fn choices() -> [SshServerChoice; 2] {
    [
        SshServerChoice {
            server: server("db"),
            port: 22,
        },
        SshServerChoice {
            server: server("cache"),
            port: 2222,
        },
    ]
}
use nocterm_hub_model::cloud::events::CloudEvent;

#[test]
fn a_binding_takes_host_user_and_host_key_from_trusted_records_and_flags_shared_lines() {
    let (mut hub, _) = ssh_hub(&trusted());
    let (mut chat, _) = open(&mut hub);
    let mut flow = chat.bind_servers(&choices(), None, None, NOW).unwrap();
    let (updates, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Done), "{ended:?}");
    let SshUpdate::Bound {
        grant,
        needs_ca_update,
    } = &updates[0]
    else {
        panic!("{updates:?}");
    };
    assert_eq!(needs_ca_update, &[server("cache")]);
    assert!(matches!(&updates[1], SshUpdate::Delivery(d) if d.state == CommandState::Delivered));
    let signed = published(&hub, |payload| {
        let CloudCommandPayload::IssueGrant(grant) = payload else {
            panic!("a grant");
        };
        let GrantPayload::SshBinding { binding } = grant.as_ref() else {
            panic!("a binding");
        };
        binding.clone()
    });
    signed.require_ca(&ca().public_key()).unwrap();
    let binding = signed.binding();
    assert_eq!(binding.grant, *grant);
    assert_eq!(binding.chat, hub.world.selector.coordinate().unwrap());
    assert_eq!(
        binding.window.expires_at_ms - binding.window.issued_at_ms,
        DEFAULT_BINDING_WINDOW_MS
    );
    let db = binding.target(&server("db")).unwrap();
    assert_eq!(
        (
            db.host.as_str(),
            db.port,
            db.user.as_str(),
            db.host_key_sha256
        ),
        ("db.example.org", 22, "deploy", HOST_KEY)
    );
    assert_eq!(binding.target(&server("cache")).unwrap().port, 2222);
    chat.delivery(match &updates[1] {
        SshUpdate::Delivery(update) => update,
        _ => unreachable!(),
    });
    let pending = chat.transcript().pending_commands();
    assert_eq!(pending[0].kind, PendingKind::Bind);
}

#[test]
fn a_binding_refuses_servers_not_trusted_under_the_current_ca() {
    let mut pending = record("db", &ca(), CaLineForm::PerServer);
    pending.request_removal().unwrap();
    let records = [
        pending,
        record(
            "cache",
            &UserCa::from_seed([0x92; 32]),
            CaLineForm::PerServer,
        ),
    ];
    let (mut hub, _) = ssh_hub(&records);
    let (mut chat, _) = open(&mut hub);
    for profile in ["db", "cache", "gone"] {
        let choice = [SshServerChoice {
            server: server(profile),
            port: 22,
        }];
        let mut flow = chat.bind_servers(&choice, None, None, NOW).unwrap();
        let (_, ended) = hub.run(&mut flow, NOW);
        assert!(
            matches!(
                ended,
                Ended::Failed(CloudDeviceError::Ssh(SshRefusal::UntrustedServer))
            ),
            "{profile}: {ended:?}"
        );
    }
    assert!(hub.published.is_empty());
    let twice = [choices()[0], choices()[0]];
    for (choice, window, refusal) in [
        (&twice[..], None, SshRefusal::Servers),
        (&[][..], None, SshRefusal::Servers),
        (
            &choices()[..1],
            Some(MAX_BINDING_WINDOW_MS + 1),
            SshRefusal::Window,
        ),
    ] {
        assert!(matches!(
            chat.bind_servers(choice, window, None, NOW),
            Err(CloudDeviceError::Ssh(found)) if found == refusal
        ));
    }
}

#[test]
fn an_account_without_a_ca_binds_nothing() {
    let mut hub = FakeHub::new(World::new());
    let (mut chat, _) = open(&mut hub);
    let mut flow = chat.bind_servers(&choices(), None, None, NOW).unwrap();
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(
        ended,
        Ended::Failed(CloudDeviceError::Ssh(SshRefusal::NoCa))
    ));
}

#[test]
fn an_answer_certifies_only_still_trusted_requested_servers_with_every_restriction() {
    let mut removed = record("cache", &ca(), CaLineForm::PerServer);
    removed.request_removal().unwrap();
    let (mut hub, key) = ssh_hub(&[record("db", &ca(), CaLineForm::PerServer), removed]);
    let signed = binding(&hub.world, &ca(), GRANT, &["db", "cache"]);
    events(
        &mut hub,
        &key,
        &[requested(1, request(signed, 1, SUBJECT, &["db", "cache"]))],
    );
    let (mut chat, updates) = open(&mut hub);
    assert_eq!(announced(&updates), vec![[1; 16]]);
    let mut flow = chat.answer_ssh(&[1; 16], NOW).unwrap();
    let (updates, ended) = hub.run(&mut flow, NOW);
    assert!(matches!(ended, Ended::Done), "{ended:?}");
    assert_eq!(
        updates[0],
        SshUpdate::Certified {
            request: [1; 16],
            servers: vec![server("db")],
            valid_before_ms: NOW + DEFAULT_CERTIFICATE_VALIDITY_MS,
        }
    );
    let (grant, answered, certificate) = published(&hub, |payload| {
        let CloudCommandPayload::IssueGrant(grant) = payload else {
            panic!("a grant");
        };
        let GrantPayload::SshCertificate {
            grant,
            request,
            certificate,
        } = grant.as_ref()
        else {
            panic!("a certificate");
        };
        (*grant, *request, certificate.to_vec())
    });
    assert_eq!((grant, answered), (GRANT, [1; 16]));
    let facts = CertificateFacts::read(&certificate, &ca().public_key()).unwrap();
    assert_eq!(
        facts.principals,
        vec![principal_for(&ca().public_key(), &server("db"))]
    );
    assert_eq!(facts.subject_key, SUBJECT);
    assert_eq!(facts.source_addresses, vec!["203.0.113.7/32".to_owned()]);
    let start = u64::try_from(NOW / 1000).unwrap();
    assert_eq!(facts.valid_before - start, 8 * 3600);
    assert!(
        facts
            .key_id
            .contains(&hex::encode(hub.world.selector.chat_id()))
    );
}

#[test]
fn requests_outside_the_binding_or_after_revocation_are_not_answered() {
    let (mut hub, key) = ssh_hub(&trusted());
    let signed = binding(&hub.world, &ca(), GRANT, &["db"]);
    events(
        &mut hub,
        &key,
        &[requested(1, request(signed, 1, SUBJECT, &["db"]))],
    );
    let (mut chat, _) = open(&mut hub);
    let ends = NOW - 1_000 + DEFAULT_BINDING_WINDOW_MS;
    assert!(matches!(
        chat.answer_ssh(&[1; 16], ends),
        Err(CloudDeviceError::Ssh(SshRefusal::OutsideBinding))
    ));
    // This device revokes: the runner is told, and nothing of the binding is answered again.
    let mut unbind = chat.unbind_servers(None, NOW).unwrap();
    let (_, ended) = hub.run(&mut unbind, NOW);
    assert!(matches!(ended, Ended::Done));
    let class = published(&hub, |payload| match payload {
        CloudCommandPayload::RevokeGrant(scoped) => (scoped.class, scoped.grant),
        _ => panic!("a revocation"),
    });
    assert_eq!(class, (GrantClass::SshBinding, GRANT));
    assert!(matches!(
        chat.answer_ssh(&[1; 16], NOW),
        Err(CloudDeviceError::Ssh(SshRefusal::UnknownRequest))
    ));
    assert!(matches!(
        chat.unbind_servers(None, NOW),
        Err(CloudDeviceError::Ssh(SshRefusal::NotBound))
    ));
    // Another device learns of a revocation from the runner.
    let (mut hub, key) = ssh_hub(&trusted());
    let signed = binding(&hub.world, &ca(), GRANT, &["db"]);
    events(
        &mut hub,
        &key,
        &[
            requested(1, request(signed, 1, SUBJECT, &["db"])),
            reported(2, GRANT, SshAccess::Revoked),
        ],
    );
    let (mut chat, updates) = open(&mut hub);
    assert!(announced(&updates).is_empty());
    assert!(chat.answer_ssh(&[1; 16], NOW).is_err());
}

#[test]
fn a_binding_signed_by_another_ca_is_not_answered() {
    let (mut hub, key) = ssh_hub(&trusted());
    let other = UserCa::from_seed([0x92; 32]);
    let signed = binding(&hub.world, &other, GRANT, &["db"]);
    events(
        &mut hub,
        &key,
        &[requested(1, request(signed, 1, SUBJECT, &["db"]))],
    );
    let (mut chat, _) = open(&mut hub);
    let mut flow = chat.answer_ssh(&[1; 16], NOW).unwrap();
    let (_, ended) = hub.run(&mut flow, NOW);
    assert!(
        matches!(
            ended,
            Ended::Failed(CloudDeviceError::Ssh(SshRefusal::OtherCa))
        ),
        "{ended:?}"
    );
    assert!(hub.published.is_empty());
}

#[test]
fn a_request_signed_by_another_runner_key_never_reaches_an_answer() {
    let (mut hub, key) = ssh_hub(&trusted());
    let signed = binding(&hub.world, &ca(), GRANT, &["db"]);
    let pinned = std::mem::replace(
        &mut hub.world.runner_signer,
        RunnerSigningKey::from_seed(&[0x52; 32]),
    );
    events(
        &mut hub,
        &key,
        &[requested(1, request(signed, 1, SUBJECT, &["db"]))],
    );
    hub.world.runner_signer = pinned;
    let (mut chat, updates) = open(&mut hub);
    assert!(announced(&updates).is_empty());
    assert!(
        updates
            .iter()
            .any(|update| matches!(update, ChatUpdate::Refused(_)))
    );
    assert!(matches!(
        chat.answer_ssh(&[1; 16], NOW),
        Err(CloudDeviceError::Ssh(SshRefusal::UnknownRequest))
    ));
}

#[test]
fn a_prompt_naming_a_bound_server_carries_its_session_access_and_others_are_refused() {
    let (mut hub, key) = ssh_hub(&trusted());
    let signed = binding(&hub.world, &ca(), GRANT, &["db", "cache"]);
    let access = signed.binding().target_access(&server("db")).unwrap();
    events(
        &mut hub,
        &key,
        &[requested(1, request(signed, 1, SUBJECT, &["db"]))],
    );
    let (mut chat, _) = open(&mut hub);
    assert_eq!(chat.session_targets(NOW)[0].access, access);
    let prompt = |server| crate::open::ChatAction::Prompt {
        text: "deploy".to_owned(),
        model: Some(crate::open::ModelChoice {
            provider: crate::policy::MANAGED_PROVIDER.to_owned(),
            model: "m".to_owned(),
        }),
        server,
    };
    assert!(matches!(
        chat.deliver(&prompt(Some(server("cache"))), None, NOW),
        Err(CloudDeviceError::Ssh(SshRefusal::NotSelectable))
    ));
    let mut delivery = chat
        .deliver(&prompt(Some(server("db"))), None, NOW)
        .unwrap();
    let (_, ended) = hub.run(&mut delivery, NOW);
    assert!(matches!(ended, Ended::Done));
    let (target, session) = published(&hub, |payload| match payload {
        CloudCommandPayload::SubmitPrompt(prompt) => {
            (prompt.target.clone(), prompt.existing_session.clone())
        }
        _ => panic!("a prompt"),
    });
    assert_eq!((target, session), (Some(access), None));
}
