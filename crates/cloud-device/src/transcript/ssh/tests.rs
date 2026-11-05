#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use crate::{
    error::SshRefusal,
    testing::{
        NOW, World,
        ssh::{GRANT, SUBJECT, binding, ca, reported, reported_reach, request, requested, server},
    },
    transcript::{
        Transcript,
        codec::{Reader, Writer},
    },
};
use nocterm_hub_model::cloud::{
    payload::GrantReference,
    ssh::{DEFAULT_BINDING_WINDOW_MS, SshAccess, SshBindingRefusal},
};

fn requested_once(world: &World, transcript: &mut Transcript, id: u8, grant: GrantReference) {
    let signed = binding(world, &ca(), grant, &["db", "cache"]);
    transcript.apply(&requested(1, request(signed, id, SUBJECT, &["db"])));
}

#[test]
fn a_request_is_answerable_until_the_runner_reports_its_certificate() {
    let world = World::new();
    let mut transcript = Transcript::new();
    requested_once(&world, &mut transcript, 1, GRANT);
    let ssh = transcript.ssh();
    assert_eq!(ssh.answerable(&[1; 16], NOW).unwrap().request, [1; 16]);
    assert_eq!(ssh.current().unwrap().subject_key(), Some(SUBJECT));
    assert!(transcript.take_delta().unwrap().ssh.is_some());
    transcript.apply(&reported(
        2,
        GRANT,
        SshAccess::Active {
            request: [1; 16],
            valid_before_ms: NOW + 1,
        },
    ));
    assert_eq!(
        transcript.ssh().answerable(&[1; 16], NOW),
        Err(SshRefusal::UnknownRequest)
    );
    assert!(
        transcript.ssh().current().is_some(),
        "an active binding stays shown"
    );
}

#[test]
fn a_request_outside_the_binding_window_is_refused() {
    let world = World::new();
    let mut transcript = Transcript::new();
    requested_once(&world, &mut transcript, 1, GRANT);
    let ssh = transcript.ssh();
    let after = NOW - 1_000 + DEFAULT_BINDING_WINDOW_MS;
    assert_eq!(
        ssh.answerable(&[1; 16], after),
        Err(SshRefusal::OutsideBinding)
    );
    assert_eq!(
        ssh.answerable(&[1; 16], NOW - 2_000),
        Err(SshRefusal::OutsideBinding)
    );
    assert!(
        ssh.eligible(&[1; 16]).is_ok(),
        "eligibility ignores the clock"
    );
}

#[test]
fn revoked_refused_expired_or_withdrawn_bindings_answer_nothing() {
    let world = World::new();
    for access in [
        Some(SshAccess::Revoked),
        Some(SshAccess::Expired),
        Some(SshAccess::Refused(SshBindingRefusal::NoSourceAddress)),
        None,
    ] {
        let mut transcript = Transcript::new();
        requested_once(&world, &mut transcript, 1, GRANT);
        match access {
            Some(access) => transcript.apply(&reported(2, GRANT, access)),
            None => transcript.withdraw_ssh(&GRANT.id),
        }
        assert!(transcript.ssh().requests().is_empty(), "{access:?}");
        assert!(transcript.ssh().current().is_none(), "{access:?}");
        requested_once(&world, &mut transcript, 2, GRANT);
        assert_eq!(
            transcript
                .ssh()
                .answerable(&[2; 16], NOW)
                .map(|r| r.request),
            Err(SshRefusal::UnknownRequest),
            "{access:?}: a closed binding takes no new request"
        );
    }
}

#[test]
fn a_newer_epoch_replaces_the_binding_and_drops_its_older_requests() {
    let world = World::new();
    let mut transcript = Transcript::new();
    requested_once(&world, &mut transcript, 1, GRANT);
    transcript.apply(&reported(2, GRANT, SshAccess::Revoked));
    let newer = GrantReference {
        epoch: GRANT.epoch + 1,
        ..GRANT
    };
    requested_once(&world, &mut transcript, 2, newer);
    assert!(transcript.ssh().answerable(&[2; 16], NOW).is_ok());
    // A late request of the old epoch changes nothing.
    requested_once(&world, &mut transcript, 3, GRANT);
    assert_eq!(transcript.ssh().requests().len(), 1);
    assert_eq!(transcript.ssh().current().unwrap().grant(), newer);
}

#[test]
fn a_request_with_another_subject_key_than_the_first_is_refused() {
    let world = World::new();
    let mut transcript = Transcript::new();
    requested_once(&world, &mut transcript, 1, GRANT);
    let signed = binding(&world, &ca(), GRANT, &["db", "cache"]);
    transcript.apply(&requested(2, request(signed, 2, [0x56; 32], &["db"])));
    assert_eq!(
        transcript.ssh().answerable(&[2; 16], NOW),
        Err(SshRefusal::SubjectKeyChanged)
    );
}

#[test]
fn the_bindings_and_open_requests_survive_a_checkpoint() {
    let world = World::new();
    let mut transcript = Transcript::new();
    requested_once(&world, &mut transcript, 1, GRANT);
    transcript.apply(&reported(2, GRANT, SshAccess::Pending));
    let mut out = Writer(Vec::new());
    transcript.encode(&mut out).unwrap();
    let mut input = Reader(&out.0);
    let restored = Transcript::decode(&mut input).unwrap();
    input.finish().unwrap();
    assert_eq!(restored.ssh(), transcript.ssh());
    let mut truncated = Reader(&out.0[..out.0.len() - 1]);
    assert!(Transcript::decode(&mut truncated).is_err());
}

#[test]
fn the_session_targets_are_the_admitted_servers_of_the_current_binding() {
    let world = World::new();
    let mut transcript = Transcript::new();
    assert!(transcript.ssh().session_targets(NOW).is_empty());
    assert_eq!(
        transcript.ssh().session_target(&server("db"), NOW),
        Err(SshRefusal::NotBound)
    );
    // Before a report, the open request names what the runner admitted.
    requested_once(&world, &mut transcript, 1, GRANT);
    let signed = binding(&world, &ca(), GRANT, &["db", "cache"]);
    let targets = transcript.ssh().session_targets(NOW);
    assert_eq!(targets.len(), 1);
    let db = &targets[0];
    assert_eq!((db.server, db.port, db.active), (server("db"), 22, false));
    assert_eq!(
        (db.host.as_str(), db.user.as_str()),
        ("db.example.org", "deploy")
    );
    assert_eq!(
        Some(&db.access),
        signed.binding().target_access(&server("db")).as_ref()
    );
    assert_eq!(
        transcript.ssh().session_target(&server("cache"), NOW),
        Err(SshRefusal::NotSelectable)
    );
    // A report decides; an active certificate is shown as such until it lapses.
    let active = SshAccess::Active {
        request: [1; 16],
        valid_before_ms: NOW + 10,
    };
    transcript.apply(&reported_reach(2, GRANT, active, &["db"], &["cache"]));
    let ssh = transcript.ssh();
    assert!(ssh.session_target(&server("db"), NOW).unwrap().active);
    assert!(!ssh.session_target(&server("db"), NOW + 10).unwrap().active);
    let after = NOW - 1_000 + DEFAULT_BINDING_WINDOW_MS;
    assert!(ssh.session_targets(after).is_empty());
    transcript.apply(&reported(3, GRANT, SshAccess::Revoked));
    assert!(transcript.ssh().session_targets(NOW).is_empty());
}
