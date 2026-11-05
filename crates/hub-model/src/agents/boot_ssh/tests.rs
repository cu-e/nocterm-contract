#![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
use super::*;
use crate::cloud::{CloudTextId, ssh::SshServerId};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    version: u32,
    ssh_targets: Vec<BootSshTarget>,
    #[serde(default)]
    ssh_egress: Option<Vec<String>>,
}

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/boot-ssh-v3")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}
fn section() -> Section {
    serde_json::from_str(&fixture("ssh-section.json")).unwrap()
}
fn check(section: &Section) -> Result<(), BootSshError> {
    check_boot_ssh(
        section.version,
        &section.ssh_targets,
        section.ssh_egress.as_deref(),
    )
}
fn bound(host: &str, port: u16, user: &str, host_key: [u8; 32]) -> SshTarget {
    SshTarget {
        server: SshServerId::of_profile("profile-db"),
        host: CloudTextId::new(host).unwrap(),
        port,
        user: CloudTextId::new(user).unwrap(),
        host_key_sha256: host_key,
    }
}
fn db_key() -> [u8; 32] {
    hex::decode(fixture("db-host-key-sha256.hex").trim())
        .unwrap()
        .try_into()
        .unwrap()
}
type Change = fn(&mut BootSshTarget);

fn target_error(section: &Section) -> Option<BootSshField> {
    match check(section) {
        Err(BootSshError::Target { field, .. }) => Some(field),
        _ => None,
    }
}

#[test]
fn the_v3_vector_is_valid_and_its_first_target_pins_the_vector_fingerprint() {
    let section = section();
    check(&section).unwrap();
    let [db, cache] = &section.ssh_targets[..] else {
        panic!("two targets")
    };
    assert_eq!(db.host_key_sha256(), Some(db_key()));
    assert_eq!(db.session_or_default().columns, 120);
    assert_eq!(cache.host_key_sha256(), None);
    assert_eq!(cache.session_or_default(), BootSshSession::default());
    let reparsed: Vec<BootSshTarget> =
        serde_json::from_value(serde_json::to_value(&section.ssh_targets).unwrap()).unwrap();
    assert_eq!(reparsed, section.ssh_targets);
}

#[test]
fn a_bound_server_is_admitted_only_by_a_target_with_its_endpoint_and_host_key() {
    let targets = section().ssh_targets;
    let db = bound("db.example.org", 22, "deploy", db_key());
    assert_eq!(admitting_target(&targets, &db), Some(&targets[0]));
    for other in [
        bound("db.example.org", 22, "deploy", [9; 32]),
        bound("db.example.org", 2200, "deploy", db_key()),
        bound("db.example.org", 22, "root", db_key()),
        bound("db2.example.org", 22, "deploy", db_key()),
        // Listed without a host key: never admitted.
        bound("10.0.0.5", 2222, "root", [9; 32]),
    ] {
        assert_eq!(admitting_target(&targets, &other), None);
    }
}

#[test]
fn v2_states_no_egress_and_no_v3_fields_and_other_versions_are_refused() {
    let mut v2 = section();
    v2.version = BOOT_VERSION_WITHOUT_SSH_EGRESS;
    assert_eq!(check(&v2), Err(BootSshError::Egress));
    v2.ssh_egress = None;
    assert_eq!(target_error(&v2), Some(BootSshField::NotInVersion));
    v2.ssh_targets.clear();
    v2.ssh_targets.push(BootSshTarget {
        host: "h".into(),
        user: "u".into(),
        port: 22,
        host_public_key: None,
        session: None,
    });
    check(&v2).unwrap();
    let mut v4 = section();
    v4.version = 4;
    assert_eq!(check(&v4), Err(BootSshError::Version));
}

#[test]
fn v3_egress_must_be_one_to_eight_addresses_or_cidrs() {
    let mut value = section();
    value.ssh_egress = None;
    assert_eq!(check(&value), Err(BootSshError::Egress));
    for bad in [
        vec![],
        vec!["10.0.0.1".to_owned(); 9],
        vec!["host.example".to_owned()],
        vec!["10.0.0.0/33".to_owned()],
        vec!["2001:db8::/129".to_owned()],
        vec!["10.0.0.1/+8".to_owned()],
        vec![String::new()],
    ] {
        value.ssh_egress = Some(bad);
        assert_eq!(check(&value), Err(BootSshError::Egress));
    }
}

#[test]
fn a_target_with_a_bad_field_is_refused_with_its_index_and_field() {
    let cases: [(Change, BootSshField); 9] = [
        (|t| t.host = String::new(), BootSshField::Host),
        (|t| t.host = "db example".into(), BootSshField::Host),
        (|t| t.user = "a\nb".into(), BootSshField::User),
        (|t| t.port = 0, BootSshField::Port),
        (
            |t| t.host_public_key = Some("ssh-ed25519 !!!".into()),
            BootSshField::HostKey,
        ),
        (
            // The blob names another algorithm than the line.
            |t| {
                let key = t.host_public_key.take().unwrap();
                t.host_public_key = Some(key.replacen("ssh-ed25519", "ssh-rsa", 1));
            },
            BootSshField::HostKey,
        ),
        (
            |t| t.session.as_mut().unwrap().terminal = "xterm 256".into(),
            BootSshField::Session,
        ),
        (
            |t| t.session.as_mut().unwrap().connect_timeout_ms = 60_001,
            BootSshField::Session,
        ),
        (
            |t| t.session.as_mut().unwrap().args = vec!["x".into(); 65],
            BootSshField::Session,
        ),
    ];
    for (change, field) in cases {
        let mut value = section();
        change(&mut value.ssh_targets[0]);
        assert_eq!(
            check(&value),
            Err(BootSshError::Target { index: 0, field }),
            "{field:?}"
        );
    }
    let mut twice = section();
    let mut copy = twice.ssh_targets[1].clone();
    copy.host_public_key
        .clone_from(&twice.ssh_targets[0].host_public_key);
    twice.ssh_targets.push(copy);
    assert_eq!(
        check(&twice),
        Err(BootSshError::Target {
            index: 2,
            field: BootSshField::Duplicate
        })
    );
    let mut many = section();
    many.ssh_targets = (0..=MAX_BOOT_SSH_TARGETS)
        .map(|index| BootSshTarget {
            host: format!("h{index}"),
            ..section().ssh_targets[1].clone()
        })
        .collect();
    assert_eq!(check(&many), Err(BootSshError::Targets));
}

#[test]
fn unknown_fields_in_a_target_or_its_session_do_not_parse() {
    let mut value: serde_json::Value = serde_json::from_str(&fixture("ssh-section.json")).unwrap();
    value["ssh_targets"][0]["password"] = "x".into();
    assert!(serde_json::from_value::<Section>(value.clone()).is_err());
    value["ssh_targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("password");
    value["ssh_targets"][0]["session"]["env"] = serde_json::json!({"A": "b"});
    assert!(serde_json::from_value::<Section>(value).is_err());
}
