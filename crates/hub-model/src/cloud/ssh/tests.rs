#![allow(clippy::unwrap_used, reason = "test fixtures fail loudly")]
use super::*;
use crate::cloud::{CloudNamespace, RunnerCoordinate};
use ed25519_dalek::{Signer, SigningKey};

const ISSUED: i64 = 1_800_000_000_000;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-ssh-v1")
        .join(format!("{name}.hex"));
    hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
}
fn id(text: &str) -> CloudTextId {
    CloudTextId::new(text).unwrap()
}
fn ca() -> SigningKey {
    SigningKey::from_bytes(&[0x91; 32])
}
pub(crate) fn chat() -> ChatCoordinate {
    ChatCoordinate::new(
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
    .unwrap()
}
fn binding() -> SshBinding {
    SshBinding {
        chat: chat(),
        grant: GrantReference {
            id: [0x33; 16],
            epoch: u64::try_from(ISSUED).unwrap(),
        },
        window: BindingWindow {
            issued_at_ms: ISSUED,
            expires_at_ms: ISSUED + DEFAULT_BINDING_WINDOW_MS,
        },
        ca_key: ca().verifying_key().to_bytes(),
        targets: vec![
            SshTarget {
                server: SshServerId::of_profile("profile-db"),
                host: id("db.example.org"),
                port: 22,
                user: id("deploy"),
                host_key_sha256: [0xa1; 32],
            },
            SshTarget {
                server: SshServerId::of_profile("profile-cache"),
                host: id("10.0.0.5"),
                port: 2222,
                user: id("root"),
                host_key_sha256: [0xa2; 32],
            },
        ],
    }
}
fn signed() -> SignedSshBinding {
    let binding = binding();
    let signature = ca().sign(&binding.signing_bytes().unwrap()).to_bytes();
    SignedSshBinding::new(binding, signature).unwrap()
}
fn request() -> SshCertificateRequest {
    SshCertificateRequest {
        request: [0x44; 16],
        binding: signed(),
        subject_key: SigningKey::from_bytes(&[0x55; 32])
            .verifying_key()
            .to_bytes(),
        source_addresses: vec!["203.0.113.7/32".into(), "2001:db8::1".into()],
        servers: vec![SshServerId::of_profile("profile-db")],
        not_after_ms: ISSUED + DEFAULT_CERTIFICATE_VALIDITY_MS,
    }
}
fn active() -> SshAccessUpdate {
    SshAccessUpdate {
        grant: binding().grant,
        access: SshAccess::Active {
            request: [0x44; 16],
            valid_before_ms: ISSUED + DEFAULT_CERTIFICATE_VALIDITY_MS,
        },
        servers: vec![
            SshServerStatus {
                server: SshServerId::of_profile("profile-db"),
                reach: SshServerReach::Admitted,
            },
            SshServerStatus {
                server: SshServerId::of_profile("profile-cache"),
                reach: SshServerReach::Unreachable,
            },
        ],
    }
}

#[test]
fn the_values_match_the_independent_vectors_and_round_trip() {
    assert_eq!(
        ca().verifying_key().to_bytes().to_vec(),
        fixture("ca-public")
    );
    assert_eq!(
        SshServerId::of_profile("profile-db").as_bytes().to_vec(),
        fixture("server-db")
    );
    assert_eq!(binding().signing_bytes().unwrap(), fixture("binding"));
    assert_eq!(
        signed().canonical_bytes().unwrap(),
        fixture("signed-binding")
    );
    assert_eq!(request().canonical_bytes().unwrap(), fixture("request"));
    assert_eq!(
        active().canonical_bytes().unwrap(),
        fixture("access-active")
    );
    assert_eq!(
        SshBinding::from_signing_bytes(&fixture("binding")).unwrap(),
        binding()
    );
    assert_eq!(
        SignedSshBinding::from_canonical_bytes(&fixture("signed-binding")).unwrap(),
        signed()
    );
    assert_eq!(
        SshCertificateRequest::from_canonical_bytes(&fixture("request")).unwrap(),
        request()
    );
    assert_eq!(
        SshAccessUpdate::from_canonical_bytes(&fixture("access-active")).unwrap(),
        active()
    );
}

#[test]
fn a_server_id_is_its_registry_object() {
    let server = SshServerId::of_profile("profile-db");
    let object = server.object_id();
    assert_eq!(object, format!("srv-{}", hex::encode(fixture("server-db"))));
    assert_eq!(SshServerId::from_object_id(&object), Some(server));
    for other in [
        "ca",
        "srv-00",
        &object.to_uppercase(),
        &format!("{object}0"),
    ] {
        assert_eq!(SshServerId::from_object_id(other), None, "{other}");
    }
}

#[test]
fn a_binding_outside_its_bounds_is_refused() {
    let refused = |change: fn(&mut SshBinding)| {
        let mut value = binding();
        change(&mut value);
        assert_eq!(value.validate(), Err(SshFormatError::Value));
    };
    refused(|b| b.window.expires_at_ms = b.window.issued_at_ms + MAX_BINDING_WINDOW_MS + 1);
    refused(|b| b.window.expires_at_ms = b.window.issued_at_ms);
    refused(|b| b.window.issued_at_ms = 0);
    refused(|b| b.grant.epoch = 0);
    refused(|b| b.ca_key = [0; 32]);
    refused(|b| b.targets.clear());
    refused(|b| b.targets[1].server = b.targets[0].server);
    refused(|b| b.targets[0].port = 0);
    refused(|b| b.targets[0].host_key_sha256 = [0; 32]);
    refused(|b| b.targets[0].user = CloudTextId::new("de ploy").unwrap());
    refused(|b| b.targets[0].host = CloudTextId::new("db\n").unwrap());
    refused(|b| {
        let first = b.targets[0].clone();
        b.targets = (0..=MAX_BINDING_TARGETS)
            .map(|index| SshTarget {
                server: SshServerId::from_bytes([u8::try_from(index).unwrap(); 16]),
                ..first.clone()
            })
            .collect();
    });
    assert!(binding().window.contains(ISSUED));
    assert!(!binding().window.contains(ISSUED - 1));
    assert!(
        !binding()
            .window
            .contains(ISSUED + DEFAULT_BINDING_WINDOW_MS)
    );
}

#[test]
fn only_the_named_ca_signs_a_binding() {
    let binding = binding();
    let other = SigningKey::from_bytes(&[0x92; 32]);
    let forged = other.sign(&binding.signing_bytes().unwrap()).to_bytes();
    assert!(matches!(
        SignedSshBinding::new(binding.clone(), forged),
        Err(SshFormatError::Signature(_))
    ));
    let mut bytes = fixture("signed-binding");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        SignedSshBinding::from_canonical_bytes(&bytes),
        Err(SshFormatError::Signature(_))
    ));
    assert_eq!(signed().require_ca(&binding.ca_key), Ok(()));
    assert_eq!(
        signed().require_ca(&other.verifying_key().to_bytes()),
        Err(SshFormatError::Authority)
    );
    let mut longer = fixture("signed-binding");
    longer.push(0);
    assert!(SignedSshBinding::from_canonical_bytes(&longer).is_err());
}

#[test]
fn a_request_stays_inside_its_binding() {
    let refused = |change: fn(&mut SshCertificateRequest)| {
        let mut value = request();
        change(&mut value);
        assert_eq!(value.validate(), Err(SshFormatError::Value));
    };
    refused(|r| r.servers = vec![SshServerId::from_bytes([9; 16])]);
    refused(|r| r.servers.push(r.servers[0]));
    refused(|r| r.servers.clear());
    refused(|r| r.source_addresses.clear());
    refused(|r| r.source_addresses = vec!["any".into()]);
    refused(|r| r.source_addresses = vec!["10.0.0.1,10.0.0.2".into()]);
    refused(|r| r.source_addresses = vec!["1.1.1.1".into(); MAX_SOURCE_ADDRESSES + 1]);
    refused(|r| r.subject_key = [0; 32]);
    refused(|r| r.not_after_ms = ISSUED + DEFAULT_BINDING_WINDOW_MS + 1);
    refused(|r| r.not_after_ms = ISSUED);
    request().validate().unwrap();
}

#[test]
fn an_access_update_names_each_server_once_and_closed_tags_only() {
    let mut twice = active();
    twice.servers[1].server = twice.servers[0].server;
    assert_eq!(twice.validate(), Err(SshFormatError::Value));
    let mut bytes = fixture("access-active");
    let tag = 4 + 27 + 16 + 8;
    assert_eq!(bytes[tag], 2);
    bytes[tag] = 6;
    assert_eq!(
        SshAccessUpdate::from_canonical_bytes(&bytes),
        Err(SshFormatError::Value)
    );
    for access in [
        SshAccess::Pending,
        SshAccess::Refused(SshBindingRefusal::NoSourceAddress),
        SshAccess::Revoked,
        SshAccess::Expired,
    ] {
        let update = SshAccessUpdate { access, ..active() };
        let bytes = update.canonical_bytes().unwrap();
        assert_eq!(
            SshAccessUpdate::from_canonical_bytes(&bytes).unwrap(),
            update
        );
    }
}

#[test]
fn a_bound_servers_session_access_matches_the_independent_vectors() {
    let binding = binding();
    let db = SshServerId::of_profile("profile-db");
    let access = binding.target_access(&db).unwrap();
    assert_eq!(access.target.host_key, [0xa1; 32]);
    assert_eq!(access.target.route.to_vec(), fixture("target-route-db"));
    assert_eq!(access.target.principal, id("deploy"));
    assert_eq!(
        access.target.workspace.to_vec(),
        fixture("target-workspace-db")
    );
    assert_eq!(access.authentication.public_key, binding.ca_key);
    assert_eq!(
        access.authentication.credential_revision.to_vec(),
        fixture("target-credential")
    );
    assert_eq!(binding.target_of_access(&access), binding.target(&db));
    assert!(
        binding
            .target_access(&SshServerId::of_profile("other"))
            .is_none()
    );
}

#[test]
fn a_session_access_selects_nothing_in_another_epoch_ca_or_for_a_changed_server_entry() {
    let binding = binding();
    let db = SshServerId::of_profile("profile-db");
    let access = binding.target_access(&db).unwrap();
    let mut newer = binding.clone();
    newer.grant.epoch += 1;
    assert!(newer.target_of_access(&access).is_none());
    let mut other_ca = binding.clone();
    other_ca.ca_key = [0x77; 32];
    assert!(other_ca.target_of_access(&access).is_none());
    for change in [
        |t: &mut SshTarget| t.port = 2200,
        |t: &mut SshTarget| t.host = CloudTextId::new("db2.example.org").unwrap(),
        |t: &mut SshTarget| t.user = CloudTextId::new("root").unwrap(),
        |t: &mut SshTarget| t.host_key_sha256 = [0xb1; 32],
        |t: &mut SshTarget| t.server = SshServerId::from_bytes([9; 16]),
    ] {
        let mut changed = binding.clone();
        change(&mut changed.targets[0]);
        assert!(changed.target_of_access(&access).is_none());
    }
    // The workspace is the account on the server, whatever address or port reaches it.
    let mut moved = binding.targets[0].clone();
    moved.port = 2200;
    assert_eq!(
        moved.workspace_fingerprint(),
        binding.targets[0].workspace_fingerprint()
    );
    assert_ne!(
        moved.route_fingerprint(),
        binding.targets[0].route_fingerprint()
    );
}

#[test]
fn a_source_address_is_an_ip_with_an_optional_canonical_prefix() {
    for good in [
        "203.0.113.7",
        "203.0.113.0/24",
        "0.0.0.0/0",
        "198.51.100.1/32",
        "2001:db8::1",
        "2001:db8::/32",
        "::/128",
    ] {
        assert!(super::is_source_address(good), "{good} is an address");
    }
    for bad in [
        "203.0.113.7/",
        "203.0.113.7/33",
        "203.0.113.7/+8",
        "203.0.113.7/08",
        "203.0.113.7/-1",
        "203.0.113.7/ 8",
        "2001:db8::/129",
        "2001:db8::/",
        "host.example",
        "",
        "/24",
    ] {
        assert!(!super::is_source_address(bad), "{bad:?} is not an address");
    }
}
