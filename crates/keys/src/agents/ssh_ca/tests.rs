#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use nocterm_hub_model::cloud::{
    ChatCoordinate, CloudNamespace, CloudTextId, RunnerCoordinate,
    payload::GrantReference,
    ssh::{BindingWindow, DEFAULT_BINDING_WINDOW_MS, DEFAULT_CERTIFICATE_VALIDITY_MS, SshTarget},
};

const ISSUED: i64 = 1_800_000_000_000;

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-ssh-v1")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}
fn hex_fixture(name: &str) -> Vec<u8> {
    hex::decode(fixture(&format!("{name}.hex")).trim()).unwrap()
}
fn ca() -> UserCa {
    UserCa::from_seed([0x91; 32])
}
fn id(text: &str) -> CloudTextId {
    CloudTextId::new(text).unwrap()
}
fn db() -> SshServerId {
    SshServerId::of_profile("profile-db")
}
/// The binding of `fixtures/cloud-ssh-v1/binding.hex`.
fn binding() -> SshBinding {
    SshBinding {
        chat: ChatCoordinate::new(
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
        .unwrap(),
        grant: GrantReference {
            id: [0x33; 16],
            epoch: u64::try_from(ISSUED).unwrap(),
        },
        window: BindingWindow {
            issued_at_ms: ISSUED,
            expires_at_ms: ISSUED + DEFAULT_BINDING_WINDOW_MS,
        },
        ca_key: ca().public_key(),
        targets: vec![
            SshTarget {
                server: db(),
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
/// The certificate of `fixtures/cloud-ssh-v1/openssh/agent-cert.pub`.
fn spec() -> CertificateSpec {
    CertificateSpec {
        principals: vec![principal_for(&ca().public_key(), &db())],
        key_id: format!(
            "nocterm-chat-{}-{}",
            hex::encode([0x81; 16]),
            hex::encode([0x44; 16])
        ),
        subject_key: hex_fixture("subject-public").try_into().unwrap(),
        serial: 0x0102_0304_0506_0708,
        valid_after_ms: ISSUED,
        valid_before_ms: ISSUED + DEFAULT_CERTIFICATE_VALIDITY_MS,
        source_addresses: vec!["203.0.113.7/32".into(), "2001:db8::1".into()],
    }
}
const NONCE: [u8; 32] = [0x66; 32];

#[test]
fn the_ca_and_its_principals_match_the_vectors_and_the_native_derivation() {
    assert_eq!(ca().public_key().to_vec(), hex_fixture("ca-public"));
    let digest = Sha256::digest(ca().public_key());
    let tag = hex::encode(&digest[..8]);
    assert_eq!(
        agent_principal(&ca().public_key()),
        format!("nocterm-agent-{tag}")
    );
    let principal = principal_for(&ca().public_key(), &db());
    assert_eq!(
        principal,
        format!(
            "nocterm-agent-{tag}-{}",
            hex::encode(&hex_fixture("server-db")[..8])
        )
    );
    assert!(principal.len() <= MAX_PRINCIPAL_BYTES);
    assert!(ca().fingerprint().starts_with("SHA256:"));
    assert_eq!(
        sha256_of_fingerprint(&ca().fingerprint()).map(|d| d.len()),
        Some(32)
    );
    assert_eq!(sha256_of_fingerprint("MD5:aa"), None);
    assert!(
        ca().openssh_public_key()
            .unwrap()
            .starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")
    );
    assert!(!format!("{:?}", ca()).contains(&hex::encode([0x91; 32])));
}

#[test]
fn the_ca_signs_the_independent_binding_vector_and_only_its_own_bindings() {
    let signed = ca().sign_binding(binding()).unwrap();
    assert_eq!(
        signed.canonical_bytes().unwrap(),
        hex_fixture("signed-binding")
    );
    let mut other = binding();
    other.ca_key = UserCa::from_seed([0x92; 32]).public_key();
    assert_eq!(ca().sign_binding(other), Err(CaError::OtherCa));
    let mut invalid = binding();
    invalid.targets.clear();
    assert!(matches!(
        ca().sign_binding(invalid),
        Err(CaError::Binding(_))
    ));
}

#[test]
fn a_certificate_names_only_its_principals_a_pty_and_its_source_and_matches_the_openssh_vector() {
    let issued = ca().issue(&spec(), NONCE).unwrap();
    assert_eq!(
        issued.openssh().unwrap(),
        fixture("openssh/agent-cert.pub").trim(),
        "the certificate ssh-keygen -L checked (fixtures/cloud-ssh-v1/openssh)"
    );
    let facts = CertificateFacts::read(issued.as_bytes(), &ca().public_key()).unwrap();
    assert_eq!(facts.principals, spec().principals);
    assert_eq!(facts.subject_key, spec().subject_key);
    assert_eq!(facts.source_addresses, spec().source_addresses);
    assert_eq!(facts.serial, spec().serial);
    assert_eq!(facts.key_id, spec().key_id);
    let start = u64::try_from(ISSUED / 1000).unwrap();
    assert_eq!(facts.valid_after, start - BACKDATE_SECONDS);
    assert_eq!(facts.valid_before, start + 8 * 3600);
    let other = UserCa::from_seed([0x92; 32]).public_key();
    assert_eq!(
        CertificateFacts::read(issued.as_bytes(), &other),
        Err(CertificateError::Restrictions)
    );
    let mut tampered = issued.into_bytes();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    assert!(CertificateFacts::read(&tampered, &ca().public_key()).is_err());
}

#[test]
fn unsafe_certificate_specs_are_refused_before_signing() {
    use CertificateError as E;
    let refused = |change: fn(&mut CertificateSpec), expected: CertificateError| {
        let mut value = spec();
        change(&mut value);
        assert_eq!(ca().issue(&value, NONCE), Err(expected));
    };
    refused(|s| s.principals.clear(), E::Principal);
    refused(|s| s.principals = vec!["root".into()], E::Principal);
    refused(|s| s.principals.push(s.principals[0].clone()), E::Principal);
    refused(
        |s| s.principals = vec![format!("nocterm-agent-{}", "a".repeat(60))],
        E::Principal,
    );
    refused(|s| s.key_id = "two words".into(), E::KeyId);
    refused(|s| s.key_id.clear(), E::KeyId);
    refused(|s| s.subject_key = [0; 32], E::Subject);
    refused(
        |s| s.valid_before_ms = s.valid_after_ms + MAX_CERTIFICATE_VALIDITY_MS + 1,
        E::Validity,
    );
    refused(|s| s.valid_before_ms = s.valid_after_ms, E::Validity);
    refused(|s| s.valid_after_ms = -1, E::Validity);
    refused(|s| s.source_addresses.clear(), E::SourceAddress);
    refused(|s| s.source_addresses = vec!["*".into()], E::SourceAddress);
    refused(
        |s| s.source_addresses = vec!["1.1.1.1".into(); 9],
        E::SourceAddress,
    );
    let mut longest = spec();
    longest.valid_before_ms = longest.valid_after_ms + MAX_CERTIFICATE_VALIDITY_MS;
    assert!(ca().issue(&longest, NONCE).is_ok());
}

#[test]
fn the_ca_document_keeps_the_native_format_1_and_refuses_others() {
    let document =
        CaDocument::new(ca(), ISSUED).replaced(UserCa::from_seed([0x93; 32]), ISSUED + 1);
    let encoded = document.encode().unwrap();
    assert_eq!(
        std::str::from_utf8(&encoded).unwrap(),
        fixture("ca-document.json").trim(),
        "the JSON the native client writes (format 1)"
    );
    let decoded = CaDocument::decode(&encoded).unwrap();
    assert_eq!(
        decoded.ca().public_key(),
        UserCa::from_seed([0x93; 32]).public_key()
    );
    assert_eq!(decoded.retired(), &[ca().public_key()]);
    assert_eq!(decoded.created_at_ms(), ISSUED + 1);
    let minimal =
        r#"{"format":1,"seed":"kZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZE=","created_at_ms":5}"#;
    assert!(
        CaDocument::decode(minimal.as_bytes())
            .unwrap()
            .retired()
            .is_empty()
    );
    for bad in [
        minimal.replace("\"format\":1", "\"format\":2"),
        minimal.replace("kZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZE=", "kZE="),
        "not json".to_owned(),
    ] {
        assert!(CaDocument::decode(bad.as_bytes()).is_err(), "{bad}");
    }
    let mut many = CaDocument::new(ca(), 1);
    for seed in 0..=u8::try_from(MAX_RETIRED).unwrap() {
        many = many.replaced(UserCa::from_seed([seed; 32]), 2);
    }
    assert_eq!(many.retired().len(), MAX_RETIRED);
    assert!(!format!("{many:?}").contains("kZGR"));
}

#[test]
#[ignore = "writes the OpenSSH and CA document fixtures; run explicitly after a format change"]
fn write_openssh_fixtures() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/cloud-ssh-v1");
    std::fs::create_dir_all(root.join("openssh")).unwrap();
    let issued = ca().issue(&spec(), NONCE).unwrap();
    std::fs::write(
        root.join("openssh/agent-cert.pub"),
        issued.openssh().unwrap() + "\n",
    )
    .unwrap();
    std::fs::write(
        root.join("openssh/ca.pub"),
        ca().openssh_public_key().unwrap() + "\n",
    )
    .unwrap();
    let document =
        CaDocument::new(ca(), ISSUED).replaced(UserCa::from_seed([0x93; 32]), ISSUED + 1);
    let encoded = document.encode().unwrap();
    std::fs::write(
        root.join("ca-document.json"),
        [encoded.as_slice(), b"\n"].concat(),
    )
    .unwrap();
}
