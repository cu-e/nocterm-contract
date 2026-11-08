use nocterm_keys::CollectionKey;
use serde_json::{Value, json};

use super::*;

const ED25519: &str = include_str!("fixtures/ed25519");
const ED25519_PUB: &str = include_str!("fixtures/ed25519.pub");
const ED25519_ENCRYPTED: &str = include_str!("fixtures/ed25519-encrypted");
const ED25519_ENCRYPTED_PUB: &str = include_str!("fixtures/ed25519-encrypted.pub");
const RSA_1024: &str = include_str!("fixtures/rsa-1024");
const PASSPHRASE: &str = "correct horse";

fn collection() -> (WebCollectionKey, CollectionKey) {
    let native = CollectionKey::generate().unwrap();
    let account = nocterm_keys::AccountKey::generate().unwrap();
    let wrapped = native.seal_for(&account, "col").unwrap();
    let web = WebCollectionKey {
        collection_id: "col".into(),
        key: CollectionKey::open(&account, "col", &wrapped).unwrap(),
    };
    (web, native)
}

/// The record as a native client opens it.
fn opened(native: &CollectionKey, object_id: &str, sealed: &[u8]) -> Value {
    let plain = native.open_object("col", object_id, KIND, sealed).unwrap();
    serde_json::from_slice(&plain).unwrap()
}

/// `"<algorithm> <base64>"` of a `.pub` line.
fn canonical(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn a_password_is_bound_to_the_address_it_signs_in_to() {
    let (web, native) = collection();
    let sealed = web
        .password("c1", "prod.example.com", 2222, "ops", "s3cret")
        .unwrap();
    assert_eq!(
        opened(&native, "c1", &sealed),
        json!({
            "v": 1,
            "label": "ops@prod.example.com:2222",
            "binding": {
                "kind": "password",
                "target": {"host": "prod.example.com", "port": 2222, "user": "ops"}
            },
            "secret": "s3cret"
        })
    );
    let sealed = web.password("c2", "web.example", 22, "root", "pw").unwrap();
    let record = opened(&native, "c2", &sealed);
    assert_eq!(record["label"], "root@web.example");
    assert_eq!(
        record["binding"]["target"],
        json!({"host": "web.example", "user": "root"})
    );
}

#[test]
fn a_private_key_is_kept_without_its_passphrase_and_bound_to_its_public_half() {
    let (web, native) = collection();
    let key = web.ssh_key("k1", "prod", ED25519, None).unwrap();
    assert_eq!(key.public_key, canonical(ED25519_PUB));
    // `ssh-keygen -lf` of the fixture.
    assert_eq!(
        key.fingerprint,
        "SHA256:IcTCIphGPK3d9UZTQNsCnzJYrbdJNLARbB2m/D+T+io"
    );
    let record = opened(&native, "k1", &key.ciphertext);
    assert_eq!(record["label"], "prod");
    assert_eq!(
        record["binding"],
        json!({"kind": "private_key", "public_key": canonical(ED25519_PUB)})
    );

    let protected = web
        .ssh_key("k2", "prod", ED25519_ENCRYPTED, Some(PASSPHRASE))
        .unwrap();
    assert_eq!(protected.public_key, canonical(ED25519_ENCRYPTED_PUB));
    let secret = opened(&native, "k2", &protected.ciphertext)["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let kept = PrivateKey::from_openssh(&secret).unwrap();
    assert!(!kept.is_encrypted(), "the vault's encryption protects it");
    assert_eq!(
        canonical(&kept.public_key().to_openssh().unwrap()),
        protected.public_key
    );
}

#[test]
fn a_key_native_clients_refuse_is_not_kept() {
    let (web, _) = collection();
    let refused =
        |text: &str, passphrase: Option<&str>| match web.ssh_key("k", "x", text, passphrase) {
            Err(WebError::SshKey(refused)) => refused,
            other => panic!("kept: {other:?}"),
        };
    assert!(matches!(
        refused(ED25519_ENCRYPTED, None),
        KeyRefused::PassphraseRequired
    ));
    assert!(matches!(
        refused(ED25519_ENCRYPTED, Some("wrong")),
        KeyRefused::WrongPassphrase
    ));
    assert!(matches!(
        refused(RSA_1024, None),
        KeyRefused::TooWeak { bits: 1024 }
    ));
    assert!(matches!(
        refused("not a key", None),
        KeyRefused::Malformed(_)
    ));
}
