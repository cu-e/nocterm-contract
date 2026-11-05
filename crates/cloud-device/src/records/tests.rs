#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]
use super::*;
use crate::AccountScope;
use nocterm_hub_model::cloud::RunnerCoordinate;
use nocterm_keys::{AccountKey, CollectionKey, cloud::ChatKey};
use sha2::Digest as _;

/// One `key=value` fixture produced by the native encoder.
struct Vectors(&'static str);
impl Vectors {
    fn text(&self, key: &str) -> &'static str {
        self.0
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("missing {key}"))
    }
    fn bytes(&self, key: &str) -> Vec<u8> {
        hex::decode(self.text(key)).unwrap()
    }
    fn array<const N: usize>(&self, key: &str) -> [u8; N] {
        self.bytes(key).try_into().unwrap()
    }
}
const HUB_TRUST: Vectors = Vectors(include_str!(
    "../../../../fixtures/cloud-device-v1/desktop-hub-trust.txt"
));
const REGISTRY: Vectors = Vectors(include_str!(
    "../../../../fixtures/cloud-device-v1/desktop-runner-registry.txt"
));
const MATERIAL: Vectors = Vectors(include_str!(
    "../../../../fixtures/cloud-device-v1/desktop-chat-material.txt"
));

fn scope(v: &Vectors) -> AccountScope {
    AccountScope::from_parts(
        v.text("hub_instance"),
        v.array("authority_fingerprint"),
        v.text("account"),
        v.array("account_key_digest"),
    )
    .unwrap()
}
fn selector() -> ChatSelector {
    let v = &MATERIAL;
    ChatSelector::new(
        scope(v),
        RunnerCoordinate {
            id: v.array("runner"),
            key_epoch: v.text("runner_epoch").parse().unwrap(),
        },
        v.array("chat"),
        v.text("key_epoch").parse().unwrap(),
        RunnerPins {
            encryption: v.array("encryption"),
            signing: v.array("signing"),
            proof: v.array("proof"),
        },
    )
    .unwrap()
}

#[test]
fn a_hub_trust_record_encodes_the_native_bytes_and_reads_its_origin_back() {
    let v = &HUB_TRUST;
    let record = HubTrustRecord::new(
        v.text("origin"),
        v.text("raw_hub"),
        v.text("account"),
        v.array("account_key_digest"),
        v.array("authority"),
    )
    .unwrap();
    assert_eq!(record.context().unwrap(), v.bytes("context"));
    assert_eq!(record.collection_id().unwrap(), v.text("collection_id"));
    assert_eq!(record.encode().unwrap().as_slice(), v.bytes("plaintext"));
    let decoded = HubTrustRecord::decode(&v.bytes("plaintext")).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.origin(), "hub.example.org:7443");
    let scope = decoded.scope().unwrap();
    assert_eq!(scope.hub_instance(), v.text("namespace"));
    assert_eq!(
        scope.authority_fingerprint(),
        v.array::<32>("authority_fingerprint")
    );
}

#[test]
fn a_hub_trust_record_with_trailing_or_missing_bytes_is_refused() {
    let mut plaintext = HUB_TRUST.bytes("plaintext");
    plaintext.push(0);
    assert!(matches!(
        HubTrustRecord::decode(&plaintext),
        Err(CloudDeviceError::Format)
    ));
    plaintext.truncate(plaintext.len() - 2);
    assert!(matches!(
        HubTrustRecord::decode(&plaintext),
        Err(CloudDeviceError::Format)
    ));
    plaintext = HUB_TRUST.bytes("plaintext");
    plaintext[3] ^= 1;
    assert!(matches!(
        HubTrustRecord::decode(&plaintext),
        Err(CloudDeviceError::Format)
    ));
}

#[test]
fn a_hub_trust_record_matches_only_its_hub_account_and_key() {
    let key = [9u8; 32];
    let digest: [u8; 32] = sha2::Sha256::digest(key).into();
    let record = HubTrustRecord::new("h:1", "raw", "acc", digest, [1; 32]).unwrap();
    assert!(record.matches("raw", "acc", &key));
    assert!(!record.matches("raw-2", "acc", &key));
    assert!(!record.matches("raw", "acc-2", &key));
    assert!(!record.matches("raw", "acc", &[8; 32]));
}

#[test]
fn a_hub_trust_object_opens_only_in_the_collection_its_context_derives() {
    let key = CollectionKey::generate().unwrap();
    let record = HubTrustRecord::decode(&HUB_TRUST.bytes("plaintext")).unwrap();
    let collection = record.collection_id().unwrap();
    let sealed = key
        .seal_object(
            &collection,
            HUB_TRUST_OBJECT,
            HUB_TRUST_KIND,
            &record.encode().unwrap(),
        )
        .unwrap();
    let object = StoredObject {
        collection_id: &collection,
        object_id: HUB_TRUST_OBJECT,
        kind: HUB_TRUST_KIND,
        version: 1,
        deleted: false,
        ciphertext: &sealed,
    };
    assert_eq!(HubTrustRecord::open(&key, &object).unwrap(), record);
    let deleted = StoredObject {
        deleted: true,
        ..object
    };
    assert!(matches!(
        HubTrustRecord::open(&key, &deleted),
        Err(CloudDeviceError::Deleted)
    ));
    let moved = key
        .seal_object(
            "8e14b6c7-35e6-84ad-b67d-000000000000",
            HUB_TRUST_OBJECT,
            HUB_TRUST_KIND,
            &record.encode().unwrap(),
        )
        .unwrap();
    let elsewhere = StoredObject {
        collection_id: "8e14b6c7-35e6-84ad-b67d-000000000000",
        ciphertext: &moved,
        ..object
    };
    assert!(matches!(
        HubTrustRecord::open(&key, &elsewhere),
        Err(CloudDeviceError::Binding)
    ));
    let second = StoredObject {
        version: 2,
        ..object
    };
    assert!(matches!(
        HubTrustRecord::open(&key, &second),
        Err(CloudDeviceError::ObjectVersion(2))
    ));
}

fn registry_rows() -> Vec<TrustedRunner> {
    let row = |id: u8, epoch: u64, label: &str| {
        TrustedRunner::new(
            RunnerCoordinate {
                id: [id; 16],
                key_epoch: epoch,
            },
            RunnerPins {
                encryption: [id + 0x40; 32],
                signing: [id + 0x50; 32],
                proof: [id + 0x60; 32],
            },
            label,
        )
        .unwrap()
    };
    vec![row(2, 3, "Rig \u{3b2}"), row(1, 1, "Runner A")]
}

#[test]
fn a_runner_registry_encodes_the_native_bytes_in_runner_order() {
    let v = &REGISTRY;
    let scope = scope(v);
    assert_eq!(RunnerRegistry::context(&scope).unwrap(), v.bytes("context"));
    assert_eq!(
        RunnerRegistry::collection_id(&scope).unwrap(),
        v.text("collection_id")
    );
    let registry = RunnerRegistry::new(scope.clone(), registry_rows()).unwrap();
    assert_eq!(registry.version(), 2);
    assert_eq!(registry.encode().unwrap().as_slice(), v.bytes("plaintext"));
    let decoded = RunnerRegistry::decode(&scope, 2, &v.bytes("plaintext")).unwrap();
    assert_eq!(decoded, registry);
    assert_eq!(decoded.runner(&[2; 16]).unwrap().label(), "Rig \u{3b2}");
}

#[test]
fn a_runner_registry_of_another_scope_version_or_order_is_refused() {
    let v = &REGISTRY;
    let plaintext = v.bytes("plaintext");
    let other = AccountScope::from_parts("other", [0x33; 32], "account-0001", [0x11; 32]).unwrap();
    assert!(matches!(
        RunnerRegistry::decode(&other, 2, &plaintext),
        Err(CloudDeviceError::Binding)
    ));
    assert!(matches!(
        RunnerRegistry::decode(&scope(v), 3, &plaintext),
        Err(CloudDeviceError::Format)
    ));
    // Swap the two rows' runner ids so they are no longer sorted.
    let context = v.bytes("context").len() + 9;
    let mut swapped = plaintext.clone();
    swapped[context..context + 16].copy_from_slice(&[3; 16]);
    assert!(matches!(
        RunnerRegistry::decode(&scope(v), 2, &swapped),
        Err(CloudDeviceError::Format)
    ));
    let mut control = plaintext;
    let last = control.len() - 1;
    control[last] = b'\n';
    assert!(RunnerRegistry::decode(&scope(v), 2, &control).is_err());
}

#[test]
fn chat_material_and_grant_records_encode_the_native_bytes_and_identifiers() {
    let v = &MATERIAL;
    let selector = selector();
    assert_eq!(
        selector.coordinate().unwrap().canonical_bytes().unwrap(),
        v.bytes("coordinate")
    );
    assert_eq!(selector.object_id().unwrap(), v.text("object_id"));
    assert_eq!(
        ChatMaterialRecord::collection_id(selector.scope()).unwrap(),
        v.text("material_collection_id")
    );
    assert_eq!(
        ChatGrantRecord::collection_id(selector.scope()).unwrap(),
        v.text("grant_collection_id")
    );
    let material = ChatMaterialRecord::new(selector.clone(), v.bytes("wrapped")).unwrap();
    assert_eq!(
        material.encode().unwrap().as_slice(),
        v.bytes("material_plaintext")
    );
    assert_eq!(
        ChatMaterialRecord::decode(selector.clone(), &v.bytes("material_plaintext")).unwrap(),
        material
    );
    let grant =
        ChatGrantRecord::new(v.array("grant_publication_id"), v.bytes("grant_ciphertext")).unwrap();
    assert_eq!(grant.encode(), v.bytes("grant_plaintext"));
    assert_eq!(
        ChatGrantRecord::decode(&v.bytes("grant_plaintext")).unwrap(),
        grant
    );
}

#[test]
fn chat_material_for_other_pins_or_epoch_is_refused() {
    let plaintext = MATERIAL.bytes("material_plaintext");
    let mut pins = selector().pins();
    pins.signing = [0; 32];
    let other = ChatSelector::new(
        selector().scope().clone(),
        selector().runner(),
        selector().chat_id(),
        1,
        pins,
    )
    .unwrap();
    assert!(matches!(
        ChatMaterialRecord::decode(other, &plaintext),
        Err(CloudDeviceError::Binding)
    ));
    let later = ChatSelector::new(
        selector().scope().clone(),
        selector().runner(),
        selector().chat_id(),
        2,
        selector().pins(),
    )
    .unwrap();
    assert!(ChatMaterialRecord::decode(later, &plaintext).is_err());
}

#[test]
fn a_wrapped_chat_key_round_trips_through_its_sealed_object() {
    let account = AccountKey::generate().unwrap();
    let collection_key = CollectionKey::generate().unwrap();
    let chat = ChatKey::generate().unwrap();
    let record = ChatMaterialRecord::wrap(selector(), &chat, &account).unwrap();
    let sealed = record.seal(&collection_key).unwrap();
    let collection = ChatMaterialRecord::collection_id(selector().scope()).unwrap();
    let id = selector().object_id().unwrap();
    let object = StoredObject {
        collection_id: &collection,
        object_id: &id,
        kind: CHAT_MATERIAL_KIND,
        version: 1,
        deleted: false,
        ciphertext: &sealed,
    };
    let opened = ChatMaterialRecord::open(&collection_key, selector(), &object, &account).unwrap();
    assert_eq!(opened, record);
    let stranger = AccountKey::generate().unwrap();
    assert!(ChatMaterialRecord::open(&collection_key, selector(), &object, &stranger).is_err());
}
