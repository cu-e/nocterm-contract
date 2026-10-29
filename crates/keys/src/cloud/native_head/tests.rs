use super::*;
use nocterm_hub_model::cloud::{CloudTextId, RunnerCoordinate};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-native-head-v1")
        .join(format!("{name}.hex"));
    Ok(hex::decode(std::fs::read_to_string(path)?.trim())?)
}
#[test]
fn independent_native_head_boxes_open_with_retained_runner_identity_without_chat_key() -> TestResult
{
    let identity = RunnerEncryptionKey::from_seed(&[0x41; 32]);
    for suffix in ["", "-no-writer"] {
        let coordinate =
            NativeChatHeadCoordinate::from_canonical_bytes(&fixture(&format!("context{suffix}"))?)?;
        let key = NativeChatHeadKey::for_runner(&identity, &coordinate)?;
        assert_eq!(
            key.open_head(&fixture(&format!("head{suffix}"))?)?
                .as_slice(),
            fixture("plaintext")?
        );
        let sealed = key.seal_head(b"actual metadata after tombstone")?;
        let restored = RunnerEncryptionKey::from_seed(&identity.seed());
        let restored = NativeChatHeadKey::for_runner(&restored, &coordinate)?;
        assert_eq!(
            restored.open_head(&sealed)?.as_slice(),
            b"actual metadata after tombstone"
        );
        assert_eq!(format!("{key:?}"), "NativeChatHeadKey(…)");
    }
    Ok(())
}
#[test]
fn moving_native_head_across_any_exact_source_writer_or_revision_fails() -> TestResult {
    let identity = RunnerEncryptionKey::from_seed(&[0x41; 32]);
    let original = NativeChatHeadCoordinate::from_canonical_bytes(&fixture("context")?)?;
    let sealed = fixture("head")?;
    for changed in 0..8 {
        let mut namespace = original.namespace().clone();
        let mut fingerprint = original.account_key_fingerprint();
        let mut runner = original.runner();
        let mut chat = original.chat_id();
        let mut writer = original.current_writer();
        let mut revision = original.metadata_revision();
        match changed {
            0 => namespace.hub_instance_id = CloudTextId::new("other-hub")?,
            1 => namespace.account_id = CloudTextId::new("other-account")?,
            2 => fingerprint[0] ^= 1,
            3 => {
                runner = RunnerCoordinate {
                    id: [4; 16],
                    ..runner
                }
            }
            4 => runner.key_epoch += 1,
            5 => chat[0] ^= 1,
            6 => writer = Some(4),
            _ => revision += 1,
        }
        let coordinate =
            NativeChatHeadCoordinate::new(namespace, fingerprint, runner, chat, writer, revision)?;
        assert!(
            NativeChatHeadKey::for_runner(&identity, &coordinate)?
                .open_head(&sealed)
                .is_err()
        );
    }
    let another = RunnerEncryptionKey::from_seed(&[0x42; 32]);
    assert!(
        NativeChatHeadKey::for_runner(&another, &original)?
            .open_head(&sealed)
            .is_err()
    );
    let none = NativeChatHeadCoordinate::from_canonical_bytes(&fixture("context-no-writer")?)?;
    assert!(
        NativeChatHeadKey::for_runner(&identity, &none)?
            .open_head(&sealed)
            .is_err()
    );
    Ok(())
}
#[test]
fn native_head_bounds_and_purpose_refuse_malformed_or_tampered_cells() -> TestResult {
    let identity = RunnerEncryptionKey::from_seed(&[0x41; 32]);
    let coordinate = NativeChatHeadCoordinate::from_canonical_bytes(&fixture("context")?)?;
    let key = NativeChatHeadKey::for_runner(&identity, &coordinate)?;
    assert!(matches!(
        key.seal_head(&[]),
        Err(NativeChatHeadError::Bounds)
    ));
    assert!(matches!(
        key.seal_head(&vec![0; MAX_NATIVE_CHAT_HEAD_BYTES + 1]),
        Err(NativeChatHeadError::Bounds)
    ));
    for bytes in [
        vec![],
        vec![0; 42],
        vec![0; MAX_NATIVE_CHAT_HEAD_CIPHERTEXT_BYTES + 1],
        fixture("wrong-purpose")?,
    ] {
        assert!(key.open_head(&bytes).is_err());
    }
    let sealed = fixture("head")?;
    for end in 0..sealed.len() {
        assert!(key.open_head(&sealed[..end]).is_err());
    }
    for offset in [0, 1, 2, sealed.len() - 1] {
        let mut changed = sealed.clone();
        changed[offset] ^= 1;
        assert!(key.open_head(&changed).is_err());
    }
    let largest = vec![0x6b; MAX_NATIVE_CHAT_HEAD_BYTES];
    let sealed = key.seal_head(&largest)?;
    assert_eq!(sealed.len(), MAX_NATIVE_CHAT_HEAD_CIPHERTEXT_BYTES);
    assert_eq!(key.open_head(&sealed)?.as_slice(), largest);
    Ok(())
}
