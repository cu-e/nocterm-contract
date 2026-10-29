use super::*;
use crate::cloud::CloudTextId;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-native-head-v1")
        .join(format!("{name}.hex"));
    Ok(hex::decode(std::fs::read_to_string(path)?.trim())?)
}
#[test]
fn independent_native_head_context_preserves_real_chat_and_optional_writer() -> TestResult {
    for (name, writer) in [("context", Some(3)), ("context-no-writer", None)] {
        let bytes = fixture(name)?;
        let value = NativeChatHeadCoordinate::from_canonical_bytes(&bytes)?;
        assert_eq!(value.canonical_bytes()?, bytes);
        assert_eq!(value.namespace().hub_instance_id.as_str(), "hub");
        assert_eq!(value.namespace().account_id.as_str(), "account");
        assert_eq!(value.account_key_fingerprint(), [7; 32]);
        assert_eq!(
            value.runner(),
            RunnerCoordinate {
                id: [2; 16],
                key_epoch: 3
            }
        );
        assert_eq!(value.chat_id(), [0x81; 16]);
        assert_eq!(value.current_writer(), writer);
        assert_eq!(value.metadata_revision(), 9);
    }
    Ok(())
}
#[test]
fn native_head_context_refuses_zero_epochs_unknown_options_and_suffixes() -> TestResult {
    let bytes = fixture("context")?;
    let value = NativeChatHeadCoordinate::from_canonical_bytes(&bytes)?;
    for (epoch, writer, revision) in [(0, Some(3), 9), (3, Some(0), 9), (3, None, 0)] {
        assert!(
            NativeChatHeadCoordinate::new(
                value.namespace().clone(),
                value.account_key_fingerprint(),
                RunnerCoordinate {
                    id: [2; 16],
                    key_epoch: epoch
                },
                value.chat_id(),
                writer,
                revision
            )
            .is_err()
        );
    }
    for end in 0..bytes.len() {
        assert!(NativeChatHeadCoordinate::from_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(NativeChatHeadCoordinate::from_canonical_bytes(&extra).is_err());
    let mut unknown = bytes.clone();
    let flag = unknown.len() - 17;
    unknown[flag] = 2;
    assert!(NativeChatHeadCoordinate::from_canonical_bytes(&unknown).is_err());
    assert!(
        NativeChatHeadCoordinate::from_canonical_bytes(&vec![
            0;
            MAX_NATIVE_CHAT_HEAD_CONTEXT_BYTES + 1
        ])
        .is_err()
    );
    Ok(())
}
#[test]
fn largest_valid_native_head_scope_stays_within_complete_context_bound() -> TestResult {
    let namespace = CloudNamespace {
        hub_instance_id: CloudTextId::new("h".repeat(128))?,
        account_id: CloudTextId::new("a".repeat(128))?,
    };
    let value = NativeChatHeadCoordinate::new(
        namespace,
        [7; 32],
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: u64::MAX,
        },
        [0x81; 16],
        Some(u64::MAX),
        u64::MAX,
    )?;
    let bytes = value.canonical_bytes()?;
    assert!(bytes.len() <= MAX_NATIVE_CHAT_HEAD_CONTEXT_BYTES);
    assert_eq!(
        NativeChatHeadCoordinate::from_canonical_bytes(&bytes)?,
        value
    );
    Ok(())
}
