use super::*;
use nocterm_hub_model::cloud::{CloudNamespace, CloudTextId, RunnerCoordinate};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn coordinate() -> Result<AccountCatalogCoordinate, AccountCatalogError> {
    AccountCatalogCoordinate::new(
        CloudNamespace {
            hub_instance_id: CloudTextId::new("hub")?,
            account_id: CloudTextId::new("account")?,
        },
        [7; 32],
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        4,
    )
}
#[test]
fn native_catalog_opens_independent_python_bytes_without_an_account_root_or_chat_key() -> TestResult
{
    let runner = RunnerEncryptionKey::from_seed(&[0x22; 32]);
    let bytes =
        hex::decode(include_str!("../../../../../fixtures/cloud-catalog-v1/context.hex").trim())?;
    let context = AccountCatalogCoordinate::from_canonical_bytes(&bytes)?;
    assert_eq!(context, coordinate()?);
    assert_eq!(context.canonical_bytes()?, bytes);
    let key = NativeCatalogKey::for_runner(&runner, &context)?;
    let ciphertext =
        hex::decode(include_str!("../../../../../fixtures/cloud-catalog-v1/catalog.hex").trim())?;
    assert_eq!(&*key.open_catalog(&ciphertext)?, b"public catalog fixture");
    let restored = RunnerEncryptionKey::from_seed(&runner.seed());
    assert_eq!(
        &*NativeCatalogKey::for_runner(&restored, &context)?.open_catalog(&ciphertext)?,
        b"public catalog fixture"
    );
    for length in 0..bytes.len() {
        assert!(AccountCatalogCoordinate::from_canonical_bytes(&bytes[..length]).is_err());
    }
    let mut suffix = bytes;
    suffix.push(0);
    assert!(AccountCatalogCoordinate::from_canonical_bytes(&suffix).is_err());
    assert!(!format!("{key:?}").contains(&hex::encode([0x22; 32])));
    Ok(())
}
#[test]
fn catalog_authentication_binds_account_runner_epoch_revision_and_purpose() -> TestResult {
    let runner = RunnerEncryptionKey::generate()?;
    let context = coordinate()?;
    let key = NativeCatalogKey::for_runner(&runner, &context)?;
    let ciphertext = key.seal_catalog(b"native catalog metadata")?;
    assert!(
        NativeCatalogKey::for_runner(&RunnerEncryptionKey::generate()?, &context)?
            .open_catalog(&ciphertext)
            .is_err()
    );
    let mut namespace = context.namespace().clone();
    namespace.account_id = CloudTextId::new("other")?;
    let mut different = context.runner();
    different.id = [9; 16];
    let mut epoch = context.runner();
    epoch.key_epoch += 1;
    for changed in [
        AccountCatalogCoordinate::new(
            namespace,
            context.account_key_fingerprint(),
            context.runner(),
            4,
        )?,
        AccountCatalogCoordinate::new(
            context.namespace().clone(),
            context.account_key_fingerprint(),
            different,
            4,
        )?,
        AccountCatalogCoordinate::new(
            context.namespace().clone(),
            context.account_key_fingerprint(),
            epoch,
            4,
        )?,
        AccountCatalogCoordinate::new(
            context.namespace().clone(),
            context.account_key_fingerprint(),
            context.runner(),
            5,
        )?,
        AccountCatalogCoordinate::new(context.namespace().clone(), [8; 32], context.runner(), 4)?,
    ] {
        assert!(
            NativeCatalogKey::for_runner(&runner, &changed)?
                .open_catalog(&ciphertext)
                .is_err()
        );
    }
    for index in 0..ciphertext.len() {
        let mut changed = ciphertext.clone();
        changed[index] ^= 1;
        assert!(key.open_catalog(&changed).is_err());
    }
    for purpose in 1..15 {
        let mut changed = ciphertext.clone();
        changed[1] = purpose;
        assert!(key.open_catalog(&changed).is_err());
    }
    assert!(key.seal_catalog(b"").is_err());
    assert!(
        key.seal_catalog(&vec![0; MAX_ACCOUNT_CATALOG_BYTES + 1])
            .is_err()
    );
    assert!(
        AccountCatalogCoordinate::new(
            context.namespace().clone(),
            context.account_key_fingerprint(),
            context.runner(),
            0
        )
        .is_err()
    );
    Ok(())
}
