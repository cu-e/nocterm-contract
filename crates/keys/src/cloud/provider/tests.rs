use super::*;
use crate::cloud::RunnerSigningKey;
use nocterm_hub_model::cloud::{
    CloudNamespace, CloudTextId, RunnerCoordinate,
    provider::{BootDescriptor, BootWindow, SignedBootDescriptor},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn descriptor(boot: &RunnerBootKey) -> Result<BootDescriptor, ProviderLeaseError> {
    BootDescriptor::new(
        CloudNamespace {
            hub_instance_id: CloudTextId::new("hub")?,
            account_id: CloudTextId::new("account")?,
        },
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        [4; 16],
        boot.public_key().to_bytes(),
        BootWindow {
            issued_at_ms: 100_000,
            expires_at_ms: 160_000,
        },
    )
}
fn context(boot: BootDescriptor) -> Result<ProviderLeaseContext, ProviderLeaseError> {
    ProviderLeaseContext::new(boot, CloudTextId::new("openai")?, [5; 16], 150_000)
}
fn verified(boot: BootDescriptor) -> Result<VerifiedBootDescriptor, ProviderLeaseError> {
    let signer = RunnerSigningKey::from_seed(&[0x66; 32]);
    let attestation = signer.attest_boot(boot)?;
    attestation.verify(
        &signer.public_key(),
        attestation.descriptor().namespace(),
        attestation.descriptor().runner(),
        110_000,
    )
}

#[test]
fn python_boot_attestation_and_memory_only_lease_open_with_exact_context() -> TestResult {
    // Public deterministic crypto fixture input, never a production restoration API.
    let boot = RunnerBootKey {
        secret: StaticSecret::from([0x22; 32]),
    };
    let account = AccountKeyPair::from_seed(&[0x11; 32]);
    let canonical =
        hex::decode(include_str!("../../../../../fixtures/cloud-provider-v1/boot.hex").trim())?;
    let expected = BootDescriptor::from_canonical_bytes(&canonical)?;
    assert_eq!(expected, descriptor(&boot)?);
    assert_eq!(expected.canonical_bytes()?, canonical);
    let signature = hex::decode(
        include_str!("../../../../../fixtures/cloud-provider-v1/boot-signature.hex").trim(),
    )?
    .try_into()
    .map_err(|_| "signature")?;
    let attestation = SignedBootDescriptor::new(expected.clone(), signature);
    let attestation = SignedBootDescriptor::from_canonical_bytes(&attestation.canonical_bytes()?)?;
    let pinned = RunnerSigningKey::from_seed(&[0x66; 32]).public_key();
    attestation.verify(&pinned, expected.namespace(), expected.runner(), 110_000)?;
    assert!(
        attestation
            .verify(&[0; 32], expected.namespace(), expected.runner(), 110_000)
            .is_err()
    );
    let encoded =
        hex::decode(include_str!("../../../../../fixtures/cloud-provider-v1/context.hex").trim())?;
    let context = ProviderLeaseContext::from_canonical_bytes(&encoded)?;
    assert_eq!(context.canonical_bytes()?, encoded);
    let ciphertext =
        hex::decode(include_str!("../../../../../fixtures/cloud-provider-v1/lease.hex").trim())?;
    let opened = boot.open_provider_lease(&account.public_key(), &context, &ciphertext, 110_000)?;
    assert_eq!(opened.secret(), b"public-fixture-api-key");
    assert!(!format!("{opened:?}").contains("public-fixture"));
    assert!(!format!("{boot:?}").contains(&hex::encode([0x22; 32])));
    for length in 0..canonical.len() {
        assert!(BootDescriptor::from_canonical_bytes(&canonical[..length]).is_err());
    }
    for length in 0..encoded.len() {
        assert!(ProviderLeaseContext::from_canonical_bytes(&encoded[..length]).is_err());
    }
    let mut suffix = canonical;
    suffix.push(0);
    assert!(BootDescriptor::from_canonical_bytes(&suffix).is_err());
    let mut suffix = encoded;
    suffix.push(0);
    assert!(ProviderLeaseContext::from_canonical_bytes(&suffix).is_err());
    Ok(())
}

#[test]
fn provider_lease_is_unrecoverable_by_a_new_boot_or_stable_runner_identity() -> TestResult {
    let account = AccountKeyPair::generate()?;
    let boot = RunnerBootKey::generate()?;
    let descriptor = descriptor(&boot)?;
    let recipient = verified(descriptor.clone())?;
    let context = context(descriptor)?;
    let ciphertext = seal_provider_lease(
        &account,
        &recipient,
        &context,
        b"memory-only-secret",
        110_000,
    )?;
    assert_eq!(
        boot.open_provider_lease(&account.public_key(), &context, &ciphertext, 110_000)?
            .secret(),
        b"memory-only-secret"
    );
    assert!(
        boot.open_provider_lease(&account.public_key(), &context, &ciphertext, 150_000)
            .is_err()
    );
    assert!(
        boot.open_provider_lease(&account.public_key(), &context, &ciphertext, 39_999)
            .is_err()
    );
    drop(boot);
    let next_boot = RunnerBootKey::generate()?;
    assert!(
        next_boot
            .open_provider_lease(&account.public_key(), &context, &ciphertext, 110_000)
            .is_err()
    );
    // The API accepts only RunnerBootKey for opening, never RunnerEncryptionKey/account seed.
    assert!(seal_provider_lease(&account, &recipient, &context, b"", 110_000).is_err());
    assert!(
        seal_provider_lease(
            &account,
            &recipient,
            &context,
            &vec![1; MAX_PROVIDER_SECRET_BYTES + 1],
            110_000
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn provider_secret_cannot_move_between_contexts_purposes_or_accounts() -> TestResult {
    let account = AccountKeyPair::generate()?;
    let boot = RunnerBootKey::generate()?;
    let original = descriptor(&boot)?;
    let recipient = verified(original.clone())?;
    let context = context(original.clone())?;
    let ciphertext =
        seal_provider_lease(&account, &recipient, &context, b"private-secret", 110_000)?;
    let wrong_account = AccountKeyPair::generate()?.public_key();
    assert!(
        boot.open_provider_lease(&wrong_account, &context, &ciphertext, 110_000)
            .is_err()
    );
    let variants = [
        ProviderLeaseContext::new(
            original.clone(),
            CloudTextId::new("other")?,
            [5; 16],
            150_000,
        )?,
        ProviderLeaseContext::new(
            original.clone(),
            CloudTextId::new("openai")?,
            [6; 16],
            150_000,
        )?,
        ProviderLeaseContext::new(
            original.clone(),
            CloudTextId::new("openai")?,
            [5; 16],
            140_000,
        )?,
    ];
    for other in variants {
        assert!(
            boot.open_provider_lease(&account.public_key(), &other, &ciphertext, 110_000)
                .is_err()
        );
    }
    for index in 0..ciphertext.len() {
        let mut changed = ciphertext.clone();
        changed[index] ^= 1;
        assert!(
            boot.open_provider_lease(&account.public_key(), &context, &changed, 110_000)
                .is_err(),
            "byte {index}"
        );
    }
    for purpose in 1..14 {
        let mut changed = ciphertext.clone();
        changed[1] = purpose;
        assert!(
            boot.open_provider_lease(&account.public_key(), &context, &changed, 110_000)
                .is_err()
        );
    }
    let other_boot = descriptor(&RunnerBootKey::generate()?)?;
    assert!(
        seal_provider_lease(
            &account,
            &verified(other_boot)?,
            &context,
            b"secret",
            110_000
        )
        .is_err()
    );
    assert!(
        ProviderLeaseContext::new(original, CloudTextId::new("openai")?, [5; 16], 160_001).is_err()
    );
    Ok(())
}

#[test]
fn boot_attestation_binds_source_recipient_identity_and_finite_window() -> TestResult {
    let boot = RunnerBootKey::generate()?;
    let original = descriptor(&boot)?;
    let signer = RunnerSigningKey::generate()?;
    let attestation = signer.attest_boot(original.clone())?;
    let mut runner = original.runner();
    runner.key_epoch += 1;
    assert!(
        attestation
            .verify(&signer.public_key(), original.namespace(), runner, 110_000)
            .is_err()
    );
    let mut namespace = original.namespace().clone();
    namespace.account_id = CloudTextId::new("other")?;
    assert!(
        attestation
            .verify(&signer.public_key(), &namespace, original.runner(), 110_000)
            .is_err()
    );
    for now in [160_000, 39_999, i64::MIN, i64::MAX] {
        assert!(
            attestation
                .verify(
                    &signer.public_key(),
                    original.namespace(),
                    original.runner(),
                    now
                )
                .is_err()
        );
    }
    for window in [
        BootWindow {
            issued_at_ms: 0,
            expires_at_ms: 0,
        },
        BootWindow {
            issued_at_ms: 0,
            expires_at_ms: 1_800_001,
        },
        BootWindow {
            issued_at_ms: i64::MIN,
            expires_at_ms: i64::MAX,
        },
    ] {
        assert!(
            BootDescriptor::new(
                original.namespace().clone(),
                original.runner(),
                [4; 16],
                original.recipient(),
                window
            )
            .is_err()
        );
    }
    Ok(())
}
