use super::*;
use crate::{AccountKeyPair, cloud::RunnerSigningKey};
use nocterm_hub_model::cloud::{
    ChatCoordinate, CloudNamespace, CloudTextId, RunnerCoordinate,
    summary::{ChatState, ChatSummary, MAX_SEALED_SUMMARY_BYTES, SummaryHost},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-summary-v1")
        .join(format!("{name}.hex"));
    Ok(hex::decode(std::fs::read_to_string(path)?.trim())?)
}
fn context(revision: u64) -> Result<SummaryContext, Box<dyn std::error::Error>> {
    let chat = ChatCoordinate::new(
        CloudNamespace {
            hub_instance_id: CloudTextId::new("hub")?,
            account_id: CloudTextId::new("acc-1")?,
        },
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        [0x81; 16],
        4,
    )?;
    Ok(SummaryContext::new(chat, revision)?)
}
fn pins() -> SummaryPins {
    SummaryPins {
        runner_encryption: RunnerEncryptionKey::from_seed(&[0x41; 32])
            .public_key()
            .to_bytes(),
        runner_signing: RunnerSigningKey::from_seed(&[0x51; 32]).public_key(),
    }
}
fn summary() -> ChatSummary {
    ChatSummary {
        head: None,
        control_revision: 1,
        created_at_ms: 1,
        last_activity_ms: 2,
        title: "Hello".to_owned(),
        host: SummaryHost::Own,
        model: None,
        state: ChatState::Running,
        pending_approvals: 0,
        servers: Vec::new(),
        features: 0,
    }
}

#[test]
fn an_independent_sealed_summary_opens_under_the_account_and_runner_pins() -> TestResult {
    let account = AccountKeyPair::from_seed(&[0x31; 32]);
    let opened = open_summary(&account, &pins(), &context(7)?, &fixture("sealed-full")?)?;
    assert_eq!(opened.canonical_bytes()?, fixture("signed-full")?);
    assert_eq!(opened.context(), &context(7)?);
    Ok(())
}

#[test]
fn an_older_summary_or_another_signer_inside_a_valid_box_is_refused() -> TestResult {
    let account = AccountKeyPair::from_seed(&[0x31; 32]);
    assert!(matches!(
        open_summary(
            &account,
            &pins(),
            &context(7)?,
            &fixture("sealed-older-inside")?
        ),
        Err(SummaryCryptoError::ContextMismatch)
    ));
    assert!(matches!(
        open_summary(
            &account,
            &pins(),
            &context(7)?,
            &fixture("sealed-other-signer")?
        ),
        Err(SummaryCryptoError::Summary(SummaryError::Signature(_)))
    ));
    Ok(())
}

#[test]
fn a_summary_opens_only_for_its_account_runner_and_routing() -> TestResult {
    let account = AccountKeyPair::from_seed(&[0x31; 32]);
    let runner = RunnerEncryptionKey::from_seed(&[0x41; 32]);
    let attested =
        RunnerSigningKey::from_seed(&[0x51; 32]).attest_summary(context(7)?, summary())?;
    let sealed = seal_summary(&runner, &account.public_key(), &attested)?;
    assert_eq!(
        open_summary(&account, &pins(), &context(7)?, &sealed)?,
        attested
    );
    let other_account = AccountKeyPair::from_seed(&[0x32; 32]);
    assert!(matches!(
        open_summary(&other_account, &pins(), &context(7)?, &sealed),
        Err(SummaryCryptoError::Open(OpenError::Rejected))
    ));
    let mut wrong_runner = pins();
    wrong_runner.runner_encryption = RunnerEncryptionKey::from_seed(&[0x42; 32])
        .public_key()
        .to_bytes();
    assert!(matches!(
        open_summary(&account, &wrong_runner, &context(7)?, &sealed),
        Err(SummaryCryptoError::Open(OpenError::Rejected))
    ));
    let mut wrong_signer = pins();
    wrong_signer.runner_signing = RunnerSigningKey::from_seed(&[0x52; 32]).public_key();
    assert!(matches!(
        open_summary(&account, &wrong_signer, &context(7)?, &sealed),
        Err(SummaryCryptoError::Summary(SummaryError::Signature(_)))
    ));
    // The hub moved the ciphertext to another revision's routing.
    assert!(matches!(
        open_summary(&account, &pins(), &context(8)?, &sealed),
        Err(SummaryCryptoError::Open(OpenError::Rejected))
    ));
    let mut tampered = sealed.clone();
    *tampered.last_mut().ok_or("empty")? ^= 1;
    assert!(open_summary(&account, &pins(), &context(7)?, &tampered).is_err());
    Ok(())
}

#[test]
fn oversized_or_other_purpose_boxes_are_refused_before_opening() -> TestResult {
    let account = AccountKeyPair::from_seed(&[0x31; 32]);
    assert!(matches!(
        open_summary(
            &account,
            &pins(),
            &context(7)?,
            &vec![0; MAX_SEALED_SUMMARY_BYTES + 1]
        ),
        Err(SummaryCryptoError::Bounds)
    ));
    let mut sealed = fixture("sealed-full")?;
    sealed[1] = 17;
    assert!(matches!(
        open_summary(&account, &pins(), &context(7)?, &sealed),
        Err(SummaryCryptoError::Open(OpenError::Malformed))
    ));
    Ok(())
}
