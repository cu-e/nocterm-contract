use super::*;
use crate::{AccountKeyPair, PublicKey, cloud::RunnerEncryptionKey};
use nocterm_hub_model::cloud::{CloudNamespace, CloudTextId, JournalClass, RunnerCoordinate};

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn chat() -> Result<ChatCoordinate, Box<dyn std::error::Error>> {
    Ok(ChatCoordinate::new(
        CloudNamespace {
            hub_instance_id: CloudTextId::new("hub")?,
            account_id: CloudTextId::new("account")?,
        },
        RunnerCoordinate {
            id: [2; 16],
            key_epoch: 3,
        },
        [4; 16],
        5,
    )?)
}

pub(super) fn moved_chats() -> Result<Vec<ChatCoordinate>, Box<dyn std::error::Error>> {
    let original = chat()?;
    let mut hub = original.namespace().clone();
    hub.hub_instance_id = CloudTextId::new("other hub")?;
    let mut account = original.namespace().clone();
    account.account_id = CloudTextId::new("other account")?;
    let mut runner = original.runner();
    runner.id[0] ^= 1;
    let mut runner_epoch = original.runner();
    runner_epoch.key_epoch += 1;
    Ok(vec![
        ChatCoordinate::new(
            hub,
            original.runner(),
            original.chat_id(),
            original.key_epoch(),
        )?,
        ChatCoordinate::new(
            account,
            original.runner(),
            original.chat_id(),
            original.key_epoch(),
        )?,
        ChatCoordinate::new(
            original.namespace().clone(),
            runner,
            original.chat_id(),
            original.key_epoch(),
        )?,
        ChatCoordinate::new(
            original.namespace().clone(),
            runner_epoch,
            original.chat_id(),
            original.key_epoch(),
        )?,
        ChatCoordinate::new(
            original.namespace().clone(),
            original.runner(),
            [9; 16],
            original.key_epoch(),
        )?,
        ChatCoordinate::new(
            original.namespace().clone(),
            original.runner(),
            original.chat_id(),
            6,
        )?,
    ])
}

fn slot(chat: ChatCoordinate) -> Result<JournalCoordinate, MaterialError> {
    JournalCoordinate::new(chat, JournalClass::Record, [6; 16], 7, 8, 9)
}

#[test]
fn account_sign_in_opens_its_chat_key_without_runner_or_old_device() -> TestResult {
    let account = AccountKey::generate()?;
    let original = ChatKey::generate()?;
    let sealed = original.seal_for_account(&account, &chat()?)?;
    let later_device = ChatKey::open_for_account(&account, &chat()?, &sealed)?;
    let slot = slot(chat()?)?;
    let encrypted = original.seal_journal(&slot, b"saved progress")?;
    assert_eq!(
        &*later_device.open_journal(&slot, &encrypted)?,
        b"saved progress"
    );
    assert!(ChatKey::open_for_account(&AccountKey::generate()?, &chat()?, &sealed).is_err());
    for changed in moved_chats()? {
        assert!(ChatKey::open_for_account(&account, &changed, &sealed).is_err());
    }
    Ok(())
}

#[test]
fn runner_receives_one_chat_key_without_account_root_material() -> TestResult {
    let account = AccountKeyPair::generate()?;
    let runner = RunnerEncryptionKey::generate()?;
    let original = ChatKey::generate()?;
    let sealed = seal_chat_key_to_runner(&original, &account, &runner.public_key(), &chat()?)?;
    let granted = open_chat_key_from_account(&runner, &account.public_key(), &chat()?, &sealed)?;
    let slot = slot(chat()?)?;
    let encrypted = original.seal_journal(&slot, b"one chat only")?;
    assert_eq!(&*granted.open_journal(&slot, &encrypted)?, b"one chat only");
    let unrelated = ChatKey::generate()?;
    assert!(unrelated.open_journal(&slot, &encrypted).is_err());
    assert!(
        open_chat_key_from_account(
            &RunnerEncryptionKey::generate()?,
            &account.public_key(),
            &chat()?,
            &sealed
        )
        .is_err()
    );
    assert!(
        open_chat_key_from_account(
            &runner,
            &AccountKeyPair::generate()?.public_key(),
            &chat()?,
            &sealed
        )
        .is_err()
    );
    for changed in moved_chats()? {
        assert!(
            open_chat_key_from_account(&runner, &account.public_key(), &changed, &sealed).is_err()
        );
    }
    Ok(())
}

#[test]
fn journal_rejects_moved_class_slot_sequence_revision_or_writer() -> TestResult {
    let key = ChatKey::generate()?;
    let encrypted = key.seal_journal(&slot(chat()?)?, b"sensitive native codec bytes")?;
    for class in [
        JournalClass::Header,
        JournalClass::CommandReceipt,
        JournalClass::Checkpoint,
        JournalClass::Snapshot,
        JournalClass::Outbox,
        JournalClass::BackgroundCommand,
        JournalClass::Effect,
        JournalClass::RunHead,
    ] {
        let changed = JournalCoordinate::new(chat()?, class, [6; 16], 7, 8, 9)?;
        assert!(key.open_journal(&changed, &encrypted).is_err());
    }
    for (id, sequence, revision, writer) in [
        ([0; 16], 7, 8, 9),
        ([6; 16], 8, 8, 9),
        ([6; 16], 7, 9, 9),
        ([6; 16], 7, 8, 10),
    ] {
        let changed = JournalCoordinate::new(
            chat()?,
            JournalClass::Record,
            id,
            sequence,
            revision,
            writer,
        )?;
        assert!(key.open_journal(&changed, &encrypted).is_err());
    }
    for changed in moved_chats()? {
        assert!(key.open_journal(&slot(changed)?, &encrypted).is_err());
    }
    Ok(())
}

#[test]
fn material_envelopes_reject_every_byte_tamper_truncation_or_suffix() -> TestResult {
    let account = AccountKeyPair::generate()?;
    let root = AccountKey::generate()?;
    let runner = RunnerEncryptionKey::generate()?;
    let key = ChatKey::generate()?;
    let wrap = key.seal_for_account(&root, &chat()?)?;
    let grant = seal_chat_key_to_runner(&key, &account, &runner.public_key(), &chat()?)?;
    for i in 0..wrap.len() {
        let mut changed = wrap.clone();
        changed[i] ^= 1;
        assert!(ChatKey::open_for_account(&root, &chat()?, &changed).is_err());
        assert!(ChatKey::open_for_account(&root, &chat()?, &wrap[..i]).is_err());
    }
    for i in 0..grant.len() {
        let mut changed = grant.clone();
        changed[i] ^= 1;
        assert!(
            open_chat_key_from_account(&runner, &account.public_key(), &chat()?, &changed).is_err()
        );
        assert!(
            open_chat_key_from_account(&runner, &account.public_key(), &chat()?, &grant[..i])
                .is_err()
        );
    }
    let mut suffix = grant;
    suffix.push(0);
    assert!(open_chat_key_from_account(&runner, &account.public_key(), &chat()?, &suffix).is_err());
    let mut suffix = wrap;
    suffix.push(0);
    assert!(ChatKey::open_for_account(&root, &chat()?, &suffix).is_err());
    Ok(())
}

#[test]
fn journal_tamper_and_other_material_purposes_fail_closed() -> TestResult {
    let root = AccountKey::generate()?;
    let key = ChatKey::generate()?;
    let location = slot(chat()?)?;
    let encrypted = key.seal_journal(&location, b"not a key grant")?;
    for i in 0..encrypted.len() {
        let mut changed = encrypted.clone();
        changed[i] ^= 1;
        assert!(key.open_journal(&location, &changed).is_err());
        assert!(key.open_journal(&location, &encrypted[..i]).is_err());
    }
    let wrap = key.seal_for_account(&root, &chat()?)?;
    assert!(key.open_journal(&location, &wrap).is_err());
    assert!(ChatKey::open_for_account(&root, &chat()?, &encrypted).is_err());
    let mut suffixed = encrypted;
    suffixed.push(0);
    assert!(key.open_journal(&location, &suffixed).is_err());
    Ok(())
}

#[test]
fn noncontributory_key_grants_never_open_or_seal() -> TestResult {
    let account = AccountKeyPair::generate()?;
    let runner = RunnerEncryptionKey::generate()?;
    let key = ChatKey::generate()?;
    let zero = PublicKey::from_bytes(&[0; 32])?;
    assert!(seal_chat_key_to_runner(&key, &account, &zero, &chat()?).is_err());
    let mut grant = seal_chat_key_to_runner(&key, &account, &runner.public_key(), &chat()?)?;
    grant[2..34].fill(0);
    assert!(open_chat_key_from_account(&runner, &account.public_key(), &chat()?, &grant).is_err());
    assert!(open_chat_key_from_account(&runner, &zero, &chat()?, &grant).is_err());
    Ok(())
}

#[test]
fn journal_sealing_uses_fresh_nonce_and_never_prints_plaintext() -> TestResult {
    let key = ChatKey::generate()?;
    let location = slot(chat()?)?;
    let a = key.seal_journal(&location, b"private-tool-argument")?;
    let b = key.seal_journal(&location, b"private-tool-argument")?;
    assert_ne!(a, b);
    assert_eq!(format!("{key:?}"), "ChatKey(…)");
    assert!(!a.windows(21).any(|part| part == b"private-tool-argument"));
    Ok(())
}

#[test]
fn oversized_local_slot_refused_before_decryption() -> TestResult {
    let key = ChatKey::generate()?;
    let oversized = vec![0; MAX_JOURNAL_CIPHERTEXT_BYTES + 1];
    assert!(matches!(
        key.open_journal(&slot(chat()?)?, &oversized),
        Err(CloudMaterialError::Capacity)
    ));
    assert!(matches!(
        key.seal_journal(&slot(chat()?)?, &oversized),
        Err(CloudMaterialError::Capacity)
    ));
    Ok(())
}

#[test]
fn independent_python_vectors_open_account_wrap_runner_grant_and_journal() -> TestResult {
    let root = AccountKey([0x55; 32]);
    let account = AccountKeyPair::from_seed(&[0x11; 32]);
    let runner = RunnerEncryptionKey::from_seed(&[0x22; 32]);
    let wrap = hex::decode(
        include_str!("../../../../../fixtures/cloud-material-v1/account-wrap.hex").trim(),
    )?;
    let grant = hex::decode(
        include_str!("../../../../../fixtures/cloud-material-v1/runner-grant.hex").trim(),
    )?;
    let record =
        hex::decode(include_str!("../../../../../fixtures/cloud-material-v1/journal.hex").trim())?;
    let account_key = ChatKey::open_for_account(&root, &chat()?, &wrap)?;
    let runner_key = open_chat_key_from_account(&runner, &account.public_key(), &chat()?, &grant)?;
    assert_eq!(
        &*account_key.open_journal(&slot(chat()?)?, &record)?,
        b"independent journal fixture"
    );
    assert_eq!(
        &*runner_key.open_journal(&slot(chat()?)?, &record)?,
        b"independent journal fixture"
    );
    Ok(())
}
