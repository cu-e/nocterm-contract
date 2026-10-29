//! Account-authenticated grant of one chat key to its pinned runner.
use super::{ChatKey, CloudMaterialError, require_key_envelope};
use crate::{
    AccountKeyPair, OpenError, PublicKey, SealError, authenticated_box::AuthenticatedBoxKeys,
    cloud::RunnerEncryptionKey, random_bytes, seal,
};
use nocterm_hub_model::cloud::ChatCoordinate;
use zeroize::Zeroizing;

const HEADER_BYTES: usize = 2 + 32 + 24;
const ENVELOPE_BYTES: usize = HEADER_BYTES + 32 + 16;
const KEY_INFO: &[u8] = b"nocterm-cloud-chat-runner-key-v1/auth";

/// Grants only this key. Account and runner trust pins must be established separately.
pub fn seal_chat_key_to_runner(
    chat_key: &ChatKey,
    account: &AccountKeyPair,
    pinned_runner: &PublicKey,
    chat: &ChatCoordinate,
) -> Result<Vec<u8>, CloudMaterialError> {
    let ephemeral = AccountKeyPair::from_seed(&Zeroizing::new(random_bytes::<32>()?));
    let dh_ephemeral = ephemeral.agree(pinned_runner.as_bytes());
    let dh_account = account.agree(pinned_runner.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_account.was_contributory() {
        return Err(SealError::UnusableRecipientKey.into());
    }
    let account_public = account.public_key();
    let ephemeral_public = ephemeral.public_key();
    let key = AuthenticatedBoxKeys::new(
        ephemeral_public.as_bytes(),
        account_public.as_bytes(),
        pinned_runner.as_bytes(),
    )
    .key(&dh_ephemeral, &dh_account, KEY_INFO)?;
    let context = grant_context(chat, &account_public, pinned_runner)?;
    let nonce = random_bytes::<24>()?;
    let encrypted = seal::encrypt(
        &key,
        seal::Purpose::CloudChatRunnerKey,
        &[&context],
        &nonce,
        &chat_key.0,
    )?;
    let mut bytes = Vec::with_capacity(ENVELOPE_BYTES);
    bytes.extend_from_slice(&[
        seal::FORMAT_VERSION,
        seal::Purpose::CloudChatRunnerKey as u8,
    ]);
    bytes.extend_from_slice(ephemeral_public.as_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    Ok(bytes)
}

/// Authenticates the account pin and exact key coordinates, never hub directory keys.
/// Like existing grants, this is recipient-forgeable and is not an account signature.
pub fn open_chat_key_from_account(
    runner: &RunnerEncryptionKey,
    pinned_account: &PublicKey,
    expected: &ChatCoordinate,
    ciphertext: &[u8],
) -> Result<ChatKey, CloudMaterialError> {
    require_key_envelope(ciphertext, ENVELOPE_BYTES)?;
    if ciphertext[..2]
        != [
            seal::FORMAT_VERSION,
            seal::Purpose::CloudChatRunnerKey as u8,
        ]
    {
        return Err(OpenError::Malformed.into());
    }
    let ephemeral = ciphertext[2..34]
        .try_into()
        .map_err(|_| OpenError::Malformed)?;
    let nonce = ciphertext[34..HEADER_BYTES]
        .try_into()
        .map_err(|_| OpenError::Malformed)?;
    let dh_ephemeral = runner.agree(&ephemeral);
    let dh_account = runner.agree(pinned_account.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_account.was_contributory() {
        return Err(OpenError::Rejected.into());
    }
    let runner_public = runner.public_key();
    let key = AuthenticatedBoxKeys::new(
        &ephemeral,
        pinned_account.as_bytes(),
        runner_public.as_bytes(),
    )
    .key(&dh_ephemeral, &dh_account, KEY_INFO)?;
    let context = grant_context(expected, pinned_account, &runner_public)?;
    let plaintext = seal::decrypt(
        &key,
        seal::Purpose::CloudChatRunnerKey,
        &[&context],
        &nonce,
        &ciphertext[HEADER_BYTES..],
    )?;
    Ok(ChatKey::from_plaintext(&plaintext)?)
}

fn grant_context(
    chat: &ChatCoordinate,
    account: &PublicKey,
    runner: &PublicKey,
) -> Result<String, CloudMaterialError> {
    let mut context = chat.canonical_bytes()?;
    context.extend_from_slice(account.as_bytes());
    context.extend_from_slice(runner.as_bytes());
    Ok(hex::encode(context))
}
