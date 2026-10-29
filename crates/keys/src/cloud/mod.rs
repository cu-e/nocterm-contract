//! Account-authenticated Cloud commands addressed to a pinned runner.
//!
//! The account's existing X25519 key authenticates the sender against a hostile hub;
//! the original device signs its immutable command. This is not a third-party
//! account signature: the trusted recipient can forge the authenticated box.
//! Semantic payloads, first-pin setup, replay receipts, grants and effect admission
//! are not owned here. In particular, call validate_admission_time only for a new
//! admission, after the journal has looked up the original idempotent receipt.

mod catalog;
mod head;
pub use head::{
    HeadCryptoError, open_head_query, open_head_witness, seal_head_query, seal_head_witness,
};
mod envelope;
pub use catalog::{NativeCatalogError, NativeCatalogKey};
mod material;
mod native_head;
pub use native_head::{NativeChatHeadError, NativeChatHeadKey};
mod provider;
pub use provider::{
    MAX_PROVIDER_LEASE_BYTES, MAX_PROVIDER_SECRET_BYTES, OpenedProviderLease, ProviderSecretError,
    RunnerBootKey, seal_provider_lease,
};
mod runner_key;
mod runner_signer;

pub use material::{
    ChatKey, CloudMaterialError, CloudRecordError, MAX_JOURNAL_CIPHERTEXT_BYTES, OpenedRecord,
    open_chat_key_from_account, open_event, open_snapshot, seal_chat_key_to_runner, seal_event,
    seal_snapshot,
};
pub use runner_key::RunnerEncryptionKey;
pub use runner_signer::RunnerSigningKey;

use crate::{
    AccountKeyPair, KeyError, PublicKey, authenticated_box::AuthenticatedBoxKeys, random_bytes,
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use core::fmt;
use envelope::Envelope;
use nocterm_hub_model::cloud::{CloudRoute, CommandError, SignedCommand};
use zeroize::Zeroizing;

const KEY_INFO: &[u8] = b"nocterm-cloud-command-v1/auth";
const AAD_PURPOSE: &[u8] = b"nocterm/cloud-command-box/v1";

#[derive(Debug, thiserror::Error)]
pub enum CloudCommandError {
    #[error("the Cloud command framing or device signature is invalid")]
    Command(#[from] CommandError),
    #[error("Cloud command key generation or derivation failed")]
    Key(#[from] KeyError),
    #[error("the Cloud command peer key is not contributory")]
    UnusablePeer,
    #[error("the Cloud command envelope exceeds its limit")]
    EnvelopeTooLarge,
    #[error("malformed Cloud command envelope")]
    MalformedEnvelope,
    #[error("unsupported Cloud command envelope version")]
    UnsupportedVersion,
    #[error("the envelope is not a Cloud command box")]
    WrongPurpose,
    #[error("Cloud command identities differ from the expected account, runner or route")]
    ContextMismatch,
    #[error("Cloud command encryption failed")]
    Encrypt(#[source] chacha20poly1305::Error),
    #[error("Cloud command authentication failed")]
    Authentication(#[source] chacha20poly1305::Error),
}

/// Owns the zeroizing plaintext of an authenticated command, never a replay receipt.
pub struct OpenedCommand {
    plaintext: Zeroizing<Vec<u8>>,
}
impl OpenedCommand {
    /// Borrows the device-authenticated command. Its semantic payload remains untrusted.
    pub fn command(&self) -> Result<SignedCommand<'_>, CommandError> {
        SignedCommand::from_plaintext(&self.plaintext)
    }
}
impl fmt::Debug for OpenedCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedCommand")
            .field("plaintext_bytes", &self.plaintext.len())
            .finish_non_exhaustive()
    }
}

/// Seals an already device-signed command from the account to its pinned runner.
/// Account and runner keys repeated in the command must match these actual keys.
pub fn seal_command(
    account: &AccountKeyPair,
    pinned_runner: &PublicKey,
    command: &SignedCommand<'_>,
) -> Result<Vec<u8>, CloudCommandError> {
    let keys = command.header().keys();
    if keys.account != account.public_key().to_bytes() || keys.runner != pinned_runner.to_bytes() {
        return Err(CloudCommandError::ContextMismatch);
    }
    let ephemeral = AccountKeyPair::from_seed(&Zeroizing::new(random_bytes::<32>()?));
    let nonce = random_bytes::<24>()?;
    let dh_ephemeral = ephemeral.agree(pinned_runner.as_bytes());
    let dh_account = account.agree(pinned_runner.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_account.was_contributory() {
        return Err(CloudCommandError::UnusablePeer);
    }
    let ephemeral_public = ephemeral.public_key();
    let account_public = account.public_key();
    let key = AuthenticatedBoxKeys::new(
        ephemeral_public.as_bytes(),
        account_public.as_bytes(),
        pinned_runner.as_bytes(),
    )
    .key(&dh_ephemeral, &dh_account, KEY_INFO)?;
    let associated = associated_data(command.header().route(), &account_public, pinned_runner)?;
    let plaintext = Zeroizing::new(command.plaintext_bytes()?);
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &associated,
            },
        )
        .map_err(CloudCommandError::Encrypt)?;
    Envelope::encode(ephemeral_public.to_bytes(), nonce, &ciphertext)
}

/// Opens only from an installed account pin, to this runner, at this captured route.
/// No key discovered from a hub directory or from the ciphertext establishes trust.
pub fn open_command(
    runner: &RunnerEncryptionKey,
    pinned_account: &PublicKey,
    expected_route: &CloudRoute,
    ciphertext: &[u8],
) -> Result<OpenedCommand, CloudCommandError> {
    let envelope = Envelope::parse(ciphertext)?;
    let dh_ephemeral = runner.agree(&envelope.ephemeral);
    let dh_account = runner.agree(pinned_account.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_account.was_contributory() {
        return Err(CloudCommandError::UnusablePeer);
    }
    let runner_public = runner.public_key();
    let key = AuthenticatedBoxKeys::new(
        &envelope.ephemeral,
        pinned_account.as_bytes(),
        runner_public.as_bytes(),
    )
    .key(&dh_ephemeral, &dh_account, KEY_INFO)?;
    let associated = associated_data(expected_route, pinned_account, &runner_public)?;
    let plaintext = XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            &XNonce::from(envelope.nonce),
            Payload {
                msg: envelope.ciphertext,
                aad: &associated,
            },
        )
        .map(Zeroizing::new)
        .map_err(CloudCommandError::Authentication)?;
    let command = SignedCommand::from_plaintext(&plaintext)?;
    let keys = command.header().keys();
    if command.header().route() != expected_route
        || keys.account != pinned_account.to_bytes()
        || keys.runner != runner_public.to_bytes()
    {
        return Err(CloudCommandError::ContextMismatch);
    }
    Ok(OpenedCommand { plaintext })
}

fn associated_data(
    route: &CloudRoute,
    account: &PublicKey,
    runner: &PublicKey,
) -> Result<Vec<u8>, CommandError> {
    let mut bytes = Vec::with_capacity(512);
    // The fixed label's length fits u32; all route fields are already bounded.
    bytes.extend_from_slice(
        &u32::try_from(AAD_PURPOSE.len())
            .map_err(|_| CommandError::HeaderTooLarge)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(AAD_PURPOSE);
    bytes.extend_from_slice(&route.canonical_bytes()?);
    bytes.extend_from_slice(account.as_bytes());
    bytes.extend_from_slice(runner.as_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests;
