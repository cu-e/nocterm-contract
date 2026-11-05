//! Chat summaries sealed from a runner to its account (purpose 22, ADR 0008).
//!
//! The runner signs a summary with its pinned [`super::RunnerSigningKey`]
//! ([`super::RunnerSigningKey::attest_summary`]) and seals the signed framing with the existing
//! static+ephemeral authenticated box from its [`RunnerEncryptionKey`] to the account's public
//! key, HKDF info `nocterm-cloud-chat-summary-v1/auth`, with the canonical [`SummaryContext`] as
//! associated data. Listing chats therefore needs neither a chat key nor any replay, and a hub
//! can neither read, forge, alter nor move a summary to another chat, revision, runner or
//! account. The box authenticates the runner to the account only; the signature is what a
//! device checks against the runner's signing pin. Freshness and completeness are not proven:
//! a hub can withhold or replay an older summary, which the device's revision order and catalog
//! witness detect.
use super::{
    RunnerEncryptionKey,
    account_box::{self, AccountBox, BoxError, KeyOwner},
};
use crate::{AccountKeyPair, KeyError, OpenError, PublicKey, SealError};
use nocterm_hub_model::cloud::summary::{SignedChatSummary, SummaryContext, SummaryError};

/// The runner keys a device pinned for the summary's runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SummaryPins {
    /// X25519 key the runner seals from.
    pub runner_encryption: [u8; 32],
    /// Ed25519 key the runner signs with.
    pub runner_signing: [u8; 32],
}

/// Seals a signed summary from this runner to the pinned account key.
pub fn seal_summary(
    runner: &RunnerEncryptionKey,
    account: &PublicKey,
    summary: &SignedChatSummary,
) -> Result<Vec<u8>, SummaryCryptoError> {
    Ok(account_box::seal(
        AccountBox::Summary,
        KeyOwner::Runner(runner),
        account,
        &summary.context().canonical_bytes()?,
        &summary.canonical_bytes()?,
    )?)
}

/// Opens a summary routed under `expected` (the context of its relay binding) from the runner
/// with `pins`, and checks that the runner signed exactly that context.
pub fn open_summary(
    account: &AccountKeyPair,
    pins: &SummaryPins,
    expected: &SummaryContext,
    ciphertext: &[u8],
) -> Result<SignedChatSummary, SummaryCryptoError> {
    let plaintext = account_box::open(
        AccountBox::Summary,
        KeyOwner::Account(account),
        &PublicKey::from_array(pins.runner_encryption),
        &expected.canonical_bytes()?,
        ciphertext,
    )?;
    let summary = SignedChatSummary::from_canonical_bytes(&plaintext, &pins.runner_signing)?;
    if summary.context() != expected {
        return Err(SummaryCryptoError::ContextMismatch);
    }
    Ok(summary)
}

#[derive(Debug, thiserror::Error)]
pub enum SummaryCryptoError {
    #[error("the chat summary was refused")]
    Summary(#[from] SummaryError),
    #[error("the sealed chat summary exceeds its bound")]
    Bounds,
    #[error("the sealed chat summary names another chat or revision than its routing")]
    ContextMismatch,
    #[error("chat summary key generation or derivation failed")]
    Key(#[from] KeyError),
    #[error("the chat summary could not be sealed")]
    Seal(#[from] SealError),
    #[error("the chat summary does not open from this runner to this account")]
    Open(#[from] OpenError),
}
impl From<BoxError> for SummaryCryptoError {
    fn from(error: BoxError) -> Self {
        match error {
            BoxError::Bounds => Self::Bounds,
            BoxError::Key(error) => Self::Key(error),
            BoxError::Seal(error) => Self::Seal(error),
            BoxError::Open(error) => Self::Open(error),
        }
    }
}

#[cfg(test)]
mod tests;
