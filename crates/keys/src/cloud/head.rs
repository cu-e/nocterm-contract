//! Purpose-specific authenticated head probes. Witnesses use the account's
//! normal key pair and remain openable after a deleted chat key is retired.
mod envelope;
use super::RunnerEncryptionKey;
use crate::{AccountKeyPair, KeyError, OpenError, PublicKey, SealError};
use envelope::{HeadBox, KeyOwner};
use nocterm_hub_model::cloud::head::{
    HeadProbeError, HeadProbeScope, HeadQuery, SignedHeadQuery, SignedHeadWitness,
};

/// Seals an already device-signed, read-only query. This supplies no membership,
/// first-pin trust or execution permission to the receiver.
pub fn seal_head_query(
    account: &AccountKeyPair,
    query: &SignedHeadQuery,
) -> Result<Vec<u8>, HeadCryptoError> {
    let request = query.query();
    if request.scope.keys.account != account.public_key().to_bytes() {
        return Err(HeadProbeError::Scope.into());
    }
    let recipient = PublicKey::from_array(request.scope.keys.runner_encryption);
    envelope::seal(
        HeadBox::Query,
        KeyOwner::Account(account),
        &recipient,
        &query_context(&request.scope, &request.probe_id)?,
        &query.canonical_bytes()?,
    )
}
/// The complete expected scope is independently configured. A hub's offered
/// encryption/signing keys and routing values are not these pins.
pub fn open_head_query(
    runner: &RunnerEncryptionKey,
    expected: &HeadProbeScope,
    probe_id: [u8; 16],
    ciphertext: &[u8],
    now_ms: i64,
) -> Result<SignedHeadQuery, HeadCryptoError> {
    if runner.public_key().to_bytes() != expected.keys.runner_encryption {
        return Err(HeadProbeError::Scope.into());
    }
    let sender = PublicKey::from_array(expected.keys.account);
    let plaintext = envelope::open(
        HeadBox::Query,
        KeyOwner::Runner(runner),
        &sender,
        &query_context(expected, &probe_id)?,
        ciphertext,
    )?;
    let signed = SignedHeadQuery::from_canonical_bytes(&plaintext)?;
    let query = signed.query();
    if &query.scope != expected || query.probe_id != probe_id {
        return Err(HeadProbeError::Scope.into());
    }
    // R tolerates only bounded clock skew for receipt. The device later checks
    // its exact original UTC and monotonic deadline without extending it.
    if now_ms.saturating_add(nocterm_hub_model::cloud::head::MAX_HEAD_CLOCK_SKEW_MS)
        < query.window.issued_at_ms
        || now_ms >= query.window.expires_at_ms
    {
        return Err(HeadProbeError::Time.into());
    }
    Ok(signed)
}
pub fn seal_head_witness(
    runner: &RunnerEncryptionKey,
    witness: &SignedHeadWitness,
) -> Result<Vec<u8>, HeadCryptoError> {
    let query = &witness.witness().query;
    if runner.public_key().to_bytes() != query.scope.keys.runner_encryption {
        return Err(HeadProbeError::Scope.into());
    }
    let recipient = PublicKey::from_array(query.scope.keys.account);
    envelope::seal(
        HeadBox::Witness,
        KeyOwner::Runner(runner),
        &recipient,
        &query.canonical_bytes()?,
        &witness.canonical_bytes()?,
    )
}
/// Only the original pending query supplies expected context/challenge. A valid
/// witness to another nonce or earlier login must not establish a cold head.
pub fn open_head_witness(
    account: &AccountKeyPair,
    expected: &HeadQuery,
    ciphertext: &[u8],
    now_ms: i64,
) -> Result<SignedHeadWitness, HeadCryptoError> {
    expected.require_fresh(now_ms)?;
    if account.public_key().to_bytes() != expected.scope.keys.account {
        return Err(HeadProbeError::Scope.into());
    }
    let sender = PublicKey::from_array(expected.scope.keys.runner_encryption);
    let plaintext = envelope::open(
        HeadBox::Witness,
        KeyOwner::Account(account),
        &sender,
        &expected.canonical_bytes()?,
        ciphertext,
    )?;
    let witness = SignedHeadWitness::from_canonical_bytes(&plaintext)?;
    witness.require_query(expected, now_ms)?;
    Ok(witness)
}
fn query_context(scope: &HeadProbeScope, probe: &[u8; 16]) -> Result<Vec<u8>, HeadProbeError> {
    let mut bytes = scope.canonical_bytes()?;
    bytes.extend_from_slice(probe);
    Ok(bytes)
}
#[derive(Debug, thiserror::Error)]
pub enum HeadCryptoError {
    #[error("the bounded purpose-specific head probe was refused")]
    Probe(#[from] HeadProbeError),
    #[error("head probe key generation or derivation failed")]
    Key(#[from] KeyError),
    #[error("the sealed head probe or witness exceeds its bound")]
    Bounds,
    #[error("the head probe sealing failed")]
    Seal(#[from] SealError),
    #[error("the head probe authentication failed")]
    Open(#[from] OpenError),
}

#[cfg(test)]
mod tests;
