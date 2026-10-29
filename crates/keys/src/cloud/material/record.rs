//! Runner signatures remain necessary even for account devices holding the chat key.
use super::ChatKey;
use crate::{OpenError, SealError, cloud::RunnerSigningKey, seal};
use core::fmt;
use nocterm_hub_model::cloud::{
    MAX_PLAINTEXT_BYTES, RecordContext, RecordError, RecordHeader, RecordKind, SignedRecord,
};
use zeroize::Zeroizing;

const OVERHEAD: usize = 2 + 24 + 16;

pub struct OpenedRecord {
    plaintext: Zeroizing<Vec<u8>>,
}
impl OpenedRecord {
    pub fn record(&self) -> Result<SignedRecord<'_>, RecordError> {
        SignedRecord::from_plaintext(&self.plaintext)
    }
}
impl fmt::Debug for OpenedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedRecord")
            .field("plaintext_bytes", &self.plaintext.len())
            .finish_non_exhaustive()
    }
}

pub fn seal_event(
    key: &ChatKey,
    signer: &RunnerSigningKey,
    context: RecordContext,
    payload: &[u8],
) -> Result<Vec<u8>, CloudRecordError> {
    seal_record(key, signer, context, RecordKind::Event, payload)
}
pub fn seal_snapshot(
    key: &ChatKey,
    signer: &RunnerSigningKey,
    context: RecordContext,
    payload: &[u8],
) -> Result<Vec<u8>, CloudRecordError> {
    seal_record(key, signer, context, RecordKind::Snapshot, payload)
}
pub fn open_event(
    key: &ChatKey,
    pinned_runner_signer: &[u8; 32],
    context: &RecordContext,
    ciphertext: &[u8],
) -> Result<OpenedRecord, CloudRecordError> {
    open_record(
        key,
        pinned_runner_signer,
        context,
        RecordKind::Event,
        ciphertext,
    )
}
pub fn open_snapshot(
    key: &ChatKey,
    pinned_runner_signer: &[u8; 32],
    context: &RecordContext,
    ciphertext: &[u8],
) -> Result<OpenedRecord, CloudRecordError> {
    open_record(
        key,
        pinned_runner_signer,
        context,
        RecordKind::Snapshot,
        ciphertext,
    )
}

fn seal_record(
    key: &ChatKey,
    signer: &RunnerSigningKey,
    context: RecordContext,
    kind: RecordKind,
    payload: &[u8],
) -> Result<Vec<u8>, CloudRecordError> {
    let aad = hex::encode(context.canonical_bytes()?);
    let header = RecordHeader::new(context, kind, signer.public_key(), payload)?;
    let signature = signer.sign_record(&header.canonical_bytes()?);
    let record = SignedRecord::new(header, payload, signature)?;
    let plaintext = Zeroizing::new(record.plaintext_bytes()?);
    Ok(seal::seal(&key.0, purpose(kind), &[&aad], &plaintext)?)
}

fn open_record(
    key: &ChatKey,
    signer: &[u8; 32],
    context: &RecordContext,
    kind: RecordKind,
    ciphertext: &[u8],
) -> Result<OpenedRecord, CloudRecordError> {
    if ciphertext.len() > MAX_PLAINTEXT_BYTES + OVERHEAD {
        return Err(CloudRecordError::Capacity);
    }
    let aad = hex::encode(context.canonical_bytes()?);
    let plaintext = seal::open(&key.0, purpose(kind), &[&aad], ciphertext)?;
    let record = SignedRecord::from_plaintext(&plaintext)?;
    if record.header().kind() != kind
        || record.header().context() != context
        || &record.header().signer() != signer
    {
        return Err(CloudRecordError::ContextMismatch);
    }
    Ok(OpenedRecord { plaintext })
}

fn purpose(kind: RecordKind) -> seal::Purpose {
    match kind {
        RecordKind::Event => seal::Purpose::CloudEvent,
        RecordKind::Snapshot => seal::Purpose::CloudSnapshot,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CloudRecordError {
    #[error("Cloud record framing or signature is invalid")]
    Record(#[from] RecordError),
    #[error("Cloud record exceeds its ciphertext byte limit")]
    Capacity,
    #[error("Cloud record does not match its pinned runner or expected coordinates")]
    ContextMismatch,
    #[error("Cloud record sealing failed")]
    Seal(#[from] SealError),
    #[error("Cloud record authentication failed")]
    Open(#[from] OpenError),
}

#[cfg(test)]
mod tests;
