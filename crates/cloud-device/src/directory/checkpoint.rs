//! Directory checkpoints, version 1: a runner directory's cursor and held summaries, sealed
//! with a key derived from the account key (`nocterm_keys::cloud::CheckpointKey`), so a
//! listing replays only summaries published since.
//!
//! Key context: `nocterm/cloud-device-directory/v1` ‖ u32-length hub namespace ‖ u32-length
//! account id ‖ runner id ‖ runner key epoch ‖ runner encryption, signing and proof pins ‖
//! authority fingerprint ‖ account key digest. A checkpoint therefore opens only for the same
//! account, hub, runner generation and pins.
//!
//! Plaintext: the label ‖ u16 version ‖ cursor u64 ‖ u32 row count ‖ rows by chat id, each the
//! row's cursor u64 ‖ u32-length signed summary framing. Restoring verifies every summary
//! again under the runner's signing pin; any inconsistency refuses the checkpoint
//! ([`CloudDeviceError::Checkpoint`]) and the directory is read from the start.
use super::{DirectoryOrigin, DirectoryRow, MAX_DIRECTORY_CHATS, RunnerDirectory};
use crate::{
    AccountScope, CloudDeviceError,
    context::AccountKeys,
    records::TrustedRunner,
    transcript::codec::{Reader, Writer},
    trust::HubCapabilities,
};
use nocterm_hub_model::cloud::summary::{MAX_SIGNED_SUMMARY_BYTES, SignedChatSummary};
use nocterm_keys::cloud::CheckpointKey;
use std::collections::BTreeMap;

const LABEL: &[u8] = b"nocterm/cloud-device-directory/v1";
const VERSION: u16 = 1;

/// A sealed directory checkpoint as the client stores it, one per runner. Opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDirectory(Vec<u8>);
impl VerifiedDirectory {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

fn key(
    scope: &AccountScope,
    origin: &DirectoryOrigin,
    keys: &AccountKeys,
) -> Result<CheckpointKey, CloudDeviceError> {
    if !scope.is_account_key(&keys.public_key()) || scope.namespace() != origin.namespace {
        return Err(CloudDeviceError::Binding);
    }
    let mut context = Writer(LABEL.to_vec());
    context.text(scope.hub_instance())?;
    context.text(scope.account_id())?;
    context.bytes(&origin.runner.id);
    context.u64(origin.runner.key_epoch);
    for part in [
        origin.pins.encryption,
        origin.pins.signing,
        origin.pins.proof,
    ] {
        context.bytes(&part);
    }
    context.bytes(&scope.authority_fingerprint());
    context.bytes(&scope.account_key_digest());
    Ok(CheckpointKey::derive(keys.account(), &context.0)?)
}

impl RunnerDirectory {
    /// Seals the directory between rounds.
    pub fn checkpoint(
        &self,
        scope: &AccountScope,
        keys: &AccountKeys,
    ) -> Result<VerifiedDirectory, CloudDeviceError> {
        if !self.idle() {
            return Err(CloudDeviceError::Checkpoint);
        }
        let mut out = Writer(LABEL.to_vec());
        out.bytes(&VERSION.to_be_bytes());
        out.u64(self.cursor);
        out.len(self.rows.len())?;
        for row in self.rows.values() {
            out.u64(row.cursor);
            let framing = row
                .summary
                .canonical_bytes()
                .map_err(|_| CloudDeviceError::Checkpoint)?;
            out.len(framing.len())?;
            out.bytes(&framing);
        }
        let sealed = key(scope, &self.origin, keys)?.seal(&out.0);
        zeroize::Zeroize::zeroize(&mut out.0);
        Ok(VerifiedDirectory(sealed?))
    }
    /// The directory of `runner` resumed at `checkpoint`.
    pub fn restore(
        scope: &AccountScope,
        runner: &TrustedRunner,
        capabilities: &HubCapabilities,
        keys: &AccountKeys,
        checkpoint: &VerifiedDirectory,
    ) -> Result<Self, CloudDeviceError> {
        let origin = Self::origin(scope, runner);
        let plaintext = key(scope, &origin, keys)?.open(&checkpoint.0)?;
        let mut input = Reader(&plaintext);
        if input.take(LABEL.len())? != LABEL || u16::from_be_bytes(input.array()?) != VERSION {
            return Err(CloudDeviceError::Checkpoint);
        }
        let cursor = input.u64()?;
        let count = input.len(MAX_DIRECTORY_CHATS)?;
        let mut rows = BTreeMap::new();
        for _ in 0..count {
            let row_cursor = input.u64()?;
            let length = input.len(MAX_SIGNED_SUMMARY_BYTES)?;
            let summary =
                SignedChatSummary::from_canonical_bytes(input.take(length)?, &origin.pins.signing)
                    .map_err(|_| CloudDeviceError::Checkpoint)?;
            let chat = summary.context().chat();
            let previous = rows.keys().next_back().copied();
            if chat.namespace() != &origin.namespace
                || chat.runner() != origin.runner
                || row_cursor == 0
                || row_cursor > cursor
                || previous.is_some_and(|last: [u8; 16]| last >= chat.chat_id())
            {
                return Err(CloudDeviceError::Checkpoint);
            }
            rows.insert(
                chat.chat_id(),
                DirectoryRow {
                    summary,
                    cursor: row_cursor,
                },
            );
        }
        input.finish()?;
        Self::with_rows(origin, capabilities, cursor, rows)
    }
}
