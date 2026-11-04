//! Device checkpoints, version 1: a reader's verified position and transcript, sealed with a key
//! derived from the account key (`nocterm_keys::cloud::CheckpointKey`).
//!
//! Key context: `nocterm/cloud-device-checkpoint/v1` ‖ chat coordinate (canonical) ‖ runner
//! encryption, signing and proof pins ‖ authority fingerprint ‖ account key digest. A checkpoint
//! therefore opens only for the same account, hub, chat generation and runner pins.
//!
//! Plaintext: the label ‖ u16 reducer version ‖ cursor ‖ sequence ‖ writer (u64 each) ‖ the last
//! accepted record anchor (optional) ‖ the last witnessed head and its time (optional) ‖ the
//! transcript ([`crate::transcript`] codec). A checkpoint of another reducer version is refused,
//! and the caller reads the chat again from the start. Pending commands and freshness are not
//! stored: a restored reader is `Opening` until a new round completes.
use super::{ChatReader, Position, Witnessed};
use crate::{
    CloudDeviceError,
    context::AccountKeys,
    records::ChatSelector,
    transcript::{
        REDUCER_VERSION, Transcript,
        codec::{Reader, Writer},
    },
    trust::HubCapabilities,
};
use nocterm_hub_model::cloud::{
    RecordKind, RecordPosition, RunCoordinate,
    head::{ChatHead, HeadRecordAnchor},
};
use nocterm_keys::cloud::{CheckpointKey, MAX_CHECKPOINT_PLAINTEXT_BYTES};

const LABEL: &[u8] = b"nocterm/cloud-device-checkpoint/v1";

/// A sealed checkpoint as the client stores it (IndexedDB, a private file). Opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedChat(Vec<u8>);
impl VerifiedChat {
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

fn key(selector: &ChatSelector, keys: &AccountKeys) -> Result<CheckpointKey, CloudDeviceError> {
    let scope = selector.scope();
    if !scope.is_account_key(&keys.public_key()) {
        return Err(CloudDeviceError::Binding);
    }
    let pins = selector.pins();
    let mut context = LABEL.to_vec();
    context.extend_from_slice(&selector.coordinate()?.canonical_bytes()?);
    for part in [pins.encryption, pins.signing, pins.proof] {
        context.extend_from_slice(&part);
    }
    context.extend_from_slice(&scope.authority_fingerprint());
    context.extend_from_slice(&scope.account_key_digest());
    Ok(CheckpointKey::derive(keys.account(), &context)?)
}

impl ChatReader {
    /// Seals the reader's state between rounds.
    pub fn checkpoint(
        &self,
        selector: &ChatSelector,
        keys: &AccountKeys,
    ) -> Result<VerifiedChat, CloudDeviceError> {
        if !self.idle() || &selector.coordinate()? != self.chat() {
            return Err(CloudDeviceError::Checkpoint);
        }
        let mut out = Writer(LABEL.to_vec());
        out.bytes(&REDUCER_VERSION.to_be_bytes());
        let position = self.position();
        out.u64(position.cursor);
        out.u64(position.sequence);
        out.u64(position.writer);
        out.optional(position.last.as_ref(), anchor_out)?;
        out.optional(self.witnessed(), |out, seen| {
            head_out(out, &seen.head)?;
            out.i64(seen.at_ms);
            Ok(())
        })?;
        self.transcript().encode(&mut out)?;
        if out.0.len() > MAX_CHECKPOINT_PLAINTEXT_BYTES {
            return Err(CloudDeviceError::Capacity);
        }
        let sealed = key(selector, keys)?.seal(&out.0);
        zeroize::Zeroize::zeroize(&mut out.0);
        Ok(VerifiedChat(sealed?))
    }
    /// A reader that resumes at a checkpoint of `selector`.
    pub fn restore(
        selector: &ChatSelector,
        capabilities: &HubCapabilities,
        keys: &AccountKeys,
        checkpoint: &VerifiedChat,
    ) -> Result<Self, CloudDeviceError> {
        let plaintext = key(selector, keys)?.open(&checkpoint.0)?;
        let mut input = Reader(&plaintext);
        if input.take(LABEL.len())? != LABEL
            || u16::from_be_bytes(input.array()?) != REDUCER_VERSION
        {
            return Err(CloudDeviceError::Checkpoint);
        }
        let position = Position {
            cursor: input.u64()?,
            sequence: input.u64()?,
            writer: input.u64()?,
            last: input.optional(anchor_in)?,
        };
        let witnessed = input.optional(|input| {
            Ok(Witnessed {
                head: head_in(input)?,
                at_ms: input.i64()?,
            })
        })?;
        let transcript = Transcript::decode(&mut input)?;
        input.finish()?;
        let consistent = position
            .last
            .as_ref()
            .map_or(position.sequence == 0, |last| {
                last.position.sequence == position.sequence
                    && last.position.writer_epoch == position.writer
            });
        if !consistent || position.cursor < position.sequence.min(1) {
            return Err(CloudDeviceError::Checkpoint);
        }
        Self::with_state(selector, capabilities, position, witnessed, transcript)
    }
}

fn anchor_out(out: &mut Writer, anchor: &HeadRecordAnchor) -> Result<(), CloudDeviceError> {
    out.u8(match anchor.kind {
        RecordKind::Event => 1,
        RecordKind::Snapshot => 2,
    });
    let position = &anchor.position;
    for value in [
        position.writer_epoch,
        position.sequence,
        position.journal_sequence,
        position.revision,
    ] {
        out.u64(value);
    }
    out.bytes(&anchor.id);
    out.optional(anchor.run.as_ref(), |out, run| {
        out.bytes(&run.id);
        out.u64(run.expected_epoch);
        Ok(())
    })?;
    out.bytes(&anchor.ciphertext_digest);
    Ok(())
}
fn anchor_in(input: &mut Reader<'_>) -> Result<HeadRecordAnchor, CloudDeviceError> {
    let kind = match input.u8()? {
        1 => RecordKind::Event,
        2 => RecordKind::Snapshot,
        _ => return Err(CloudDeviceError::Checkpoint),
    };
    Ok(HeadRecordAnchor {
        kind,
        position: RecordPosition {
            writer_epoch: input.u64()?,
            sequence: input.u64()?,
            journal_sequence: input.u64()?,
            revision: input.u64()?,
        },
        id: input.array()?,
        run: input.optional(|input| {
            Ok(RunCoordinate {
                id: input.array()?,
                expected_epoch: input.u64()?,
            })
        })?,
        ciphertext_digest: input.array()?,
    })
}
fn head_out(out: &mut Writer, head: &ChatHead) -> Result<(), CloudDeviceError> {
    out.bytes(&head.chat_id);
    out.u64(head.chat_key_epoch);
    out.optional(head.current_writer.as_ref(), |out, writer| {
        out.u64(*writer);
        Ok(())
    })?;
    out.u64(head.control_revision);
    out.bool(head.deleted);
    out.optional(head.head.as_ref(), anchor_out)?;
    out.u64(head.retained_from);
    out.optional(head.snapshot.as_ref(), anchor_out)
}
fn head_in(input: &mut Reader<'_>) -> Result<ChatHead, CloudDeviceError> {
    Ok(ChatHead {
        chat_id: input.array()?,
        chat_key_epoch: input.u64()?,
        current_writer: input.optional(Reader::u64)?,
        control_revision: input.u64()?,
        deleted: input.bool()?,
        head: input.optional(anchor_in)?,
        retained_from: input.u64()?,
        snapshot: input.optional(anchor_in)?,
    })
}
