//! Commands kept across a restart (contract ADR 0010).
//!
//! A command is signed and sealed once; every retry publishes exactly those bytes. A client that
//! quits before its command settled keeps it as a [`StoredCommand`] ([`crate::open::OpenChat::stored`])
//! and resumes it with [`crate::open::OpenChat::resume`]: the same publication again, a receipt
//! probe when its outcome stays unknown, and the pending row the person saw before the restart.
//!
//! Format 1, sealed with a key derived from the account key for this chat generation
//! (`reader::checkpoint::chat_key` with label `nocterm/cloud-device-command/v1`), so it opens only
//! for the same account, hub, chat generation and runner pins and a store that holds the bytes
//! (a private file, IndexedDB) learns nothing from them. Plaintext: the label ‖ command id ‖
//! publication id ‖ binding (u32 length) ‖ ciphertext (u32 length) ‖ semantic digest ‖ expected
//! control revision (u64) ‖ accept-before (i64) ‖ pending kind (u8) ‖ pending text (u32 length) ‖
//! run (optional: id ‖ expected epoch) ‖ tracked at (i64). Opening checks every bound, that the
//! binding routes a command of this chat with this command id, and recomputes the digest.
use super::{Deliver, Publication, SealedCommand};
use crate::{
    CloudDeviceError,
    context::{AccountKeys, CloudSession},
    reader::checkpoint::chat_key,
    records::ChatSelector,
    ssh::ChatParts,
    transcript::{
        CommandState, PendingCommand, PendingKind, Transcript,
        codec::{Reader, Writer},
    },
    trust::HubCapabilities,
};
use nocterm_hub_model::cloud::{
    MAX_ENVELOPE_BYTES, RunCoordinate,
    relay::{MAX_RELAY_BINDING_BYTES, RelayBinding},
};

const LABEL: &[u8] = b"nocterm/cloud-device-command/v1";
/// A logical command ciphertext, its binding, bounded pending prompt text and fixed fields.
/// Format 1 framing is unchanged; transport frames do not bound the stored logical ciphertext.
pub const MAX_STORED_COMMAND_PLAINTEXT_BYTES: usize =
    MAX_ENVELOPE_BYTES + crate::open::MAX_PROMPT_TEXT_BYTES + MAX_RELAY_BINDING_BYTES + 512;

/// A sealed, signed command and its pending row as the client keeps them (a private file,
/// IndexedDB). Opaque bytes; the client files it under the chat and
/// [`crate::command::Deliver::command_id`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCommand(Vec<u8>);
impl StoredCommand {
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

fn kind_tag(kind: PendingKind) -> u8 {
    match kind {
        PendingKind::Prompt => 1,
        PendingKind::Stop => 2,
        PendingKind::Allow => 3,
        PendingKind::Answer => 4,
        PendingKind::Provider => 5,
        PendingKind::Bind => 6,
        PendingKind::Unbind => 7,
        PendingKind::Certificate => 8,
    }
}
fn kind_of(tag: u8) -> Result<PendingKind, CloudDeviceError> {
    Ok(match tag {
        1 => PendingKind::Prompt,
        2 => PendingKind::Stop,
        3 => PendingKind::Allow,
        4 => PendingKind::Answer,
        5 => PendingKind::Provider,
        6 => PendingKind::Bind,
        7 => PendingKind::Unbind,
        8 => PendingKind::Certificate,
        _ => return Err(CloudDeviceError::StoredCommand),
    })
}

/// Seals `sealed` with its pending row for `selector`'s chat.
pub(crate) fn store(
    selector: &ChatSelector,
    keys: &AccountKeys,
    sealed: &SealedCommand,
    pending: &PendingCommand,
) -> Result<StoredCommand, CloudDeviceError> {
    let publication = sealed.publication();
    if pending.text.len() > crate::open::MAX_PROMPT_TEXT_BYTES {
        return Err(CloudDeviceError::Capacity);
    }
    let mut out = Writer(LABEL.to_vec());
    out.bytes(&pending.command_id);
    out.bytes(&publication.publication_id());
    let binding = publication.binding()?;
    out.len(binding.len())?;
    out.bytes(&binding);
    out.len(publication.ciphertext().len())?;
    out.bytes(publication.ciphertext());
    out.bytes(&sealed.semantic_digest());
    out.u64(sealed.expected_control_revision());
    out.i64(sealed.accept_before_ms());
    out.u8(kind_tag(pending.kind));
    out.text(&pending.text)?;
    out.optional(pending.run.as_ref(), |out, run| {
        out.bytes(&run.id);
        out.u64(run.expected_epoch);
        Ok(())
    })?;
    out.i64(pending.at_ms);
    if out.0.len() > MAX_STORED_COMMAND_PLAINTEXT_BYTES {
        zeroize::Zeroize::zeroize(&mut out.0);
        return Err(CloudDeviceError::Capacity);
    }
    let stored = chat_key(LABEL, selector, keys)?.seal(&out.0);
    zeroize::Zeroize::zeroize(&mut out.0);
    Ok(StoredCommand(stored?))
}

/// Opens a stored command of `selector`'s chat: the sealed command and its pending row, which is
/// `Sending` again.
pub(crate) fn open(
    selector: &ChatSelector,
    keys: &AccountKeys,
    capabilities: &HubCapabilities,
    stored: &StoredCommand,
) -> Result<(SealedCommand, PendingCommand), CloudDeviceError> {
    if stored.0.len() > MAX_STORED_COMMAND_PLAINTEXT_BYTES + 64 {
        return Err(CloudDeviceError::StoredCommand);
    }
    let plaintext = chat_key(LABEL, selector, keys)?
        .open(&stored.0)
        .map_err(|_| CloudDeviceError::StoredCommand)?;
    let refused = |_| CloudDeviceError::StoredCommand;
    let mut input = Reader(&plaintext);
    if input.take(LABEL.len()).map_err(refused)? != LABEL {
        return Err(CloudDeviceError::StoredCommand);
    }
    let command_id: [u8; 16] = input.array().map_err(refused)?;
    let publication_id = input.array().map_err(refused)?;
    let length = input.len(MAX_RELAY_BINDING_BYTES).map_err(refused)?;
    let binding = RelayBinding::from_canonical_bytes(input.take(length).map_err(refused)?)?;
    let length = input.len(MAX_ENVELOPE_BYTES).map_err(refused)?;
    let ciphertext = input.take(length).map_err(refused)?.to_vec();
    let semantic_digest = input.array().map_err(refused)?;
    let expected_control_revision = input.u64().map_err(refused)?;
    let accept_before_ms = input.i64().map_err(refused)?;
    let kind = kind_of(input.u8().map_err(refused)?)?;
    let length = input
        .len(crate::open::MAX_PROMPT_TEXT_BYTES)
        .map_err(refused)?;
    let text = std::str::from_utf8(input.take(length).map_err(refused)?)
        .map_err(|_| CloudDeviceError::StoredCommand)?
        .to_owned();
    let run = input
        .optional(|input| {
            Ok(RunCoordinate {
                id: input.array()?,
                expected_epoch: input.u64()?,
            })
        })
        .map_err(refused)?;
    let at_ms = input.i64().map_err(refused)?;
    input.finish().map_err(refused)?;
    let route = binding
        .command_route()
        .ok_or(CloudDeviceError::StoredCommand)?;
    if route.namespace != selector.scope().namespace()
        || route.runner != selector.runner()
        || route.chat_id != selector.chat_id()
        || route.command_id != command_id
    {
        return Err(CloudDeviceError::Binding);
    }
    let publication = Publication::with_id(publication_id, binding, ciphertext, capabilities)?;
    let sealed = SealedCommand {
        publication,
        semantic_digest,
        expected_control_revision,
        accept_before_ms,
    };
    let pending = PendingCommand {
        command_id,
        kind,
        text,
        run,
        state: CommandState::Sending,
        at_ms,
    };
    Ok((sealed, pending))
}

/// The stored form of `deliver`'s command once it is sealed; `None` before the device signed it
/// or for a command this chat does not track.
pub(crate) fn keep(
    session: &CloudSession,
    selector: &ChatSelector,
    transcript: &Transcript,
    deliver: &Deliver,
) -> Result<Option<StoredCommand>, CloudDeviceError> {
    let Some(sealed) = deliver.sealed() else {
        return Ok(None);
    };
    let command_id = deliver.command_id();
    let Some(pending) = transcript
        .pending_commands()
        .iter()
        .find(|pending| pending.command_id == command_id)
    else {
        return Ok(None);
    };
    store(selector, session.keys(), sealed, pending).map(Some)
}

/// Tracks a stored command's pending row again and resumes its delivery. `None` when nothing is
/// left to deliver: the runner already started its run, this chat tracks it already, or its
/// admission window ended (then it shows as `Unreachable`).
pub(crate) fn resume(
    parts: ChatParts<'_>,
    stored: &StoredCommand,
    wake: Option<String>,
    now_ms: i64,
) -> Result<Option<Deliver>, CloudDeviceError> {
    let (sealed, mut pending) = open(
        parts.selector,
        parts.session.keys(),
        parts.session.capabilities(),
        stored,
    )?;
    let command_id = pending.command_id;
    let transcript = parts.transcript;
    if transcript
        .pending_commands()
        .iter()
        .any(|known| known.command_id == command_id)
    {
        return Ok(None);
    }
    let started = transcript
        .runs()
        .iter()
        .any(|run| run.prompt_command == command_id);
    if started || now_ms >= sealed.accept_before_ms() {
        pending.state = if started {
            CommandState::Accepted
        } else {
            CommandState::Unreachable
        };
        transcript.track(pending);
        return Ok(None);
    }
    transcript.track(pending);
    Ok(Some(Deliver::resume(
        parts.session.clone(),
        parts.device.clone(),
        parts.selector.clone(),
        sealed,
        command_id,
        wake,
    )))
}

#[cfg(test)]
mod tests;
