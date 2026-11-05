//! Checked coordinates for per-chat material and encrypted native journal slots.
use super::{CloudNamespace, CommandError, MAX_HEADER_BYTES, RunnerCoordinate, codec};

/// One captured chat and key generation. This value does not authenticate its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatCoordinate {
    namespace: CloudNamespace,
    runner: RunnerCoordinate,
    chat_id: [u8; 16],
    key_epoch: u64,
}

impl ChatCoordinate {
    pub fn new(
        namespace: CloudNamespace,
        runner: RunnerCoordinate,
        chat_id: [u8; 16],
        key_epoch: u64,
    ) -> Result<Self, MaterialError> {
        if runner.key_epoch == 0 || key_epoch == 0 {
            return Err(MaterialError::ZeroEpoch);
        }
        Ok(Self {
            namespace,
            runner,
            chat_id,
            key_epoch,
        })
    }
    pub fn namespace(&self) -> &CloudNamespace {
        &self.namespace
    }
    pub fn runner(&self) -> RunnerCoordinate {
        self.runner
    }
    pub fn chat_id(&self) -> [u8; 16] {
        self.chat_id
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    /// Canonical context bytes, independent of the displayed hub address.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MaterialError> {
        let mut bytes = Vec::with_capacity(352);
        codec::field(&mut bytes, b"nocterm/cloud-chat-coordinate/v1")?;
        codec::field(
            &mut bytes,
            self.namespace.hub_instance_id.as_str().as_bytes(),
        )?;
        codec::field(&mut bytes, self.namespace.account_id.as_str().as_bytes())?;
        bytes.extend_from_slice(&self.runner.id);
        bytes.extend_from_slice(&self.runner.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.chat_id);
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, MaterialError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(CommandError::HeaderTooLarge.into());
        }
        let mut reader = codec::Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-chat-coordinate/v1" {
            return Err(CommandError::UnsupportedVersion.into());
        }
        let namespace = CloudNamespace {
            hub_instance_id: reader.text()?,
            account_id: reader.text()?,
        };
        let runner = RunnerCoordinate {
            id: reader.array()?,
            key_epoch: u64::from_be_bytes(reader.array()?),
        };
        let chat_id = reader.array()?;
        let key_epoch = u64::from_be_bytes(reader.array()?);
        reader.finish()?;
        Self::new(namespace, runner, chat_id, key_epoch)
    }
}

/// Closed storage purposes. These numbers are part of authenticated data.
///
/// The slot layout (`nocterm/cloud-journal-slot/v1`) is unchanged by a new class: a class only
/// adds a purpose byte that older journals never wrote. Classes 1 to 9 exist since the first
/// slot format; [`JournalClass::SshAccess`] (10) since journal class set 2
/// ([`JOURNAL_CLASS_SET`], contract ADR 0011). A native journal that starts writing a class of a
/// newer set bumps its own format version, and a row sealed under another class never opens
/// under this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum JournalClass {
    Header = 1,
    Record = 2,
    CommandReceipt = 3,
    Checkpoint = 4,
    Snapshot = 5,
    Outbox = 6,
    BackgroundCommand = 7,
    Effect = 8,
    RunHead = 9,
    /// A chat's SSH access row: its binding, open certificate request, active certificate and
    /// the sealed seed of its per-chat subject key (contract ADR 0009, 0011). One row per chat;
    /// its slot id is [`SSH_ACCESS_SLOT`].
    SshAccess = 10,
}
impl JournalClass {
    /// The class of a stored purpose byte; `None` for a byte no class set defines.
    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::Header,
            2 => Self::Record,
            3 => Self::CommandReceipt,
            4 => Self::Checkpoint,
            5 => Self::Snapshot,
            6 => Self::Outbox,
            7 => Self::BackgroundCommand,
            8 => Self::Effect,
            9 => Self::RunHead,
            10 => Self::SshAccess,
            _ => return None,
        })
    }
    /// The first class set that defines this class: 1 for classes 1 to 9, 2 for `SshAccess`.
    pub fn since_set(self) -> u8 {
        match self {
            Self::SshAccess => 2,
            _ => 1,
        }
    }
}

/// The newest journal class set this contract defines (contract ADR 0011): set 1 is classes 1
/// to 9, set 2 adds [`JournalClass::SshAccess`].
pub const JOURNAL_CLASS_SET: u8 = 2;

/// The slot id of a chat's one [`JournalClass::SshAccess`] row. The class already separates it
/// from every other slot; the id is fixed (the one native journals used under `Effect` before
/// class set 2) so a migration only changes the class.
pub const SSH_ACCESS_SLOT: [u8; 16] = *b"nocterm-ssh-row1";

/// One encrypted slot in the native journal. Matching it does not prove durability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalCoordinate {
    chat: ChatCoordinate,
    class: JournalClass,
    id: [u8; 16],
    journal_sequence: u64,
    revision: u64,
    writer_epoch: u64,
}

impl JournalCoordinate {
    pub fn new(
        chat: ChatCoordinate,
        class: JournalClass,
        id: [u8; 16],
        journal_sequence: u64,
        revision: u64,
        writer_epoch: u64,
    ) -> Result<Self, MaterialError> {
        if writer_epoch == 0 {
            return Err(MaterialError::ZeroEpoch);
        }
        Ok(Self {
            chat,
            class,
            id,
            journal_sequence,
            revision,
            writer_epoch,
        })
    }
    pub fn chat(&self) -> &ChatCoordinate {
        &self.chat
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MaterialError> {
        let mut bytes = Vec::with_capacity(416);
        codec::field(&mut bytes, b"nocterm/cloud-journal-slot/v1")?;
        bytes.extend_from_slice(&self.chat.canonical_bytes()?);
        bytes.push(self.class as u8);
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.journal_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&self.writer_epoch.to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MaterialError {
    #[error("a Cloud material epoch must be nonzero")]
    ZeroEpoch,
    #[error("Cloud material coordinates could not be encoded")]
    Encoding(#[from] CommandError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_journal_class_reads_back_from_its_tag_and_unknown_tags_are_refused() {
        for tag in 1..=10u8 {
            let class = JournalClass::from_tag(tag).map(|class| class as u8);
            assert_eq!(class, Some(tag));
        }
        assert_eq!(JournalClass::from_tag(0), None);
        assert_eq!(JournalClass::from_tag(11), None);
    }

    #[test]
    fn the_ssh_access_class_belongs_to_the_newest_class_set_and_the_rest_to_the_first() {
        assert_eq!(JournalClass::SshAccess.since_set(), JOURNAL_CLASS_SET);
        assert_eq!(JournalClass::RunHead.since_set(), 1);
        assert_eq!(JournalClass::SshAccess as u8, 10);
    }
}
