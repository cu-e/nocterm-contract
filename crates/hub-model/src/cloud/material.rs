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
}

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
