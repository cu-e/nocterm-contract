//! Runner-signed, encrypted event/snapshot framing. No projection or replay policy.
use super::{
    ChatCoordinate, CommandError, MAX_HEADER_BYTES, MAX_PLAINTEXT_BYTES, MaterialError,
    RunCoordinate,
    codec::{self, Reader},
};
use crate::pop::{self, SignatureError};
use core::fmt;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Event = 1,
    Snapshot = 2,
}

/// Distinct delivered-event, native-journal and atomic-transaction coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordPosition {
    pub writer_epoch: u64,
    pub sequence: u64,
    pub journal_sequence: u64,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordContext {
    chat: ChatCoordinate,
    position: RecordPosition,
    id: [u8; 16],
    run: Option<RunCoordinate>,
}
impl RecordContext {
    pub fn new(
        chat: ChatCoordinate,
        position: RecordPosition,
        id: [u8; 16],
        run: Option<RunCoordinate>,
    ) -> Result<Self, RecordError> {
        if position.writer_epoch == 0
            || position.sequence == 0
            || position.journal_sequence == 0
            || position.revision == 0
            || run.is_some_and(|run| run.expected_epoch == 0)
        {
            return Err(RecordError::InvalidPosition);
        }
        Ok(Self {
            chat,
            position,
            id,
            run,
        })
    }
    pub fn chat(&self) -> &ChatCoordinate {
        &self.chat
    }
    pub fn position(&self) -> RecordPosition {
        self.position
    }
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    pub fn run(&self) -> Option<RunCoordinate> {
        self.run
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecordError> {
        let mut bytes = Vec::with_capacity(480);
        codec::field(&mut bytes, b"nocterm/cloud-record-context/v1")?;
        codec::field(&mut bytes, &self.chat.canonical_bytes()?)?;
        for coordinate in [
            self.position.writer_epoch,
            self.position.sequence,
            self.position.journal_sequence,
            self.position.revision,
        ] {
            bytes.extend_from_slice(&coordinate.to_be_bytes());
        }
        bytes.extend_from_slice(&self.id);
        bytes.push(u8::from(self.run.is_some()));
        if let Some(run) = self.run {
            bytes.extend_from_slice(&run.id);
            bytes.extend_from_slice(&run.expected_epoch.to_be_bytes());
        }
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(RecordError::Capacity);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-record-context/v1" {
            return Err(RecordError::Malformed);
        }
        let chat = ChatCoordinate::from_canonical_bytes(reader.field(MAX_HEADER_BYTES)?)?;
        let position = RecordPosition {
            writer_epoch: u64::from_be_bytes(reader.array()?),
            sequence: u64::from_be_bytes(reader.array()?),
            journal_sequence: u64::from_be_bytes(reader.array()?),
            revision: u64::from_be_bytes(reader.array()?),
        };
        let id = reader.array()?;
        let run = match reader.array::<1>()? {
            [0] => None,
            [1] => Some(RunCoordinate {
                id: reader.array()?,
                expected_epoch: u64::from_be_bytes(reader.array()?),
            }),
            _ => return Err(RecordError::Malformed),
        };
        reader.finish()?;
        Self::new(chat, position, id, run)
    }
}

/// Contains only descriptive coordinates and authenticated length/digest, never payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    context: RecordContext,
    kind: RecordKind,
    signer: [u8; 32],
    length: u32,
    digest: [u8; 32],
}
impl RecordHeader {
    pub fn new(
        context: RecordContext,
        kind: RecordKind,
        signer: [u8; 32],
        payload: &[u8],
    ) -> Result<Self, RecordError> {
        if payload.len() > MAX_PLAINTEXT_BYTES {
            return Err(RecordError::Capacity);
        }
        let header = Self {
            context,
            kind,
            signer,
            length: u32::try_from(payload.len()).map_err(|_| RecordError::Capacity)?,
            digest: Sha256::digest(payload).into(),
        };
        header.check_size()?;
        Ok(header)
    }
    pub fn context(&self) -> &RecordContext {
        &self.context
    }
    pub fn kind(&self) -> RecordKind {
        self.kind
    }
    pub fn signer(&self) -> [u8; 32] {
        self.signer
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecordError> {
        let mut bytes = Vec::with_capacity(640);
        codec::field(&mut bytes, b"nocterm/cloud-record/v1")?;
        bytes.push(self.kind as u8);
        codec::field(&mut bytes, &self.context.canonical_bytes()?)?;
        bytes.extend_from_slice(&self.signer);
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(RecordError::Capacity);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-record/v1" {
            return Err(RecordError::Malformed);
        }
        let kind = match reader.array::<1>()? {
            [1] => RecordKind::Event,
            [2] => RecordKind::Snapshot,
            _ => return Err(RecordError::Malformed),
        };
        let context = RecordContext::from_canonical_bytes(reader.field(MAX_HEADER_BYTES)?)?;
        let header = Self {
            context,
            kind,
            signer: reader.array()?,
            length: u32::from_be_bytes(reader.array()?),
            digest: reader.array()?,
        };
        reader.finish()?;
        header.check_size()?;
        Ok(header)
    }
    fn check_size(&self) -> Result<(), RecordError> {
        let header_size = self.canonical_bytes()?.len();
        if header_size > MAX_HEADER_BYTES
            || header_size
                .saturating_add(self.length as usize)
                .saturating_add(72)
                > MAX_PLAINTEXT_BYTES
        {
            return Err(RecordError::Capacity);
        }
        Ok(())
    }
    fn matches(&self, payload: &[u8]) -> bool {
        payload.len() == self.length as usize
            && self.digest == <[u8; 32]>::from(Sha256::digest(payload))
    }
}

#[derive(Clone)]
pub struct SignedRecord<'a> {
    header: RecordHeader,
    payload: &'a [u8],
    signature: [u8; 64],
}
impl<'a> SignedRecord<'a> {
    pub fn new(
        header: RecordHeader,
        payload: &'a [u8],
        signature: [u8; 64],
    ) -> Result<Self, RecordError> {
        header.check_size()?;
        if !header.matches(payload) {
            return Err(RecordError::PayloadMismatch);
        }
        pop::verify(&header.signer, &header.canonical_bytes()?, &signature)?;
        Ok(Self {
            header,
            payload,
            signature,
        })
    }
    pub fn header(&self) -> &RecordHeader {
        &self.header
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn plaintext_bytes(&self) -> Result<Vec<u8>, RecordError> {
        let header = self.header.canonical_bytes()?;
        let mut bytes = Vec::with_capacity(header.len() + self.payload.len() + 72);
        codec::field(&mut bytes, &header)?;
        codec::field(&mut bytes, self.payload)?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }
    pub fn from_plaintext(bytes: &'a [u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(RecordError::Capacity);
        }
        let mut reader = Reader::new(bytes);
        let header = RecordHeader::from_canonical_bytes(reader.field(MAX_HEADER_BYTES)?)?;
        let payload = reader.field(MAX_PLAINTEXT_BYTES)?;
        let signature = reader.array()?;
        reader.finish()?;
        Self::new(header, payload, signature)
    }
}
impl fmt::Debug for SignedRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedRecord")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("the Cloud record position or epoch is invalid")]
    InvalidPosition,
    #[error("the Cloud record exceeds its framing limit")]
    Capacity,
    #[error("malformed or unsupported Cloud record")]
    Malformed,
    #[error("Cloud record payload does not match its signed digest")]
    PayloadMismatch,
    #[error("Cloud record framing is invalid")]
    Framing(#[from] CommandError),
    #[error("Cloud record chat coordinates are invalid")]
    Chat(#[from] MaterialError),
    #[error("Cloud record signature is invalid")]
    Signature(#[from] SignatureError),
}
