//! Context for one native chat-head cell protected by the runner identity.
//! This survives content-key retirement; it supplies no writer or freshness proof.
use super::{
    CloudNamespace, CommandError, RunnerCoordinate,
    codec::{self, Reader},
};

pub const MAX_NATIVE_CHAT_HEAD_BYTES: usize = 8 * 1024;
pub const MAX_NATIVE_CHAT_HEAD_CIPHERTEXT_BYTES: usize = MAX_NATIVE_CHAT_HEAD_BYTES + 42;
pub const MAX_NATIVE_CHAT_HEAD_CONTEXT_BYTES: usize = 512;
const LABEL: &[u8] = b"nocterm/cloud-native-chat-head/v1";

/// Independently configured source pins and real metadata coordinates. The
/// installed content-key epoch is a protected native plaintext fact, not a value
/// guessed from this context or copied from the runner's separate key epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeChatHeadCoordinate {
    namespace: CloudNamespace,
    account_key_fingerprint: [u8; 32],
    runner: RunnerCoordinate,
    chat_id: [u8; 16],
    current_writer: Option<u64>,
    metadata_revision: u64,
}
impl NativeChatHeadCoordinate {
    pub fn new(
        namespace: CloudNamespace,
        account_key_fingerprint: [u8; 32],
        runner: RunnerCoordinate,
        chat_id: [u8; 16],
        current_writer: Option<u64>,
        metadata_revision: u64,
    ) -> Result<Self, NativeChatHeadContextError> {
        if runner.key_epoch == 0 || current_writer == Some(0) || metadata_revision == 0 {
            return Err(NativeChatHeadContextError::Position);
        }
        Ok(Self {
            namespace,
            account_key_fingerprint,
            runner,
            chat_id,
            current_writer,
            metadata_revision,
        })
    }
    pub fn namespace(&self) -> &CloudNamespace {
        &self.namespace
    }
    pub fn account_key_fingerprint(&self) -> [u8; 32] {
        self.account_key_fingerprint
    }
    pub fn runner(&self) -> RunnerCoordinate {
        self.runner
    }
    pub fn chat_id(&self) -> [u8; 16] {
        self.chat_id
    }
    pub fn current_writer(&self) -> Option<u64> {
        self.current_writer
    }
    pub fn metadata_revision(&self) -> u64 {
        self.metadata_revision
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeChatHeadContextError> {
        // Both textual identities were bounded by CloudTextId at construction;
        // the fixed remainder keeps the complete context below512 bytes.
        let mut bytes = Vec::with_capacity(MAX_NATIVE_CHAT_HEAD_CONTEXT_BYTES);
        codec::field(&mut bytes, LABEL)?;
        codec::field(
            &mut bytes,
            self.namespace.hub_instance_id.as_str().as_bytes(),
        )?;
        codec::field(&mut bytes, self.namespace.account_id.as_str().as_bytes())?;
        bytes.extend_from_slice(&self.account_key_fingerprint);
        bytes.extend_from_slice(&self.runner.id);
        bytes.extend_from_slice(&self.runner.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.chat_id);
        bytes.push(u8::from(self.current_writer.is_some()));
        if let Some(writer) = self.current_writer {
            bytes.extend_from_slice(&writer.to_be_bytes());
        }
        bytes.extend_from_slice(&self.metadata_revision.to_be_bytes());
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NativeChatHeadContextError> {
        if bytes.len() > MAX_NATIVE_CHAT_HEAD_CONTEXT_BYTES {
            return Err(NativeChatHeadContextError::Malformed);
        }
        let mut input = Reader::new(bytes);
        if input.field(64)? != LABEL {
            return Err(NativeChatHeadContextError::Malformed);
        }
        let namespace = CloudNamespace {
            hub_instance_id: input.text()?,
            account_id: input.text()?,
        };
        let fingerprint = input.array()?;
        let runner = RunnerCoordinate {
            id: input.array()?,
            key_epoch: u64::from_be_bytes(input.array()?),
        };
        let chat = input.array()?;
        let writer = match input.array::<1>()? {
            [0] => None,
            [1] => Some(u64::from_be_bytes(input.array()?)),
            _ => return Err(NativeChatHeadContextError::Malformed),
        };
        let revision = u64::from_be_bytes(input.array()?);
        input.finish()?;
        Self::new(namespace, fingerprint, runner, chat, writer, revision)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeChatHeadContextError {
    #[error("native chat-head runner epoch, present writer and metadata revision must be positive")]
    Position,
    #[error("malformed native chat-head context")]
    Malformed,
    #[error("native chat-head framing is invalid")]
    Framing(#[from] CommandError),
}
#[cfg(test)]
mod tests;
