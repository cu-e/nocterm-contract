use super::{
    MAX_RELAY_FRAME_BYTES, MAX_RELAY_KEY_MATERIAL_BYTES, RelayBinding, RelayFormatError, RelayKind,
};
use crate::cloud::MAX_ENVELOPE_BYTES;
use sha2::{Digest, Sha256};

/// Transport identity is independent of the binding's signed semantic command/event ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationMetadata {
    id: [u8; 16],
    binding: RelayBinding,
    total_bytes: u32,
    digest: [u8; 32],
}
impl PublicationMetadata {
    pub fn new(
        id: [u8; 16],
        binding: RelayBinding,
        total_bytes: u32,
        digest: [u8; 32],
    ) -> Result<Self, RelayFormatError> {
        let total = usize::try_from(total_bytes).map_err(|_| RelayFormatError::Capacity)?;
        if total == 0
            || total > MAX_ENVELOPE_BYTES
            || (binding.kind() == RelayKind::ChatKeyGrant
                && total_bytes > MAX_RELAY_KEY_MATERIAL_BYTES)
        {
            return Err(RelayFormatError::Capacity);
        }
        binding.canonical_bytes()?;
        Ok(Self {
            id,
            binding,
            total_bytes,
            digest,
        })
    }
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    pub fn binding(&self) -> &RelayBinding {
        &self.binding
    }
    pub fn total_bytes(&self) -> u32 {
        self.total_bytes
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Constant-space verifier. The caller stages chunks separately, under its quota.
/// No success value proves authorized publication or a durable database commit.
#[derive(Debug)]
pub struct PublicationVerifier {
    metadata: PublicationMetadata,
    received: u32,
    digest: Sha256,
    finished: bool,
    failed: bool,
}
impl PublicationVerifier {
    pub fn new(metadata: PublicationMetadata) -> Self {
        Self {
            metadata,
            received: 0,
            digest: Sha256::new(),
            finished: false,
            failed: false,
        }
    }
    /// Returns the original staged offset. On any error the verifier is terminally failed.
    pub fn chunk(&mut self, bytes: &[u8]) -> Result<u32, RelayFormatError> {
        if self.finished || self.failed {
            return self.fail(RelayFormatError::FrameOrder);
        }
        if bytes.is_empty() || bytes.len() > MAX_RELAY_FRAME_BYTES {
            return self.fail(RelayFormatError::Capacity);
        }
        let length = u32::try_from(bytes.len()).map_err(|_| RelayFormatError::Capacity)?;
        let next = self
            .received
            .checked_add(length)
            .ok_or(RelayFormatError::Capacity)?;
        if next > self.metadata.total_bytes {
            return self.fail(RelayFormatError::Integrity);
        }
        let offset = self.received;
        self.digest.update(bytes);
        self.received = next;
        Ok(offset)
    }
    pub fn finish_marker(&mut self) -> Result<(), RelayFormatError> {
        if self.finished || self.failed {
            return self.fail(RelayFormatError::FrameOrder);
        }
        if self.received != self.metadata.total_bytes
            || <[u8; 32]>::from(self.digest.clone().finalize()) != self.metadata.digest
        {
            return self.fail(RelayFormatError::Integrity);
        }
        self.finished = true;
        Ok(())
    }
    /// Call only after actual request EOF. Extra/unknown frames must fail the RPC.
    pub fn end_of_stream(self) -> Result<VerifiedPublication, RelayFormatError> {
        if self.failed || !self.finished {
            return Err(RelayFormatError::FrameOrder);
        }
        Ok(VerifiedPublication {
            metadata: self.metadata,
        })
    }
    fn fail<T>(&mut self, error: RelayFormatError) -> Result<T, RelayFormatError> {
        self.failed = true;
        Err(error)
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedPublication {
    metadata: PublicationMetadata,
}
impl VerifiedPublication {
    pub fn metadata(&self) -> &PublicationMetadata {
        &self.metadata
    }
}
