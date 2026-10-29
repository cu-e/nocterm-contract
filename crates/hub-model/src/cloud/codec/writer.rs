//! One bounded canonical sink for buffers, validation counters and argument hashes.
use crate::cloud::CommandError;
use sha2::{Digest, Sha256};
enum Sink {
    Buffer(Vec<u8>),
    Counter,
    Hash(Sha256),
}
pub(in crate::cloud) struct BoundedWriter {
    sink: Sink,
    length: usize,
    maximum: usize,
}
impl BoundedWriter {
    pub(in crate::cloud) fn buffer(maximum: usize) -> Self {
        Self {
            sink: Sink::Buffer(Vec::new()),
            length: 0,
            maximum,
        }
    }
    pub(in crate::cloud) fn counter(maximum: usize) -> Self {
        Self {
            sink: Sink::Counter,
            length: 0,
            maximum,
        }
    }
    pub(in crate::cloud) fn exact_buffer(length: usize) -> Self {
        Self {
            sink: Sink::Buffer(Vec::with_capacity(length)),
            length: 0,
            maximum: length,
        }
    }
    pub(in crate::cloud) fn len(&self) -> usize {
        self.length
    }
    pub(in crate::cloud) fn hasher(maximum: usize) -> Self {
        Self {
            sink: Sink::Hash(Sha256::new()),
            length: 0,
            maximum,
        }
    }
    pub(in crate::cloud) fn extend(&mut self, bytes: &[u8]) -> Result<(), CommandError> {
        let length = self
            .length
            .checked_add(bytes.len())
            .filter(|len| *len <= self.maximum)
            .ok_or(CommandError::PlaintextTooLarge)?;
        match &mut self.sink {
            Sink::Buffer(out) => out.extend_from_slice(bytes),
            Sink::Counter => {}
            Sink::Hash(hash) => hash.update(bytes),
        }
        self.length = length;
        Ok(())
    }
    pub(in crate::cloud) fn field(&mut self, bytes: &[u8]) -> Result<(), CommandError> {
        self.extend(
            &u32::try_from(bytes.len())
                .map_err(|_| CommandError::PlaintextTooLarge)?
                .to_be_bytes(),
        )?;
        self.extend(bytes)
    }
    pub(in crate::cloud) fn into_bytes(self) -> Result<Vec<u8>, CommandError> {
        match self.sink {
            Sink::Buffer(out) => Ok(out),
            Sink::Counter | Sink::Hash(_) => Err(CommandError::Malformed),
        }
    }
    pub(in crate::cloud) fn into_digest(self) -> Result<[u8; 32], CommandError> {
        match self.sink {
            Sink::Hash(hash) => Ok(hash.finalize().into()),
            Sink::Counter | Sink::Buffer(_) => Err(CommandError::Malformed),
        }
    }
}

impl AsMut<BoundedWriter> for BoundedWriter {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}
