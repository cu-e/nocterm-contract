use super::{CloudTextId, CommandError, MAX_ID_BYTES};
mod writer;
pub(super) use writer::BoundedWriter;

pub(super) fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CommandError> {
    let length = u32::try_from(bytes.len()).map_err(|_| CommandError::PlaintextTooLarge)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], CommandError> {
        let (bytes, rest) = self
            .remaining
            .split_at_checked(count)
            .ok_or(CommandError::Malformed)?;
        self.remaining = rest;
        Ok(bytes)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], CommandError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CommandError::Malformed)
    }

    pub(super) fn field(&mut self, limit: usize) -> Result<&'a [u8], CommandError> {
        let count = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| CommandError::Malformed)?;
        if count > limit {
            return Err(CommandError::Malformed);
        }
        self.take(count)
    }

    pub(super) fn text(&mut self) -> Result<CloudTextId, CommandError> {
        let text =
            core::str::from_utf8(self.field(MAX_ID_BYTES)?).map_err(|_| CommandError::Malformed)?;
        CloudTextId::new(text)
    }

    pub(super) fn finish(self) -> Result<(), CommandError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CommandError::Malformed)
        }
    }
}
