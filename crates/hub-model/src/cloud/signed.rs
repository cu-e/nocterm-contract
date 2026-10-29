use super::{
    CommandError, CommandHeader, MAX_HEADER_BYTES, MAX_PLAINTEXT_BYTES,
    codec::{self, Reader},
};
use core::fmt;

/// Device-authenticated bytes. Payload semantics, replay and grants are not admitted.
#[derive(Clone)]
pub struct SignedCommand<'a> {
    header: CommandHeader,
    payload: &'a [u8],
    signature: [u8; 64],
}
impl<'a> SignedCommand<'a> {
    pub fn new(
        header: CommandHeader,
        payload: &'a [u8],
        signature: [u8; 64],
    ) -> Result<Self, CommandError> {
        if !header.matches_payload(payload) {
            return Err(CommandError::PayloadMismatch);
        }
        crate::pop::verify(
            &header.issuer().signing_key,
            &header.canonical_bytes()?,
            &signature,
        )?;
        Ok(Self {
            header,
            payload,
            signature,
        })
    }
    pub fn header(&self) -> &CommandHeader {
        &self.header
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }

    /// Contains plaintext. Callers own and must protect the returned buffer's lifetime.
    pub fn plaintext_bytes(&self) -> Result<Vec<u8>, CommandError> {
        let header = self.header.canonical_bytes()?;
        let mut out = Vec::with_capacity(header.len() + self.payload.len() + 72);
        codec::field(&mut out, &header)?;
        codec::field(&mut out, self.payload)?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn from_plaintext(bytes: &'a [u8]) -> Result<Self, CommandError> {
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(CommandError::PlaintextTooLarge);
        }
        let mut reader = Reader::new(bytes);
        let header = CommandHeader::from_canonical_bytes(reader.field(MAX_HEADER_BYTES)?)?;
        let payload = reader.field(MAX_PLAINTEXT_BYTES)?;
        let signature = reader.array()?;
        reader.finish()?;
        Self::new(header, payload, signature)
    }
}
impl fmt::Debug for SignedCommand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedCommand")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}
