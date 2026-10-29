use super::CloudCommandError;
use crate::seal::{FORMAT_VERSION, Purpose};
use nocterm_hub_model::cloud::{MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES};

const HEADER_BYTES: usize = 62;

pub(super) struct Envelope<'a> {
    pub(super) ephemeral: [u8; 32],
    pub(super) nonce: [u8; 24],
    pub(super) ciphertext: &'a [u8],
}
impl<'a> Envelope<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self, CloudCommandError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(CloudCommandError::EnvelopeTooLarge);
        }
        if bytes.len() < HEADER_BYTES {
            return Err(CloudCommandError::MalformedEnvelope);
        }
        if bytes[0] != FORMAT_VERSION {
            return Err(CloudCommandError::UnsupportedVersion);
        }
        if bytes[1] != Purpose::CloudCommand as u8 {
            return Err(CloudCommandError::WrongPurpose);
        }
        let length = u32::from_be_bytes(
            bytes[58..62]
                .try_into()
                .map_err(|_| CloudCommandError::MalformedEnvelope)?,
        );
        let length = usize::try_from(length).map_err(|_| CloudCommandError::EnvelopeTooLarge)?;
        if length > MAX_PLAINTEXT_BYTES + 16 {
            return Err(CloudCommandError::EnvelopeTooLarge);
        }
        if length < 16 || bytes.len() - HEADER_BYTES != length {
            return Err(CloudCommandError::MalformedEnvelope);
        }
        Ok(Self {
            ephemeral: bytes[2..34]
                .try_into()
                .map_err(|_| CloudCommandError::MalformedEnvelope)?,
            nonce: bytes[34..58]
                .try_into()
                .map_err(|_| CloudCommandError::MalformedEnvelope)?,
            ciphertext: &bytes[HEADER_BYTES..],
        })
    }
    pub(super) fn encode(
        ephemeral: [u8; 32],
        nonce: [u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CloudCommandError> {
        if ciphertext.len() > MAX_PLAINTEXT_BYTES + 16 {
            return Err(CloudCommandError::EnvelopeTooLarge);
        }
        let length =
            u32::try_from(ciphertext.len()).map_err(|_| CloudCommandError::EnvelopeTooLarge)?;
        let mut bytes = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
        bytes.extend_from_slice(&[FORMAT_VERSION, Purpose::CloudCommand as u8]);
        bytes.extend_from_slice(&ephemeral);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(ciphertext);
        Ok(bytes)
    }
}
