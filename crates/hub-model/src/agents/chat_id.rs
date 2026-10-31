//! The text of a chat id in agent messages (`StartInstanceRequest.chat_id`,
//! `StartLease.chat_id`, `RunningLease.chat_id`, `ChatAccess.chat_id`).
//!
//! A chat is known by 16 bytes; agent messages carry them as 32 lowercase hexadecimal
//! characters. Parsing is strict (no uppercase, no separators) so one chat has one text and a
//! hub or host can compare texts byte for byte.

/// Bytes of a chat id.
pub const CHAT_ID_BYTES: usize = 16;

/// A chat id text that is not 32 lowercase hexadecimal characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a chat id must be 32 lowercase hexadecimal characters")]
pub struct ChatIdError;

/// The text of a chat id: 32 lowercase hexadecimal characters.
pub fn chat_id_to_wire(chat: &[u8; CHAT_ID_BYTES]) -> String {
    hex::encode(chat)
}

/// A chat id from its text; anything but 32 lowercase hexadecimal characters is refused.
pub fn chat_id_from_wire(text: &str) -> Result<[u8; CHAT_ID_BYTES], ChatIdError> {
    if text.len() != CHAT_ID_BYTES * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ChatIdError);
    }
    let mut chat = [0; CHAT_ID_BYTES];
    hex::decode_to_slice(text, &mut chat).map_err(|_| ChatIdError)?;
    Ok(chat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chat_id_round_trips_through_its_lowercase_text() {
        let chat = [0xab; CHAT_ID_BYTES];
        let text = chat_id_to_wire(&chat);
        assert_eq!(text, "ab".repeat(16));
        assert_eq!(chat_id_from_wire(&text), Ok(chat));
    }

    #[test]
    fn other_spellings_of_a_chat_id_are_refused() {
        for text in [
            "AB".repeat(16),
            "ab".repeat(15),
            "ab".repeat(17),
            format!("{}zz", "ab".repeat(15)),
            String::new(),
        ] {
            assert_eq!(chat_id_from_wire(&text), Err(ChatIdError), "{text}");
        }
    }
}
