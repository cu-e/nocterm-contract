//! Host-to-runner chat access frames (ADR 0003).
//!
//! After the one-shot boot document, an agent host hands its runner the broker tokens of
//! chats over a private control channel (a pipe or inherited descriptor): it issues a chat's
//! token when the hub sends `ChatAccess` ISSUE and revokes it on REVOKE. The host writes
//! frames, the runner reads them; nothing here touches the disk or the hub.
//!
//! A frame is length-delimited and versioned:
//!
//! ```text
//! u32 BE  body length (excluding these 4 bytes), at most MAX_CHAT_ACCESS_FRAME_BYTES - 4
//! body:
//!   u8      version   (CHAT_ACCESS_FRAME_VERSION = 1)
//!   u8      op        (1 = issue, 2 = revoke)
//!   [u8;16] chat id
//!   issue only:
//!     u16 BE  token length, 1..=MAX_ACCESS_TOKEN_BYTES
//!     [u8]    token text (`nvt1_` + base64url without padding)
//! ```
//!
//! A revoke carries no token. A frame with another version or op, a length over the limit,
//! a malformed token or bytes after the last field is refused with a typed error; the reader
//! then closes the channel, since the stream is no longer framed reliably. The token is
//! zeroized on drop and omitted from `Debug`.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::chat_id::CHAT_ID_BYTES;
use super::limits::{MAX_ACCESS_TOKEN_BYTES, MAX_CHAT_ACCESS_FRAME_BYTES};

/// The only frame version this contract writes and reads.
pub const CHAT_ACCESS_FRAME_VERSION: u8 = 1;

/// Prefix of a broker virtual token's text.
const TOKEN_PREFIX: &str = "nvt1_";
/// Bytes of the length prefix.
const LENGTH_BYTES: usize = 4;
/// Version, op and chat id: the head every body starts with.
const HEAD_BYTES: usize = 2 + CHAT_ID_BYTES;

const OP_ISSUE: u8 = 1;
const OP_REVOKE: u8 = 2;

const _: () = assert!(
    LENGTH_BYTES + HEAD_BYTES + 2 + MAX_ACCESS_TOKEN_BYTES <= MAX_CHAT_ACCESS_FRAME_BYTES,
    "the largest issue frame must fit the frame limit"
);

/// A chat access frame that cannot be written or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChatAccessFrameError {
    /// The length prefix announces more than the frame limit.
    #[error("a chat access frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    /// The frame has a version this reader does not know.
    #[error("unknown chat access frame version {0}")]
    UnknownVersion(u8),
    /// The frame has an operation this reader does not know.
    #[error("unknown chat access operation {0}")]
    UnknownOp(u8),
    /// The input ended inside a frame.
    #[error("the chat access frame is truncated")]
    Truncated,
    /// The body continues after its last field (a revoke with a token, for example).
    #[error("the chat access frame has trailing bytes")]
    TrailingBytes,
    /// The token is empty, too long or not a broker virtual token's text.
    #[error("the chat access token is not a broker virtual token")]
    Token,
    /// An earlier frame failed; the channel is no longer framed reliably.
    #[error("the chat access channel failed earlier")]
    Failed,
}

/// A broker virtual token (`nvt1_…`) of one chat. Zeroized on drop; `Debug` omits it.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ChatAccessToken(String);

impl ChatAccessToken {
    /// Checks the shape of a token text: `nvt1_` followed by base64url characters, at most
    /// [`MAX_ACCESS_TOKEN_BYTES`] in all. A refused text is zeroized before returning.
    pub fn new(mut text: String) -> Result<Self, ChatAccessFrameError> {
        if Self::well_formed(&text) {
            Ok(Self(text))
        } else {
            text.zeroize();
            Err(ChatAccessFrameError::Token)
        }
    }

    fn well_formed(text: &str) -> bool {
        text.len() <= MAX_ACCESS_TOKEN_BYTES
            && text.strip_prefix(TOKEN_PREFIX).is_some_and(|body| {
                !body.is_empty()
                    && body
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
    }

    /// The token text, to present to the broker.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ChatAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChatAccessToken(<redacted>)")
    }
}

/// What a frame asks of the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatAccessOp {
    /// Use this token for the chat from now on.
    Issue,
    /// Forget the chat's token; the broker no longer honours it.
    Revoke,
}

/// One instruction of the host to its runner.
#[derive(Debug, PartialEq, Eq)]
pub enum ChatAccessFrame {
    /// The chat's token, freshly minted by the host's broker.
    Issue {
        /// The chat the token serves.
        chat: [u8; CHAT_ID_BYTES],
        /// The token.
        token: ChatAccessToken,
    },
    /// The chat's token is revoked.
    Revoke {
        /// The chat whose token ends.
        chat: [u8; CHAT_ID_BYTES],
    },
}

impl ChatAccessFrame {
    /// The chat the frame is about.
    pub fn chat(&self) -> [u8; CHAT_ID_BYTES] {
        match self {
            Self::Issue { chat, .. } | Self::Revoke { chat } => *chat,
        }
    }

    /// The operation of the frame.
    pub fn op(&self) -> ChatAccessOp {
        match self {
            Self::Issue { .. } => ChatAccessOp::Issue,
            Self::Revoke { .. } => ChatAccessOp::Revoke,
        }
    }

    /// The frame with its length prefix, ready to write. Zeroized on drop.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let token = match self {
            Self::Issue { token, .. } => Some(token.expose().as_bytes()),
            Self::Revoke { .. } => None,
        };
        let body_len = HEAD_BYTES + token.map_or(0, |t| 2 + t.len());
        let mut out = Zeroizing::new(Vec::with_capacity(LENGTH_BYTES + body_len));
        // Both lengths are bounded by the frame limit (checked at compile time above).
        out.extend_from_slice(&u32::try_from(body_len).unwrap_or(u32::MAX).to_be_bytes());
        out.push(CHAT_ACCESS_FRAME_VERSION);
        out.push(match self.op() {
            ChatAccessOp::Issue => OP_ISSUE,
            ChatAccessOp::Revoke => OP_REVOKE,
        });
        out.extend_from_slice(&self.chat());
        if let Some(token) = token {
            out.extend_from_slice(&u16::try_from(token.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.extend_from_slice(token);
        }
        out
    }

    /// Reads exactly one complete frame, length prefix included.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChatAccessFrameError> {
        let mut decoder = ChatAccessDecoder::new();
        let (frame, rest) = decoder.feed(bytes)?;
        match frame {
            Some(_) if !rest.is_empty() => Err(ChatAccessFrameError::TrailingBytes),
            Some(frame) => Ok(frame),
            None => Err(ChatAccessFrameError::Truncated),
        }
    }

    fn decode_body(body: &[u8]) -> Result<Self, ChatAccessFrameError> {
        let (&[version, op], rest) = body
            .split_first_chunk::<2>()
            .ok_or(ChatAccessFrameError::Truncated)?;
        if version != CHAT_ACCESS_FRAME_VERSION {
            return Err(ChatAccessFrameError::UnknownVersion(version));
        }
        if op != OP_ISSUE && op != OP_REVOKE {
            return Err(ChatAccessFrameError::UnknownOp(op));
        }
        let (chat, rest) = rest
            .split_first_chunk::<CHAT_ID_BYTES>()
            .ok_or(ChatAccessFrameError::Truncated)?;
        let chat = *chat;
        if op == OP_REVOKE {
            return if rest.is_empty() {
                Ok(Self::Revoke { chat })
            } else {
                Err(ChatAccessFrameError::TrailingBytes)
            };
        }
        let (len, rest) = rest
            .split_first_chunk::<2>()
            .ok_or(ChatAccessFrameError::Truncated)?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len == 0 || len > MAX_ACCESS_TOKEN_BYTES {
            return Err(ChatAccessFrameError::Token);
        }
        let token = rest.get(..len).ok_or(ChatAccessFrameError::Truncated)?;
        if rest.len() > len {
            return Err(ChatAccessFrameError::TrailingBytes);
        }
        let text = std::str::from_utf8(token).map_err(|_| ChatAccessFrameError::Token)?;
        Ok(Self::Issue {
            chat,
            token: ChatAccessToken::new(text.to_owned())?,
        })
    }
}

/// Incremental reader of a chat access channel.
///
/// It buffers at most one frame (never more than [`MAX_CHAT_ACCESS_FRAME_BYTES`]) and wipes
/// the buffer after each frame. After an error it stays failed: close the channel.
pub struct ChatAccessDecoder {
    buf: Zeroizing<Vec<u8>>,
    failed: bool,
}

impl fmt::Debug for ChatAccessDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatAccessDecoder")
            .field("buffered", &self.buf.len())
            .field("failed", &self.failed)
            .finish()
    }
}

impl Default for ChatAccessDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChatAccessDecoder {
    /// A reader at the start of a channel.
    pub fn new() -> Self {
        Self {
            // Allocated once at its bound, so no reallocation leaves token bytes behind.
            buf: Zeroizing::new(Vec::with_capacity(MAX_CHAT_ACCESS_FRAME_BYTES)),
            failed: false,
        }
    }

    /// Takes from `input` only the bytes of the current frame. Returns the frame once it is
    /// complete, and the input it did not take (the start of the next frame). Call it again
    /// with the rest until the rest is empty.
    pub fn feed<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<(Option<ChatAccessFrame>, &'a [u8]), ChatAccessFrameError> {
        if self.failed {
            return Err(ChatAccessFrameError::Failed);
        }
        let result = self.step(input);
        if result.is_err() {
            self.failed = true;
            self.buf.zeroize();
        }
        result
    }

    fn step<'a>(
        &mut self,
        mut input: &'a [u8],
    ) -> Result<(Option<ChatAccessFrame>, &'a [u8]), ChatAccessFrameError> {
        if self.buf.len() < LENGTH_BYTES {
            input = self.take(input, LENGTH_BYTES - self.buf.len());
            if self.buf.len() < LENGTH_BYTES {
                return Ok((None, input));
            }
        }
        let total = LENGTH_BYTES + self.body_len()?;
        input = self.take(input, total - self.buf.len());
        if self.buf.len() < total {
            return Ok((None, input));
        }
        let frame = ChatAccessFrame::decode_body(&self.buf[LENGTH_BYTES..]);
        self.buf.zeroize();
        Ok((Some(frame?), input))
    }

    /// Body length from the prefix, refused when the frame would exceed the limit.
    fn body_len(&self) -> Result<usize, ChatAccessFrameError> {
        let prefix: [u8; LENGTH_BYTES] = self.buf[..LENGTH_BYTES]
            .try_into()
            .map_err(|_| ChatAccessFrameError::Truncated)?;
        let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
        if len > MAX_CHAT_ACCESS_FRAME_BYTES - LENGTH_BYTES {
            return Err(ChatAccessFrameError::TooLarge(
                len.saturating_add(LENGTH_BYTES),
            ));
        }
        if len < HEAD_BYTES {
            return Err(ChatAccessFrameError::Truncated);
        }
        Ok(len)
    }

    fn take<'a>(&mut self, input: &'a [u8], want: usize) -> &'a [u8] {
        let (now, rest) = input.split_at(want.min(input.len()));
        self.buf.extend_from_slice(now);
        rest
    }

    /// At the end of the channel: an error if a frame was cut off.
    pub fn finish(&self) -> Result<(), ChatAccessFrameError> {
        if self.failed {
            Err(ChatAccessFrameError::Failed)
        } else if self.buf.is_empty() {
            Ok(())
        } else {
            Err(ChatAccessFrameError::Truncated)
        }
    }
}

#[cfg(test)]
#[path = "chat_access_frame_tests.rs"]
mod tests;
