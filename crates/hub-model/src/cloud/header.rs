use super::{
    CloudRoute, CloudTextId, CommandError, MAX_COMMAND_LIFETIME_MS, MAX_FUTURE_SKEW_MS,
    MAX_HEADER_BYTES, MAX_PLAINTEXT_BYTES,
    codec::{self, Reader},
};
use core::fmt;
use sha2::{Digest, Sha256};

const PURPOSE: &[u8] = b"nocterm/cloud-command/v1";

/// Closed purpose tag; unknown commands never fall back to a prompt or tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CommandKind {
    SubmitPrompt = 1,
    Stop = 2,
    ResolveApproval = 3,
    IssueGrant = 4,
    RevokeGrant = 5,
    AnswerSshConsent = 6,
    DeleteChat = 7,
    RevokeIssuerGrants = 8,
    BeginSession = 9,
}
impl TryFrom<u16> for CommandKind {
    type Error = CommandError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SubmitPrompt),
            2 => Ok(Self::Stop),
            3 => Ok(Self::ResolveApproval),
            4 => Ok(Self::IssueGrant),
            5 => Ok(Self::RevokeGrant),
            6 => Ok(Self::AnswerSshConsent),
            7 => Ok(Self::DeleteChat),
            8 => Ok(Self::RevokeIssuerGrants),
            9 => Ok(Self::BeginSession),
            _ => Err(CommandError::UnsupportedKind),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandKeys {
    pub account: [u8; 32],
    pub runner: [u8; 32],
}

/// Original device identity and the digest of its captured access token.
/// This digest is attribution, not a token-family id or an authorization secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandIssuer {
    pub device_id: CloudTextId,
    pub signing_key: [u8; 32],
    pub access_token_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunCoordinate {
    pub id: [u8; 16],
    pub expected_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandContext {
    pub nonce: [u8; 16],
    pub expected_chat_revision: u64,
    pub run: Option<RunCoordinate>,
    pub kind: CommandKind,
    pub issued_at_ms: i64,
    pub accept_before_ms: i64,
}
impl CommandContext {
    fn validate(&self) -> Result<(), CommandError> {
        let lifetime = i128::from(self.accept_before_ms) - i128::from(self.issued_at_ms);
        if !(0..=i128::from(MAX_COMMAND_LIFETIME_MS)).contains(&lifetime) {
            return Err(CommandError::InvalidTimeWindow);
        }
        Ok(())
    }
}

/// Immutable canonical signed metadata, including the exact raw payload digest.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandHeader {
    route: CloudRoute,
    keys: CommandKeys,
    issuer: CommandIssuer,
    context: CommandContext,
    payload_length: u32,
    payload_digest: [u8; 32],
}

impl CommandHeader {
    pub fn new(
        route: CloudRoute,
        keys: CommandKeys,
        issuer: CommandIssuer,
        context: CommandContext,
        payload: &[u8],
    ) -> Result<Self, CommandError> {
        context.validate()?;
        if payload.len() > MAX_PLAINTEXT_BYTES {
            return Err(CommandError::PlaintextTooLarge);
        }
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| CommandError::PlaintextTooLarge)?;
        let mut header = Self {
            route,
            keys,
            issuer,
            context,
            payload_length,
            payload_digest: [0; 32],
        };
        header.check_sizes()?;
        header.payload_digest = Sha256::digest(payload).into();
        Ok(header)
    }
    pub fn route(&self) -> &CloudRoute {
        &self.route
    }
    pub fn keys(&self) -> CommandKeys {
        self.keys
    }
    pub fn issuer(&self) -> &CommandIssuer {
        &self.issuer
    }
    pub fn context(&self) -> CommandContext {
        self.context
    }
    pub fn payload_length(&self) -> u32 {
        self.payload_length
    }
    pub fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    /// Only for a new admission, after durable idempotency lookup. No clock is read.
    pub fn validate_admission_time(&self, now_ms: i64) -> Result<(), CommandError> {
        if now_ms >= self.context.accept_before_ms {
            return Err(CommandError::Expired);
        }
        if i128::from(self.context.issued_at_ms) - i128::from(now_ms)
            > i128::from(MAX_FUTURE_SKEW_MS)
        {
            return Err(CommandError::IssuedInFuture);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CommandError> {
        let mut bytes = Vec::with_capacity(768);
        codec::field(&mut bytes, PURPOSE)?;
        self.route.write(&mut bytes)?;
        bytes.extend_from_slice(&self.keys.account);
        bytes.extend_from_slice(&self.keys.runner);
        codec::field(&mut bytes, self.issuer.device_id.as_str().as_bytes())?;
        bytes.extend_from_slice(&self.issuer.signing_key);
        bytes.extend_from_slice(&self.issuer.access_token_digest);
        bytes.extend_from_slice(&self.context.nonce);
        bytes.extend_from_slice(&self.context.expected_chat_revision.to_be_bytes());
        bytes.push(u8::from(self.context.run.is_some()));
        if let Some(run) = self.context.run {
            bytes.extend_from_slice(&run.id);
            bytes.extend_from_slice(&run.expected_epoch.to_be_bytes());
        }
        bytes.extend_from_slice(&(self.context.kind as u16).to_be_bytes());
        bytes.extend_from_slice(&self.context.issued_at_ms.to_be_bytes());
        bytes.extend_from_slice(&self.context.accept_before_ms.to_be_bytes());
        bytes.extend_from_slice(&self.payload_length.to_be_bytes());
        bytes.extend_from_slice(&self.payload_digest);
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CommandError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(CommandError::HeaderTooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(MAX_HEADER_BYTES)? != PURPOSE {
            return Err(CommandError::UnsupportedVersion);
        }
        let route = CloudRoute::read(&mut reader)?;
        let keys = CommandKeys {
            account: reader.array()?,
            runner: reader.array()?,
        };
        let issuer = CommandIssuer {
            device_id: reader.text()?,
            signing_key: reader.array()?,
            access_token_digest: reader.array()?,
        };
        let nonce = reader.array()?;
        let expected_chat_revision = u64::from_be_bytes(reader.array()?);
        let run = match reader.array::<1>()?[0] {
            0 => None,
            1 => Some(RunCoordinate {
                id: reader.array()?,
                expected_epoch: u64::from_be_bytes(reader.array()?),
            }),
            _ => return Err(CommandError::Malformed),
        };
        let kind = CommandKind::try_from(u16::from_be_bytes(reader.array()?))?;
        let context = CommandContext {
            nonce,
            expected_chat_revision,
            run,
            kind,
            issued_at_ms: i64::from_be_bytes(reader.array()?),
            accept_before_ms: i64::from_be_bytes(reader.array()?),
        };
        context.validate()?;
        let result = Self {
            route,
            keys,
            issuer,
            context,
            payload_length: u32::from_be_bytes(reader.array()?),
            payload_digest: reader.array()?,
        };
        reader.finish()?;
        result.check_sizes()?;
        Ok(result)
    }

    fn check_sizes(&self) -> Result<(), CommandError> {
        let header_len = self.canonical_bytes()?.len();
        if header_len > MAX_HEADER_BYTES {
            return Err(CommandError::HeaderTooLarge);
        }
        // Each framing length and the signature count toward the single plaintext bound.
        let payload_len =
            usize::try_from(self.payload_length).map_err(|_| CommandError::PlaintextTooLarge)?;
        let plaintext_len = header_len
            .checked_add(payload_len)
            .and_then(|n| n.checked_add(72))
            .ok_or(CommandError::PlaintextTooLarge)?;
        if plaintext_len > MAX_PLAINTEXT_BYTES {
            return Err(CommandError::PlaintextTooLarge);
        }
        Ok(())
    }
    pub(super) fn matches_payload(&self, bytes: &[u8]) -> bool {
        usize::try_from(self.payload_length).ok() == Some(bytes.len())
            && self.payload_digest == <[u8; 32]>::from(Sha256::digest(bytes))
    }
}
impl fmt::Debug for CommandHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandHeader")
            .field("route", &self.route)
            .field("kind", &self.context.kind)
            .field("payload_length", &self.payload_length)
            .finish_non_exhaustive()
    }
}
