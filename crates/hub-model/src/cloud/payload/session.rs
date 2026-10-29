//! Finite session startup and descriptive lifecycle; never a pre-login receipt.
use super::{PayloadError, SessionReference, SshConsentBinding, SshProof, TargetAccess};
use crate::cloud::RunCoordinate;

pub const MAX_SESSION_START_MS: u64 = 60_000;
/// One admitted connection. A transport that cannot connect without starting a
/// shell must refuse ConnectOnly instead of silently upgrading it to Terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStartup {
    ConnectOnly = 1,
    Terminal = 2,
}
impl SessionStartup {
    /// Same capability bits as tool grants: Connection, plus Execution for PTY.
    /// These descriptive bits do not install a grant or authorize target I/O.
    pub fn capabilities(self) -> u8 {
        match self {
            Self::ConnectOnly => 8,
            Self::Terminal => 8 | 4,
        }
    }
    pub(super) fn from_tag(value: u8) -> Result<Self, PayloadError> {
        match value {
            1 => Ok(Self::ConnectOnly),
            2 => Ok(Self::Terminal),
            _ => Err(PayloadError::Value),
        }
    }
}

/// Device-issued original attempt coordinates, also valid for Local startup.
/// Local never carries dummy SSH keys, proofs or fabricated live session IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBinding {
    pub run: RunCoordinate,
    pub access: TargetAccess,
    pub attempt: [u8; 16],
    pub nonce: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeginSession<'a> {
    Local {
        binding: SessionBinding,
        startup: SessionStartup,
    },
    Ssh {
        binding: SshConsentBinding<'a>,
        startup: SessionStartup,
    },
}
impl BeginSession<'_> {
    pub fn run(&self) -> RunCoordinate {
        match self {
            Self::Local { binding, .. } => binding.run,
            Self::Ssh { binding, .. } => binding.run,
        }
    }
    pub fn issued_ms(&self) -> u64 {
        match self {
            Self::Local { binding, .. } => binding.issued_ms,
            Self::Ssh { binding, .. } => binding.issued_ms,
        }
    }
    pub fn expires_ms(&self) -> u64 {
        match self {
            Self::Local { binding, .. } => binding.expires_ms,
            Self::Ssh { binding, .. } => binding.expires_ms,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationRequest<'a> {
    pub binding: SshConsentBinding<'a>,
    pub startup: SessionStartup,
    pub proof: SshProof<'a>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionFailure {
    Denied = 1,
    Expired = 2,
    Cancelled = 3,
    SourceChanged = 4,
    Unavailable = 5,
    Unsupported = 6,
    Capacity = 7,
    ConnectionLost = 8,
}
impl SessionFailure {
    pub(super) fn from_tag(value: u8) -> Result<Self, PayloadError> {
        match value {
            1 => Ok(Self::Denied),
            2 => Ok(Self::Expired),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::SourceChanged),
            5 => Ok(Self::Unavailable),
            6 => Ok(Self::Unsupported),
            7 => Ok(Self::Capacity),
            8 => Ok(Self::ConnectionLost),
            _ => Err(PayloadError::Value),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Established(SessionReference),
    Lost {
        session: SessionReference,
        reason: SessionFailure,
    },
    Refused(SessionFailure),
}
/// Public historical observation only. Restoring this description never opens a
/// connection, revives a consent, or installs a native usable SessionReceipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionState {
    pub binding: SessionBinding,
    pub outcome: SessionOutcome,
}

pub(super) fn check_attempt(
    run: RunCoordinate,
    nonce: &[u8; 32],
    issued: u64,
    expires: u64,
) -> Result<(), PayloadError> {
    check_window(run, issued, expires)?;
    if issued == 0 || *nonce == [0; 32] || expires > i64::MAX as u64 {
        return Err(PayloadError::Value);
    }
    Ok(())
}
pub(super) fn check_window(
    run: RunCoordinate,
    issued: u64,
    expires: u64,
) -> Result<(), PayloadError> {
    let duration = expires.checked_sub(issued).ok_or(PayloadError::Value)?;
    if duration == 0 || duration > MAX_SESSION_START_MS || run.expected_epoch == 0 {
        return Err(PayloadError::Value);
    }
    Ok(())
}
