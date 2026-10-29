//! Typed failures of hub calls: transport statuses are classified once, here.

use std::fmt;

use nocterm_hub_grpc::metadata;
use nocterm_hub_proto::v1::ErrorCode;
use nocterm_keys::{KeyError, LoginError};

use crate::ConnectError;

/// A hub call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The hub could not be reached or its certificate was not trusted.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// The hub answered with an error status.
    #[error("{message}")]
    Status {
        code: StatusCode,
        /// The hub's machine-readable reason (`x-nocterm-error`), when it sent a known one.
        hub_code: Option<ErrorCode>,
        message: String,
        #[source]
        cause: StatusCause,
    },
    /// The hub speaks another protocol version.
    #[error("the hub speaks protocol {hub}, this client speaks {client}: upgrade")]
    UpgradeRequired { hub: u32, client: u32 },
    #[error("not signed in")]
    NotSignedIn,
    #[error("the original account sign-in was replaced")]
    SessionReplaced,
    /// The hub revoked this device; it must sign in again.
    #[error("this device was revoked; sign in again")]
    Revoked,
    /// The [`crate::SessionStore`] could not lock, load or save the tokens.
    #[error("cannot keep the session tokens")]
    SessionStore(#[source] std::io::Error),
    /// The operating system provided no randomness for a nonce.
    #[error("no randomness for a request nonce")]
    Randomness(#[source] KeyError),
    /// The password or user name cannot be used to derive the login secrets.
    #[error(transparent)]
    Login(LoginError),
    /// The key derivation was cut short: the runtime shut down or the task panicked. The
    /// source tells which.
    #[error("the key derivation was interrupted")]
    DerivationInterrupted(#[source] tokio::task::JoinError),
    #[error("sign-in through the identity provider failed")]
    Oidc(#[from] OidcError),
    #[error("terminal link failed")]
    Link(#[from] LinkError),
}

/// Why a browser sign-in (OIDC loopback with PKCE) failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OidcError {
    /// The loopback listener for the redirect could not bind, accept or read.
    #[error("the loopback redirect listener failed")]
    Loopback(#[source] std::io::Error),
    #[error("no randomness for the PKCE verifier or state")]
    Randomness(#[source] KeyError),
    /// The redirect did not carry the state this client sent (a forged or stale redirect).
    #[error("the redirect carried an unexpected state")]
    UnexpectedState,
    /// The identity provider reported an error (OAuth `error` and `error_description`).
    #[error("the identity provider refused: {error}: {description}")]
    Provider { error: String, description: String },
    #[error("the redirect carried no authorization code")]
    NoCode,
    #[error("timed out waiting for the browser")]
    TimedOut,
}

/// Why the Link (terminal stream) failed before or while carrying a channel.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The hub answered the hello with something other than `Ready`.
    #[error("the hub did not accept the link")]
    NotAccepted,
    /// The outgoing frame queue closed before the hello was sent.
    #[error("the link closed before the hello was sent")]
    Closed,
    /// The hub sent an error frame.
    #[error("{message}")]
    Rejected {
        /// The hub's reason, when it sent a known one.
        code: Option<ErrorCode>,
        message: String,
    },
}

/// gRPC status code of a failed call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusCode {
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl From<tonic::Code> for StatusCode {
    fn from(code: tonic::Code) -> Self {
        use tonic::Code as C;
        match code {
            C::Cancelled => Self::Cancelled,
            // `Ok` never reaches an error; treat it like an unknown failure.
            C::Ok | C::Unknown => Self::Unknown,
            C::InvalidArgument => Self::InvalidArgument,
            C::DeadlineExceeded => Self::DeadlineExceeded,
            C::NotFound => Self::NotFound,
            C::AlreadyExists => Self::AlreadyExists,
            C::PermissionDenied => Self::PermissionDenied,
            C::ResourceExhausted => Self::ResourceExhausted,
            C::FailedPrecondition => Self::FailedPrecondition,
            C::Aborted => Self::Aborted,
            C::OutOfRange => Self::OutOfRange,
            C::Unimplemented => Self::Unimplemented,
            C::Internal => Self::Internal,
            C::Unavailable => Self::Unavailable,
            C::DataLoss => Self::DataLoss,
            C::Unauthenticated => Self::Unauthenticated,
        }
    }
}

/// The transport's original status, kept as the error source (opaque on purpose: the
/// contract does not expose transport types in its errors).
pub struct StatusCause(Box<tonic::Status>);

impl fmt::Debug for StatusCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusCause")
            .field("code", &self.0.code())
            .field("message", &self.0.message())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for StatusCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gRPC status {:?}", self.0.code())
    }
}

impl std::error::Error for StatusCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(self.0.as_ref())
    }
}

impl StatusCause {
    fn metadata(&self, key: &str) -> Option<&str> {
        self.0.metadata().get(key).and_then(|v| v.to_str().ok())
    }
}

/// Classifies a status of the generated service clients; a revoked device becomes
/// [`ClientError::Revoked`].
impl From<tonic::Status> for ClientError {
    fn from(status: tonic::Status) -> Self {
        let cause = StatusCause(Box::new(status));
        let hub_code = cause
            .metadata(metadata::ERROR_CODE)
            .and_then(ErrorCode::from_str_name);
        if hub_code == Some(ErrorCode::DeviceRevoked) {
            return Self::Revoked;
        }
        Self::Status {
            code: cause.0.code().into(),
            hub_code,
            message: cause.0.message().to_owned(),
            cause,
        }
    }
}

impl ClientError {
    /// Whether the hub refused a conditional write because the stored version moved
    /// ([`ErrorCode::Conflict`]).
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::Status {
                hub_code: Some(ErrorCode::Conflict),
                ..
            }
        )
    }

    /// The current version of an object after a [`ErrorCode::Conflict`] on a conditional
    /// write, so the caller can pull and retry.
    pub fn conflict_version(&self) -> Option<u64> {
        match self {
            Self::Status {
                hub_code: Some(ErrorCode::Conflict),
                cause,
                ..
            } => cause.metadata(metadata::CURRENT_VERSION)?.parse().ok(),
            _ => None,
        }
    }
}

impl LinkError {
    /// An error frame of the Link; a revoked device ends the session for good.
    pub(crate) fn from_frame(frame: &nocterm_hub_proto::v1::LinkError) -> ClientError {
        let code = ErrorCode::from_str_name(&frame.code);
        if code == Some(ErrorCode::DeviceRevoked) {
            ClientError::Revoked
        } else {
            ClientError::Link(Self::Rejected {
                code,
                message: frame.message.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[tokio::test]
    async fn an_interrupted_derivation_keeps_the_cause_of_the_interruption() {
        let task = tokio::spawn(std::future::pending::<()>());
        task.abort();
        let cause = task.await.unwrap_err();
        assert!(cause.is_cancelled());

        let err = ClientError::DerivationInterrupted(cause);

        let source = err.source().expect("the join error is the source");
        let join = source
            .downcast_ref::<tokio::task::JoinError>()
            .expect("a join error");
        assert!(join.is_cancelled());
    }
}
