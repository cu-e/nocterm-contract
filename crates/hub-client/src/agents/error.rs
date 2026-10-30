use nocterm_hub_grpc::metadata;
use nocterm_hub_model::agents::{ListingError, RefusalReason};
use nocterm_hub_proto::{WireError, v1};
use prost::Message;

use crate::{ClientError, StatusCode};

/// An agents call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The hub does not offer `AgentService` (it answered `UNIMPLEMENTED`).
    #[error("this hub does not offer managed agents")]
    Unsupported,
    /// A conditional write named a stale version.
    #[error("the agent changed on the hub")]
    Conflict {
        /// The version stored on the hub, when it said so.
        current_version: Option<u64>,
    },
    /// A seat or lease was refused for a typed reason.
    #[error("the request was refused: {0}")]
    Refused(RefusalReason),
    /// Any other failure of the call.
    #[error(transparent)]
    Hub(ClientError),
    /// The hub sent a message that does not describe a valid value.
    #[error("the hub sent an invalid agent message")]
    Wire(#[from] WireError),
    /// The listing to write is outside its bounds; nothing was sent.
    #[error("the agent listing is invalid")]
    Listing(#[from] ListingError),
    /// An envelope, ticket or envelope count is outside its bounds; nothing was sent.
    #[error("an envelope, ticket or the envelope count exceeds its limit")]
    EnvelopeLimit,
    /// The hub kept returning pages beyond the client's bound.
    #[error("the hub returned too many pages")]
    TooManyPages,
}

impl From<tonic::Status> for AgentError {
    fn from(status: tonic::Status) -> Self {
        if status.code() == tonic::Code::ResourceExhausted
            && let Some(reason) = refusal(&status)
        {
            return Self::Refused(reason);
        }
        ClientError::from(status).into()
    }
}

impl From<ClientError> for AgentError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::Status {
                code: StatusCode::Unimplemented,
                ..
            } => Self::Unsupported,
            err if err.is_conflict() => Self::Conflict {
                current_version: err.conflict_version(),
            },
            err => Self::Hub(err),
        }
    }
}

/// The typed reason in `x-nocterm-refusal-bin`, if the hub sent a valid one.
fn refusal(status: &tonic::Status) -> Option<RefusalReason> {
    let bytes = status
        .metadata()
        .get_bin(metadata::REFUSAL)?
        .to_bytes()
        .ok()?;
    let wire = v1::Refusal::decode(bytes.as_ref()).ok()?;
    RefusalReason::try_from(&wire).ok()
}

#[cfg(test)]
mod tests {
    use nocterm_hub_model::agents::AgentScope;
    use tonic::metadata::MetadataValue;

    use super::*;

    fn exhausted(reason: RefusalReason) -> tonic::Status {
        let mut status = tonic::Status::resource_exhausted("no seat");
        status.metadata_mut().insert_bin(
            metadata::REFUSAL,
            MetadataValue::from_bytes(&v1::Refusal::from(reason).encode_to_vec()),
        );
        status
    }

    #[test]
    fn a_refusal_carries_its_typed_reason() {
        for reason in [
            RefusalReason::HostCapacity,
            RefusalReason::ScopeQuota {
                scope: AgentScope::Instance,
            },
            RefusalReason::MemberQuota,
            RefusalReason::Budget,
        ] {
            assert!(matches!(
                AgentError::from(exhausted(reason)),
                AgentError::Refused(got) if got == reason
            ));
        }
    }

    #[test]
    fn exhaustion_without_a_reason_is_a_plain_hub_error() {
        let err = AgentError::from(tonic::Status::resource_exhausted("busy"));
        assert!(matches!(
            err,
            AgentError::Hub(ClientError::Status {
                code: StatusCode::ResourceExhausted,
                ..
            })
        ));
    }

    #[test]
    fn unimplemented_means_unsupported() {
        let err = AgentError::from(tonic::Status::unimplemented("no agents"));
        assert!(matches!(err, AgentError::Unsupported));
    }
}
