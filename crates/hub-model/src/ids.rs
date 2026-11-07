use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A string that is not a valid identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} identifier")]
pub struct IdParseError {
    kind: &'static str,
}

impl IdParseError {
    /// Kind of identifier that failed to parse, for example `account`.
    pub fn kind(&self) -> &'static str {
        self.kind
    }
}

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh random identifier.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wraps an existing UUID.
            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// The underlying UUID.
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.as_hyphenated().fmt(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.as_hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self).map_err(|_| IdParseError { kind: $kind })
            }
        }
    };
}

uuid_id!(
    /// A person known to one hub.
    AccountId,
    "account"
);
uuid_id!(
    /// One installation of a client registered to an account.
    DeviceId,
    "device"
);
uuid_id!(
    /// A collection of end-to-end encrypted objects.
    CollectionId,
    "collection"
);
uuid_id!(
    /// One encrypted object inside a collection.
    ObjectId,
    "object"
);
uuid_id!(
    /// A model provider: an API endpoint with its key.
    ProviderId,
    "provider"
);
uuid_id!(
    /// An agent configuration of an account.
    AgentId,
    "agent"
);
uuid_id!(
    /// An SSH server connected to an account's agents.
    ServerId,
    "server"
);
uuid_id!(
    /// A chat with an agent.
    ChatId,
    "chat"
);
uuid_id!(
    /// One run of an agent in a chat.
    RunId,
    "run"
);
uuid_id!(
    /// A file attached to a chat.
    AttachmentId,
    "attachment"
);
uuid_id!(
    /// An agent worker registered to the hub.
    WorkerId,
    "worker"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_round_trip_through_text() {
        let id = ChatId::new();
        let parsed: ChatId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn invalid_text_names_the_identifier_kind() {
        let err = "nope".parse::<AccountId>().unwrap_err();
        assert_eq!(err.kind(), "account");
        assert_eq!(err.to_string(), "invalid account identifier");
    }
}
