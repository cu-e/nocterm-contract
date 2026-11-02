//! Why a host could not provision an instance (a seat).
//!
//! A host answers `ProvisionInstance` with `InstanceProvisioned`; when it fails it states a
//! short code, the hub stores it on the instance (`Instance.failure_code`) and a client shows
//! [`ProvisionFailure::describe`] instead of a generic failure. The code is never host or
//! provider text, which could carry secrets or paths.

use super::limits::MAX_PROVISION_ERROR_CODE_BYTES;

/// Why provisioning an instance failed. The wire carries [`ProvisionFailure::code`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProvisionFailure {
    /// The hub reached no host of the pool, or the host went away (`host_unreachable`).
    HostUnreachable,
    /// The host has no CPU, memory, disk or instance slot free (`no_capacity`).
    NoCapacity,
    /// The host has no pin for the key of the agent's owner (`owner_unpinned`).
    OwnerUnpinned,
    /// The host has neither a pin nor an accepted stated key for the seat account
    /// (`account_unpinned`).
    AccountUnpinned,
    /// The operator's pin for the seat account disagrees with the key the hub stated
    /// (`account_key_mismatch`).
    AccountKeyMismatch,
    /// The definition did not open or did not validate: wrong context, sender or content
    /// (`definition_invalid`).
    DefinitionInvalid,
    /// The definition's format version is one the host does not open (`unsupported_format`).
    UnsupportedFormat,
    /// A step failed and the host undid the partial instance (`rollback`).
    Rollback,
    /// The runner could not be created or did not start (`runner_failed`).
    RunnerFailed,
    /// The sandbox of the runner could not be set up (`sandbox`).
    Sandbox,
    /// The credential broker refused or failed to register the agent (`broker`).
    Broker,
    /// The instance volume could not be created or given its quota (`host_storage`).
    HostStorage,
    /// The runner setup document could not be built or attested (`malformed_setup`).
    MalformedSetup,
    /// The request names a pool the host does not serve (`wrong_pool`).
    WrongPool,
    /// The request is malformed: a missing or invalid field (`invalid_command`).
    InvalidCommand,
    /// Identifiers in the request disagree with what the host holds for the instance
    /// (`identity_mismatch`).
    IdentityMismatch,
    /// The host does not say why (`unknown`). Also what a client shows for a malformed code.
    Unknown,
    /// A code this contract does not name yet: `[a-z0-9_]`, at most
    /// [`MAX_PROVISION_ERROR_CODE_BYTES`] bytes. Kept so an older client still shows it.
    Other(String),
}

const NAMED: [(&str, ProvisionFailure); 17] = [
    ("host_unreachable", ProvisionFailure::HostUnreachable),
    ("no_capacity", ProvisionFailure::NoCapacity),
    ("owner_unpinned", ProvisionFailure::OwnerUnpinned),
    ("account_unpinned", ProvisionFailure::AccountUnpinned),
    ("account_key_mismatch", ProvisionFailure::AccountKeyMismatch),
    ("definition_invalid", ProvisionFailure::DefinitionInvalid),
    ("unsupported_format", ProvisionFailure::UnsupportedFormat),
    ("rollback", ProvisionFailure::Rollback),
    ("runner_failed", ProvisionFailure::RunnerFailed),
    ("sandbox", ProvisionFailure::Sandbox),
    ("broker", ProvisionFailure::Broker),
    ("host_storage", ProvisionFailure::HostStorage),
    ("malformed_setup", ProvisionFailure::MalformedSetup),
    ("wrong_pool", ProvisionFailure::WrongPool),
    ("invalid_command", ProvisionFailure::InvalidCommand),
    ("identity_mismatch", ProvisionFailure::IdentityMismatch),
    ("unknown", ProvisionFailure::Unknown),
];

/// A provisioning error code that is empty, too long or not `[a-z0-9_]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the provisioning error code is invalid")]
pub struct ProvisionCodeError;

impl ProvisionFailure {
    /// The wire code.
    pub fn code(&self) -> &str {
        if let Self::Other(code) = self {
            return code;
        }
        NAMED
            .iter()
            .find(|(_, failure)| failure == self)
            .map_or("", |(code, _)| code)
    }

    /// Reads a wire code; an unknown well-formed code is [`ProvisionFailure::Other`].
    pub fn from_code(code: &str) -> Result<Self, ProvisionCodeError> {
        if let Some((_, failure)) = NAMED.iter().find(|(name, _)| *name == code) {
            return Ok(failure.clone());
        }
        check_code(code)?;
        Ok(Self::Other(code.to_owned()))
    }

    /// Reads the code of a failed instance as a client shows it: `None` for an empty code
    /// (not failed, or a hub that predates the field), [`ProvisionFailure::Unknown`] for a
    /// malformed one, so a hub cannot make a client display arbitrary text.
    pub fn from_stored(code: &str) -> Option<Self> {
        if code.is_empty() {
            return None;
        }
        Some(Self::from_code(code).unwrap_or(Self::Unknown))
    }

    /// Checks the code before a host sends it or a hub stores it.
    pub fn validate(&self) -> Result<(), ProvisionCodeError> {
        check_code(self.code())
    }

    /// A short English description naming who must act.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::HostUnreachable => "no host of the pool could be reached; try again later",
            Self::NoCapacity => "the pool's hosts have no free capacity; try again later",
            Self::OwnerUnpinned => {
                "the server operator has not pinned the agent owner's key on the pool's hosts"
            }
            Self::AccountUnpinned => {
                "the server operator has not pinned your account key on the pool's hosts"
            }
            Self::AccountKeyMismatch => {
                "the account key the operator pinned on the pool's hosts differs from your \
                 account's key; the server operator must check the pin"
            }
            Self::DefinitionInvalid => {
                "the pool's host could not open the agent's definition; the agent's owner must \
                 save it again"
            }
            Self::UnsupportedFormat => {
                "the pool's hosts are too old for this agent's definition; the server operator \
                 must update them"
            }
            Self::Rollback => "the host could not finish the seat and undid it; try again",
            Self::RunnerFailed => {
                "the agent's runner did not start; the server operator must check the host"
            }
            Self::Sandbox => {
                "the host could not set up the agent's sandbox; the server operator must check the host"
            }
            Self::Broker => {
                "the host's credential broker refused the agent; the server operator must check the host"
            }
            Self::HostStorage => {
                "the host could not create the seat's storage; the server operator must check the host"
            }
            Self::MalformedSetup => {
                "the host could not prepare the runner setup; the server operator must check the host"
            }
            Self::WrongPool => {
                "the server sent the seat to a host of another pool; the server operator must check the pools"
            }
            Self::InvalidCommand => "the host refused a malformed request from the server",
            Self::IdentityMismatch => {
                "the host and the server disagree about the seat; delete it and start again"
            }
            Self::Unknown | Self::Other(_) => "the host could not create the seat",
        }
    }
}

fn check_code(code: &str) -> Result<(), ProvisionCodeError> {
    let well_formed = !code.is_empty()
        && code.len() <= MAX_PROVISION_ERROR_CODE_BYTES
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    well_formed.then_some(()).ok_or(ProvisionCodeError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_codes_round_trip_and_unknown_codes_are_kept() {
        for (code, failure) in &NAMED {
            assert_eq!(failure.code(), *code);
            assert_eq!(ProvisionFailure::from_code(code), Ok(failure.clone()));
            assert!(failure.validate().is_ok());
            assert!(!failure.describe().is_empty());
        }
        assert_eq!(
            ProvisionFailure::from_code("gpu_missing"),
            Ok(ProvisionFailure::Other("gpu_missing".into()))
        );
        assert_eq!(
            ProvisionFailure::Other("gpu_missing".into()).code(),
            "gpu_missing"
        );
    }

    #[test]
    fn named_codes_are_distinct() {
        let mut codes: Vec<_> = NAMED.iter().map(|(code, _)| *code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), NAMED.len());
    }

    #[test]
    fn codes_that_could_carry_host_text_are_refused() {
        for code in [
            "",
            "Rollback",
            "mkdir /srv/x failed",
            "a-b",
            &"x".repeat(MAX_PROVISION_ERROR_CODE_BYTES + 1),
        ] {
            assert_eq!(ProvisionFailure::from_code(code), Err(ProvisionCodeError));
        }
        assert_eq!(
            ProvisionFailure::Other("bad text".into()).validate(),
            Err(ProvisionCodeError)
        );
    }

    #[test]
    fn a_stored_code_reads_as_absent_named_or_unknown() {
        assert_eq!(ProvisionFailure::from_stored(""), None);
        assert_eq!(
            ProvisionFailure::from_stored("owner_unpinned"),
            Some(ProvisionFailure::OwnerUnpinned)
        );
        assert_eq!(
            ProvisionFailure::from_stored("Host said: disk full"),
            Some(ProvisionFailure::Unknown)
        );
    }

    #[test]
    fn the_owner_pin_description_names_the_operator() {
        assert!(
            ProvisionFailure::OwnerUnpinned
                .describe()
                .contains("server operator")
        );
    }
}
