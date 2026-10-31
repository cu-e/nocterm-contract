//! The result of probing an agent's model provider from a pool host.
//!
//! The host's credential broker opens the agent's sealed definition, calls the provider with the
//! real key and reports only this: whether it answered, how fast, the model ids it offers and a
//! short error code. Provider error text is never forwarded, because a provider may echo the
//! key or the request in it.

use super::limits::{MAX_MODEL_ID_BYTES, MAX_PROBE_ERROR_CODE_BYTES, MAX_PROBE_MODELS};

/// How long a hub waits for a host's probe result before it answers
/// [`ProbeFailure::Timeout`] itself. A host bounds its provider call below this.
pub const PROVIDER_PROBE_TIMEOUT_MS: u32 = 15_000;

/// Why a probe failed. The wire carries [`ProbeFailure::code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeFailure {
    /// The provider refused the key (`unauthorized`).
    Unauthorized,
    /// The provider could not be reached: DNS, connection or TLS (`unreachable`).
    Unreachable,
    /// The provider or the host did not answer in time (`timeout`).
    Timeout,
    /// The provider limited the request rate (`rate_limited`).
    RateLimited,
    /// The provider answered with a server error (`provider_error`).
    ProviderError,
    /// The provider's answer was not understood (`bad_response`).
    BadResponse,
    /// The definition carries no API key and the provider needs one (`no_api_key`).
    NoApiKey,
    /// The host could not open the definition: unpinned owner, unknown format or a context
    /// mismatch (`definition_unavailable`).
    DefinitionUnavailable,
    /// No host of the pool that answers probes is online; set by the hub
    /// (`host_unavailable`).
    HostUnavailable,
    /// A code this contract does not name yet: `[a-z0-9_]`, at most
    /// [`MAX_PROBE_ERROR_CODE_BYTES`] bytes.
    Other(String),
}

const NAMED: [(&str, ProbeFailure); 9] = [
    ("unauthorized", ProbeFailure::Unauthorized),
    ("unreachable", ProbeFailure::Unreachable),
    ("timeout", ProbeFailure::Timeout),
    ("rate_limited", ProbeFailure::RateLimited),
    ("provider_error", ProbeFailure::ProviderError),
    ("bad_response", ProbeFailure::BadResponse),
    ("no_api_key", ProbeFailure::NoApiKey),
    (
        "definition_unavailable",
        ProbeFailure::DefinitionUnavailable,
    ),
    ("host_unavailable", ProbeFailure::HostUnavailable),
];

impl ProbeFailure {
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

    /// Reads a wire code; an unknown well-formed code is [`ProbeFailure::Other`].
    pub fn from_code(code: &str) -> Result<Self, ProbeError> {
        if let Some((_, failure)) = NAMED.iter().find(|(name, _)| *name == code) {
            return Ok(failure.clone());
        }
        check_code(code)?;
        Ok(Self::Other(code.to_owned()))
    }
}

fn check_code(code: &str) -> Result<(), ProbeError> {
    let well_formed = !code.is_empty()
        && code.len() <= MAX_PROBE_ERROR_CODE_BYTES
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    well_formed.then_some(()).ok_or(ProbeError::Code)
}

/// What the provider answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The provider accepted the key. `models` are the ids it offers (possibly empty when it
    /// does not list them), at most [`MAX_PROBE_MODELS`].
    Ok {
        /// Model ids the provider offers.
        models: Vec<String>,
    },
    /// The probe failed.
    Failed(ProbeFailure),
}

/// The result of one provider probe. Carries no secret and no provider text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderProbe {
    /// Time from the host's request to the provider's answer, in milliseconds; zero when no
    /// request was made.
    pub latency_ms: u32,
    /// What happened.
    pub outcome: ProbeOutcome,
}

/// A probe result outside its bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// More than [`MAX_PROBE_MODELS`] model ids.
    #[error("the probe reports too many models")]
    TooManyModels,
    /// A model id is empty or longer than [`MAX_MODEL_ID_BYTES`].
    #[error("the probe reports an invalid model id")]
    ModelId,
    /// The error code is empty, too long or not `[a-z0-9_]`.
    #[error("the probe reports an invalid error code")]
    Code,
}

impl ProviderProbe {
    /// A failed probe without a provider request, as a hub reports one it answers itself.
    pub fn failed(failure: ProbeFailure) -> Self {
        Self {
            latency_ms: 0,
            outcome: ProbeOutcome::Failed(failure),
        }
    }

    /// Whether the provider accepted the key.
    pub fn is_ok(&self) -> bool {
        matches!(self.outcome, ProbeOutcome::Ok { .. })
    }

    /// Checks the bounds every side enforces before it sends or accepts a result.
    pub fn validate(&self) -> Result<(), ProbeError> {
        match &self.outcome {
            ProbeOutcome::Ok { models } => {
                if models.len() > MAX_PROBE_MODELS {
                    return Err(ProbeError::TooManyModels);
                }
                if models
                    .iter()
                    .any(|m| m.is_empty() || m.len() > MAX_MODEL_ID_BYTES)
                {
                    return Err(ProbeError::ModelId);
                }
                Ok(())
            }
            ProbeOutcome::Failed(failure) => check_code(failure.code()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_codes_round_trip_and_unknown_codes_are_kept() {
        for (code, failure) in &NAMED {
            assert_eq!(failure.code(), *code);
            assert_eq!(ProbeFailure::from_code(code).unwrap(), *failure);
        }
        assert_eq!(
            ProbeFailure::from_code("quota_exceeded").unwrap(),
            ProbeFailure::Other("quota_exceeded".into())
        );
    }

    #[test]
    fn codes_that_could_carry_provider_text_are_refused() {
        for code in [
            "",
            "Unauthorized",
            "invalid key sk-123",
            "a-b",
            &"x".repeat(MAX_PROBE_ERROR_CODE_BYTES + 1),
        ] {
            assert_eq!(ProbeFailure::from_code(code), Err(ProbeError::Code));
        }
        let smuggled = ProviderProbe::failed(ProbeFailure::Other("sk-live key".into()));
        assert_eq!(smuggled.validate(), Err(ProbeError::Code));
    }

    #[test]
    fn model_lists_are_bounded() {
        let ok = |models: Vec<String>| ProviderProbe {
            latency_ms: 120,
            outcome: ProbeOutcome::Ok { models },
        };
        assert!(ok(vec!["gpt".into()]).validate().is_ok());
        assert!(ok(vec!["gpt".into()]).is_ok());
        assert_eq!(
            ok(vec!["m".into(); MAX_PROBE_MODELS + 1]).validate(),
            Err(ProbeError::TooManyModels)
        );
        assert_eq!(
            ok(vec!["x".repeat(MAX_MODEL_ID_BYTES + 1)]).validate(),
            Err(ProbeError::ModelId)
        );
        assert_eq!(ok(vec![String::new()]).validate(), Err(ProbeError::ModelId));
        assert!(!ProviderProbe::failed(ProbeFailure::Timeout).is_ok());
    }
}
