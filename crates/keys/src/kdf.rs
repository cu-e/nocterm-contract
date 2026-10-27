use std::fmt;
use std::str::FromStr;

/// Public Argon2id parameters stored next to the sealed account key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Iterations.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

/// KDF description that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KdfParseError {
    /// Not of the form `argon2id;m=…;t=…;p=…`.
    #[error("malformed KDF description `{0}`")]
    Malformed(String),
    /// Weaker than the minimum the client accepts.
    #[error("KDF parameters are weaker than the minimum (m=65536, t=3, p=4)")]
    TooWeak,
    /// The salt is shorter than 16 or longer than 64 bytes.
    #[error("the KDF salt must be 16 to 64 bytes")]
    BadSalt,
}

impl KdfParams {
    /// Weakest parameters a client accepts, also the default for new keysets.
    pub const MINIMUM: KdfParams = KdfParams {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 4,
    };

    /// Rejects parameters weaker than [`KdfParams::MINIMUM`].
    pub fn check(self) -> Result<Self, KdfParseError> {
        let min = Self::MINIMUM;
        if self.memory_kib < min.memory_kib
            || self.iterations < min.iterations
            || self.parallelism < min.parallelism
        {
            return Err(KdfParseError::TooWeak);
        }
        Ok(self)
    }
}

impl fmt::Display for KdfParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "argon2id;m={};t={};p={}",
            self.memory_kib, self.iterations, self.parallelism
        )
    }
}

impl FromStr for KdfParams {
    type Err = KdfParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let malformed = || KdfParseError::Malformed(s.to_owned());
        let mut parts = s.split(';');
        if parts.next() != Some("argon2id") {
            return Err(malformed());
        }
        let mut field = |name: &str| -> Result<u32, KdfParseError> {
            parts
                .next()
                .and_then(|part| part.strip_prefix(name))
                .and_then(|value| value.parse().ok())
                .ok_or_else(malformed)
        };
        let params = KdfParams {
            memory_kib: field("m=")?,
            iterations: field("t=")?,
            parallelism: field("p=")?,
        };
        if parts.next().is_some() {
            return Err(malformed());
        }
        params.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_descriptions_round_trip_and_reject_downgrades() {
        let text = KdfParams::MINIMUM.to_string();
        assert_eq!(text, "argon2id;m=65536;t=3;p=4");
        assert_eq!(text.parse::<KdfParams>().unwrap(), KdfParams::MINIMUM);
        assert_eq!(
            "argon2id;m=1024;t=3;p=4".parse::<KdfParams>(),
            Err(KdfParseError::TooWeak)
        );
        assert!("scrypt;m=1;t=1;p=1".parse::<KdfParams>().is_err());
    }
}
