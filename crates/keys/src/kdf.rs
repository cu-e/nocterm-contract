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
#[non_exhaustive]
pub enum KdfParseError {
    /// Not of the form `argon2id;m=…;t=…;p=…`.
    #[error("malformed KDF description `{0}`")]
    Malformed(String),
    /// Weaker than the minimum the client accepts.
    #[error("KDF parameters are weaker than the minimum (m=65536, t=3, p=4)")]
    TooWeak,
    /// Stronger than the maximum the client accepts: a hub could otherwise make the client
    /// allocate gigabytes or compute for hours.
    #[error("KDF parameters exceed the maximum (m=1048576, t=16, p=16)")]
    TooStrong,
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

    /// Strongest parameters a client accepts from a hub (1 GiB, 16 passes, 16 lanes). The
    /// parameters of a keyset are data the hub sends; without an upper bound a hostile hub
    /// could crash the client with an allocation it cannot satisfy or keep it computing.
    pub const MAXIMUM: KdfParams = KdfParams {
        memory_kib: 1024 * 1024,
        iterations: 16,
        parallelism: 16,
    };

    /// Rejects parameters weaker than [`KdfParams::MINIMUM`] or stronger than
    /// [`KdfParams::MAXIMUM`].
    pub fn check(self) -> Result<Self, KdfParseError> {
        let (min, max) = (Self::MINIMUM, Self::MAXIMUM);
        if self.memory_kib < min.memory_kib
            || self.iterations < min.iterations
            || self.parallelism < min.parallelism
        {
            return Err(KdfParseError::TooWeak);
        }
        if self.memory_kib > max.memory_kib
            || self.iterations > max.iterations
            || self.parallelism > max.parallelism
        {
            return Err(KdfParseError::TooStrong);
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

    #[test]
    fn parameters_beyond_the_maximum_are_refused_in_every_dimension() {
        let max = KdfParams::MAXIMUM;
        assert_eq!(max.check(), Ok(max));
        for text in [
            "argon2id;m=4294967295;t=4294967295;p=4",
            "argon2id;m=1048577;t=3;p=4",
            "argon2id;m=65536;t=17;p=4",
            "argon2id;m=65536;t=3;p=17",
        ] {
            assert_eq!(
                text.parse::<KdfParams>(),
                Err(KdfParseError::TooStrong),
                "{text}"
            );
        }
        assert_eq!(
            "argon2id;m=1048576;t=16;p=16".parse::<KdfParams>(),
            Ok(KdfParams::MAXIMUM)
        );
    }
}
