use std::fmt;
use std::str::FromStr;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{KeyError, random_bytes};

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

/// A 128-bit random secret in the `NK1-…` text form.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 16]);

/// Text that is not a secret key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a Nocterm secret key (expected NK1-XXXXX-…)")]
pub struct SecretKeyParseError;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "NK1";

impl SecretKey {
    /// A fresh random secret key.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self(random_bytes::<16>()?))
    }

    /// Human-readable form `NK1-XXXXX-XXXXX-…` (Crockford base32 with a check digit).
    pub fn display(&self) -> Zeroizing<String> {
        let mut digits = Zeroizing::new(Vec::with_capacity(27));
        let mut acc: u32 = 0;
        let mut bits = 0;
        for byte in self.0 {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                digits.push(ALPHABET[((acc >> bits) & 31) as usize]);
            }
        }
        if bits > 0 {
            digits.push(ALPHABET[((acc << (5 - bits)) & 31) as usize]);
        }
        let check = ALPHABET[checksum(&digits)];
        digits.push(check);
        let mut text = Zeroizing::new(String::from(PREFIX));
        for chunk in digits.chunks(5) {
            text.push('-');
            text.extend(chunk.iter().map(|d| char::from(*d)));
        }
        text
    }

    /// Parses the form produced by [`SecretKey::display`]; dashes and case are ignored.
    pub fn parse(text: &str) -> Result<Self, SecretKeyParseError> {
        let normalized: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| *c != '-' && !c.is_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let body = normalized.strip_prefix(PREFIX).ok_or(SecretKeyParseError)?;
        let digits: Zeroizing<Vec<u8>> = Zeroizing::new(body.bytes().collect());
        if digits.len() != 27 {
            return Err(SecretKeyParseError);
        }
        let (data, check) = digits.split_at(26);
        if ALPHABET[checksum(data)] != check[0] {
            return Err(SecretKeyParseError);
        }
        let mut bytes = [0u8; 16];
        let mut acc: u32 = 0;
        let mut bits = 0;
        let mut out = 0;
        for digit in data {
            let value = ALPHABET
                .iter()
                .position(|a| a == digit)
                .ok_or(SecretKeyParseError)?;
            acc = (acc << 5) | u32::try_from(value).map_err(|_| SecretKeyParseError)?;
            bits += 5;
            if bits >= 8 && out < 16 {
                bits -= 8;
                bytes[out] = u8::try_from((acc >> bits) & 0xff).map_err(|_| SecretKeyParseError)?;
                out += 1;
            }
        }
        acc.zeroize();
        Ok(Self(bytes))
    }
}

/// Weighted check digit: odd weights catch every single-symbol substitution.
fn checksum(digits: &[u8]) -> usize {
    digits
        .iter()
        .enumerate()
        .map(|(i, d)| (2 * i + 1) * ALPHABET.iter().position(|a| a == d).unwrap_or(0))
        .sum::<usize>()
        % 32
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(…)")
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
    fn secret_keys_round_trip_and_detect_typos() {
        let key = SecretKey::generate().unwrap();
        let text = key.display();
        assert!(text.starts_with("NK1-"));
        let parsed = SecretKey::parse(&text.to_lowercase()).unwrap();
        assert_eq!(parsed.0, key.0);

        let mut typo: Vec<char> = text.chars().collect();
        let i = typo.len() - 3;
        typo[i] = if typo[i] == 'A' { 'B' } else { 'A' };
        let typo: String = typo.into_iter().collect();
        assert!(SecretKey::parse(&typo).is_err());
    }
}
