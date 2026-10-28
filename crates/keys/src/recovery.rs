//! The recovery key: a second way to open the account key when the password is forgotten.
//!
//! ```text
//! recovery_wrap = HKDF-SHA256(ikm = recovery key (128 bits), info = "nocterm-recovery-v1/wrap")
//! ```
//!
//! The key is 128 bits of randomness shown once as `NK1-XXXXX-…` and never stored by the
//! client or the hub. It is already uniform, so it goes through HKDF only: a password KDF
//! would add cost without adding strength.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::seal::{Purpose, open, seal};
use crate::{AccountKey, KeyError, OpenError, SealError, random_bytes};

const WRAP_INFO: &[u8] = b"nocterm-recovery-v1/wrap";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "NK1";
const KEY_LEN: usize = 16;
/// 128 bits as 26 base-32 digits (130 bits, two padding bits), plus a check digit.
const DATA_DIGITS: usize = 26;

/// Text that is not a recovery key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a Nocterm recovery key (expected NK1-XXXXX-…)")]
pub struct RecoveryKeyParseError;

/// The 128-bit recovery key of an account.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; KEY_LEN]);

impl RecoveryKey {
    /// A fresh random recovery key.
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self(random_bytes::<KEY_LEN>()?))
    }

    /// Seals the account key so that only this recovery key opens it.
    pub fn wrap(&self, account: &AccountKey, account_id: &str) -> Result<Vec<u8>, SealError> {
        let key = self.wrap_key()?;
        seal(
            &key,
            Purpose::RecoveredAccountKey,
            &[account_id],
            &account.0,
        )
    }

    /// Opens an account key sealed by [`RecoveryKey::wrap`]; it is bound to `account_id`.
    pub fn unwrap(&self, account_id: &str, sealed: &[u8]) -> Result<AccountKey, OpenError> {
        let key = self.wrap_key().map_err(|_| OpenError::Rejected)?;
        let bytes = open(&key, Purpose::RecoveredAccountKey, &[account_id], sealed)?;
        Ok(AccountKey(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| OpenError::Malformed)?,
        ))
    }

    fn wrap_key(&self) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(WRAP_INFO, key.as_mut())
            .map_err(KeyError::Expand)?;
        Ok(key)
    }

    /// The text form `NK1-XXXXX-XXXXX-…` (Crockford base32 with a check digit).
    pub fn display(&self) -> Zeroizing<String> {
        let mut digits = Zeroizing::new(Vec::with_capacity(DATA_DIGITS + 1));
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
        acc.zeroize();
        let mut text = Zeroizing::new(String::from(PREFIX));
        for chunk in digits.chunks(5) {
            text.push('-');
            text.extend(chunk.iter().map(|d| char::from(*d)));
        }
        text
    }

    /// Parses the form produced by [`RecoveryKey::display`]; dashes, spaces and case are
    /// ignored, any other difference (a typo, a non-zero padding bit) is refused.
    pub fn parse(text: &str) -> Result<Self, RecoveryKeyParseError> {
        let normalized: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|c| *c != '-' && !c.is_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let body = normalized
            .strip_prefix(PREFIX)
            .ok_or(RecoveryKeyParseError)?;
        let digits: Zeroizing<Vec<u8>> = Zeroizing::new(body.bytes().collect());
        if digits.len() != DATA_DIGITS + 1 {
            return Err(RecoveryKeyParseError);
        }
        let (data, check) = digits.split_at(DATA_DIGITS);
        if ALPHABET[checksum(data)] != check[0] {
            return Err(RecoveryKeyParseError);
        }
        let mut key = Self([0u8; KEY_LEN]);
        let mut acc: u32 = 0;
        let mut bits = 0;
        let mut out = 0;
        for digit in data {
            let value = ALPHABET
                .iter()
                .position(|a| a == digit)
                .ok_or(RecoveryKeyParseError)?;
            acc = (acc << 5) | u32::try_from(value).map_err(|_| RecoveryKeyParseError)?;
            bits += 5;
            if bits >= 8 && out < KEY_LEN {
                bits -= 8;
                key.0[out] =
                    u8::try_from((acc >> bits) & 0xff).map_err(|_| RecoveryKeyParseError)?;
                out += 1;
            }
        }
        let padding = acc & ((1 << bits) - 1);
        acc.zeroize();
        if padding != 0 {
            return Err(RecoveryKeyParseError);
        }
        Ok(key)
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

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> RecoveryKey {
        RecoveryKey(core::array::from_fn(|i| u8::try_from(i).unwrap()))
    }

    fn account_key() -> AccountKey {
        AccountKey(core::array::from_fn(|i| 0xC0 + u8::try_from(i).unwrap()))
    }

    #[test]
    fn recovery_keys_round_trip_and_detect_typos() {
        let key = RecoveryKey::generate().unwrap();
        let text = key.display();
        assert!(text.starts_with("NK1-"));
        let parsed = RecoveryKey::parse(&text.to_lowercase()).unwrap();
        assert_eq!(parsed.0, key.0);

        let mut typo: Vec<char> = text.chars().collect();
        let i = typo.len() - 3;
        typo[i] = if typo[i] == 'A' { 'B' } else { 'A' };
        let typo: String = typo.into_iter().collect();
        assert!(RecoveryKey::parse(&typo).is_err());
    }

    /// The text form is what users print and type back years later: its alphabet, bit order
    /// and check digit must never change. Computed independently (Python, Crockford base32 of
    /// the key padded with two zero bits, weighted check digit).
    #[test]
    fn the_text_form_matches_the_fixed_vector() {
        assert_eq!(*fixed().display(), "NK1-000G4-0R40M-30E20-9185G-R38E1-W8");
        let parsed = RecoveryKey::parse("nk1 000g4 0r40m 30e20 9185g r38e1 w8").unwrap();
        assert_eq!(parsed.0, fixed().0);
    }

    #[test]
    fn the_text_form_is_stable_and_strict() {
        let text = fixed().display();
        assert_eq!(RecoveryKey::parse(&text).unwrap().0, fixed().0);
        assert!(RecoveryKey::parse("NK1-00000").is_err());
        assert!(RecoveryKey::parse("").is_err());
        assert!(RecoveryKey::parse(&text.replace("NK1", "NK2")).is_err());
        assert!(RecoveryKey::parse(&format!("{}0", *text)).is_err());
    }

    #[test]
    fn the_account_key_comes_back_only_with_the_recovery_key() {
        let key = RecoveryKey::generate().unwrap();
        let sealed = key.wrap(&account_key(), "acc-1").unwrap();
        assert_eq!(key.unwrap("acc-1", &sealed).unwrap().0, account_key().0);

        let other = RecoveryKey::generate().unwrap();
        assert_eq!(
            other.unwrap("acc-1", &sealed).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_wrapped_key_is_bound_to_its_account() {
        let key = RecoveryKey::generate().unwrap();
        let sealed = key.wrap(&account_key(), "acc-1").unwrap();
        assert_eq!(
            key.unwrap("acc-2", &sealed).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_tampered_or_truncated_wrap_is_refused() {
        let key = RecoveryKey::generate().unwrap();
        let mut sealed = key.wrap(&account_key(), "acc-1").unwrap();
        assert_eq!(
            key.unwrap("acc-1", &sealed[..10]).unwrap_err(),
            OpenError::Malformed
        );
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(
            key.unwrap("acc-1", &sealed).unwrap_err(),
            OpenError::Rejected
        );
    }

    #[test]
    fn a_recovery_wrap_does_not_open_as_an_unlock_wrap() {
        let key = RecoveryKey::generate().unwrap();
        let sealed = key.wrap(&account_key(), "acc-1").unwrap();
        let unlock = crate::UnlockKey([9; 32], crate::UnlockSource::VaultPassword);
        assert_eq!(
            AccountKey::open(&unlock, "acc-1", &sealed).unwrap_err(),
            OpenError::Malformed
        );
    }

    /// Sealed by an independent implementation (Python `cryptography` and PyCryptodome).
    #[test]
    fn a_wrap_made_elsewhere_opens() {
        let sealed = hex::decode(concat!(
            "0106303132333435363738393a3b3c3d3e3f40414243444546477aace602fa281f93586d49488470",
            "e607e4d379997990e2a3666735b72b73a0aca51dcac7c40664595f632c86c238b6f7"
        ))
        .unwrap();
        assert_eq!(fixed().unwrap("acc-1", &sealed).unwrap().0, account_key().0);
    }

    #[test]
    fn the_wrap_key_has_its_own_label() {
        let wrap = fixed().wrap_key().unwrap();
        assert_eq!(
            hex::encode(*wrap),
            "490ea83dfb925bfe3807b8a57b7a03ebbeee79ec4ef1fc1be3531a39104c85a4"
        );
    }

    #[test]
    fn the_recovery_key_is_not_printed() {
        let debug = format!("{:?}", fixed());
        assert_eq!(debug, "RecoveryKey(…)");
    }
}
