//! Which public key belongs to which account, decided by the client and not by the hub.
//!
//! The hub publishes the public key of every account, and a grant is only as trustworthy as
//! the key it was sealed with or for. Trust is first use with a fingerprint: the first time a
//! key of an account is met, a person compares its fingerprint out of band and the client
//! pins it; from then on a different key for that account is a [`PinError::Changed`], never a
//! silent replacement. A hub can still substitute a key at the first meeting, which is why
//! the fingerprint is shown in full ([`crate::PublicKey::fingerprint`]) and compared.
//!
//! The pins are plain data (account identifier and public key): the caller persists them
//! with [`PinnedKeys::entries`] and restores them with [`PinnedKeys::from_entries`].

use std::collections::BTreeMap;

use crate::PublicKey;

/// A public key of one account that was pinned, so it may be used to grant or to open a grant.
///
/// Only [`PinnedKeys`] makes one: holding it means the key matched a pin or was confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    account_id: String,
    key: PublicKey,
}

impl TrustedKey {
    /// The account the key belongs to.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The pinned key.
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// The full fingerprint, for display.
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint()
    }
}

/// A key cannot be trusted for an account.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PinError {
    /// Nothing is pinned for the account: compare `fingerprint` out of band, then pin it.
    #[error("no key is pinned for account {account_id}")]
    Unknown {
        /// The account.
        account_id: String,
        /// Fingerprint of the key the hub offered.
        fingerprint: String,
    },
    /// The hub offers another key than the one pinned: a changed key or an attack.
    #[error("the key of account {account_id} is not the one that was pinned")]
    Changed {
        /// The account.
        account_id: String,
        /// Fingerprint of the pinned key.
        pinned: String,
        /// Fingerprint of the key the hub offered.
        offered: String,
    },
}

/// The pinned public keys of the accounts a client has dealt with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinnedKeys {
    pins: BTreeMap<String, PublicKey>,
}

impl PinnedKeys {
    /// No pins yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins restored from storage; a later entry for an account replaces an earlier one.
    pub fn from_entries<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (S, PublicKey)>,
        S: Into<String>,
    {
        Self {
            pins: entries
                .into_iter()
                .map(|(account, key)| (account.into(), key))
                .collect(),
        }
    }

    /// The pins, in account order, for storage.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &PublicKey)> {
        self.pins
            .iter()
            .map(|(account, key)| (account.as_str(), key))
    }

    /// The key the hub offers for `account_id`, if it is the pinned one.
    pub fn trust(&self, account_id: &str, offered: &PublicKey) -> Result<TrustedKey, PinError> {
        match self.pins.get(account_id) {
            Some(pinned) if pinned == offered => Ok(trusted(account_id, *offered)),
            Some(pinned) => Err(PinError::Changed {
                account_id: account_id.to_owned(),
                pinned: pinned.fingerprint(),
                offered: offered.fingerprint(),
            }),
            None => Err(PinError::Unknown {
                account_id: account_id.to_owned(),
                fingerprint: offered.fingerprint(),
            }),
        }
    }

    /// Pins `confirmed` for `account_id` after a person compared its fingerprint. Pinning the
    /// key that is already pinned is fine; pinning another is [`PinError::Changed`] and needs
    /// [`PinnedKeys::replace`].
    pub fn pin(&mut self, account_id: &str, confirmed: PublicKey) -> Result<TrustedKey, PinError> {
        match self.pins.get(account_id) {
            None => {
                self.pins.insert(account_id.to_owned(), confirmed);
                Ok(trusted(account_id, confirmed))
            }
            Some(_) => self.trust(account_id, &confirmed),
        }
    }

    /// Replaces the pin of `account_id` after a person confirmed the new fingerprint out of
    /// band (the account really changed its key).
    pub fn replace(&mut self, account_id: &str, confirmed: PublicKey) -> TrustedKey {
        self.pins.insert(account_id.to_owned(), confirmed);
        trusted(account_id, confirmed)
    }
}

fn trusted(account_id: &str, key: PublicKey) -> TrustedKey {
    TrustedKey {
        account_id: account_id.to_owned(),
        key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountKeyPair;

    fn key() -> PublicKey {
        AccountKeyPair::generate().unwrap().public_key()
    }

    #[test]
    fn a_key_is_unknown_until_it_is_pinned_and_then_trusted() {
        let mut pins = PinnedKeys::new();
        let admin = key();

        let err = pins.trust("admin", &admin).unwrap_err();
        assert_eq!(
            err,
            PinError::Unknown {
                account_id: "admin".into(),
                fingerprint: admin.fingerprint(),
            }
        );

        let pinned = pins.pin("admin", admin).unwrap();
        assert_eq!(pinned.account_id(), "admin");
        assert_eq!(pinned.public_key(), &admin);
        assert_eq!(pinned.fingerprint(), admin.fingerprint());
        assert_eq!(pins.trust("admin", &admin).unwrap(), pinned);
        // Pinning the same key again changes nothing.
        assert_eq!(pins.pin("admin", admin).unwrap(), pinned);
    }

    #[test]
    fn a_key_the_hub_swaps_after_pinning_is_a_change_not_a_replacement() {
        let mut pins = PinnedKeys::new();
        let (admin, swapped) = (key(), key());
        pins.pin("admin", admin).unwrap();

        let err = pins.trust("admin", &swapped).unwrap_err();
        assert_eq!(
            err,
            PinError::Changed {
                account_id: "admin".into(),
                pinned: admin.fingerprint(),
                offered: swapped.fingerprint(),
            }
        );
        assert!(matches!(
            pins.pin("admin", swapped),
            Err(PinError::Changed { .. })
        ));
        assert!(pins.trust("admin", &admin).is_ok());
    }

    #[test]
    fn a_confirmed_new_key_replaces_the_pin_and_the_old_one_stops_working() {
        let mut pins = PinnedKeys::new();
        let (old, new) = (key(), key());
        pins.pin("admin", old).unwrap();

        let trusted = pins.replace("admin", new);

        assert_eq!(trusted.public_key(), &new);
        assert!(pins.trust("admin", &new).is_ok());
        assert!(matches!(
            pins.trust("admin", &old),
            Err(PinError::Changed { .. })
        ));
    }

    #[test]
    fn pins_survive_storage_and_belong_to_their_account() {
        let mut pins = PinnedKeys::new();
        let (a, b) = (key(), key());
        pins.pin("a", a).unwrap();
        pins.pin("b", b).unwrap();

        let stored: Vec<(String, PublicKey)> = pins
            .entries()
            .map(|(account, key)| (account.to_owned(), *key))
            .collect();
        let restored = PinnedKeys::from_entries(stored);

        assert_eq!(restored, pins);
        assert!(restored.trust("a", &a).is_ok());
        // The key of one account is not trusted for another.
        assert!(matches!(
            restored.trust("a", &b),
            Err(PinError::Changed { .. })
        ));
    }
}
