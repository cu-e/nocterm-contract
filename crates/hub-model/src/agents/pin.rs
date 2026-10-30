use super::PoolKeys;

/// How a pool's keys relate to what this device has pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolTrust {
    /// Nothing is pinned for the pool. Show the fingerprint and pin only after the person
    /// confirms it; until then trust nothing.
    FirstUse,
    /// The offered keys are exactly the pinned ones.
    Pinned,
}

/// The pool offered other keys than the pinned ones: a hub or host substitution until proven
/// otherwise. Nothing may be registered or sealed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the pool key changed: pinned {pinned}, offered {offered}")]
pub struct PoolKeyChanged {
    /// Fingerprint of the pinned keys.
    pub pinned: String,
    /// Fingerprint of the keys now offered.
    pub offered: String,
}

/// Compares the keys a hub offers for a pool with the pin of this device (trust on first use).
/// The caller stores the pin; this function only decides.
pub fn check_pool_keys(
    pinned: Option<&PoolKeys>,
    offered: &PoolKeys,
) -> Result<PoolTrust, PoolKeyChanged> {
    match pinned {
        None => Ok(PoolTrust::FirstUse),
        Some(pinned) if pinned == offered => Ok(PoolTrust::Pinned),
        Some(pinned) => Err(PoolKeyChanged {
            pinned: pinned.fingerprint(),
            offered: offered.fingerprint(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: PoolKeys = PoolKeys {
        encryption: [1; 32],
        signing: [2; 32],
    };

    #[test]
    fn an_unknown_pool_is_first_use() {
        assert_eq!(check_pool_keys(None, &A), Ok(PoolTrust::FirstUse));
    }

    #[test]
    fn the_same_keys_are_pinned() {
        assert_eq!(check_pool_keys(Some(&A), &A), Ok(PoolTrust::Pinned));
    }

    #[test]
    fn changing_either_key_is_refused_with_both_fingerprints() {
        for other in [
            PoolKeys {
                encryption: [9; 32],
                ..A
            },
            PoolKeys {
                signing: [9; 32],
                ..A
            },
        ] {
            let err = check_pool_keys(Some(&A), &other).unwrap_err();
            assert_eq!(err.pinned, A.fingerprint());
            assert_eq!(err.offered, other.fingerprint());
        }
    }
}
