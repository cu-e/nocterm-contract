//! Where flows take probe ids, probe challenges and capability nonces from: the operating
//! system's randomness, or, for recorded test sessions only (feature `testing`), a seeded
//! sequence so a recorded runner answer matches the replayed query.
use crate::CloudDeviceError;
use core::fmt;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, PoisonError};

/// The source of a session's fresh values. Cloning shares the sequence.
#[derive(Clone, Default)]
pub struct Nonces {
    seeded: Option<Arc<Mutex<Seeded>>>,
}
struct Seeded {
    seed: [u8; 32],
    counter: u64,
}
impl Nonces {
    /// The operating system's randomness.
    pub fn os() -> Self {
        Self::default()
    }
    /// A deterministic sequence: SHA-256(`nocterm/cloud-device-test-nonce/v1` ‖ seed ‖ counter).
    /// A reused value is not a freshness proof; recorded test sessions only.
    #[cfg(any(test, feature = "testing"))]
    pub fn seeded(seed: [u8; 32]) -> Self {
        Self {
            seeded: Some(Arc::new(Mutex::new(Seeded { seed, counter: 0 }))),
        }
    }
    pub(crate) fn fill<const N: usize>(&self) -> Result<[u8; N], CloudDeviceError> {
        let Some(seeded) = &self.seeded else {
            return Ok(nocterm_keys::random_bytes()?);
        };
        let mut state = seeded.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = [0; N];
        for chunk in out.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(b"nocterm/cloud-device-test-nonce/v1");
            hash.update(state.seed);
            hash.update(state.counter.to_be_bytes());
            state.counter += 1;
            chunk.copy_from_slice(&hash.finalize()[..chunk.len()]);
        }
        Ok(out)
    }
}
impl fmt::Debug for Nonces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.seeded.is_some() {
            "Nonces(seeded)"
        } else {
            "Nonces(os)"
        })
    }
}
