//! The CA document of the personal `agent_ssh_trust` collection (object [`CA_OBJECT`], kind
//! `agent_ssh_trust`): the seed of the CA key and the public keys of the CAs it replaced.
//!
//! Layout (format 1, written by the native client since ADR 0119 and unchanged): UTF-8 JSON
//! `{"format":1,"seed":<standard base64 of 32 bytes>,"created_at_ms":<i64>,"retired":[<standard
//! base64 of 32 bytes>…]}`; `retired` may be absent. Other formats are refused, not guessed. The
//! document is sealed by the collection key, which binds collection id, object id and kind.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::UserCa;

/// The object id of the CA document.
pub const CA_OBJECT: &str = "ca";
/// Replaced CAs kept so their `authorized_keys` lines are still recognised.
pub const MAX_RETIRED: usize = 8;
/// The largest document accepted.
pub const MAX_CA_DOCUMENT_BYTES: usize = 4096;
const FORMAT: u8 = 1;

/// Why a stored CA document cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum CaDocumentError {
    #[error("the CA document is not valid JSON")]
    Json(#[source] serde_json::Error),
    #[error("the CA document has another format or exceeds its bound")]
    Format,
    #[error("the CA document holds a key that is not 32 bytes")]
    Key,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    format: u8,
    seed: String,
    created_at_ms: i64,
    #[serde(default)]
    retired: Vec<String>,
}
impl Drop for Stored {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// The CA of the account and the keys it replaced. `Debug` shows only fingerprints.
pub struct CaDocument {
    ca: UserCa,
    created_at_ms: i64,
    retired: Vec<[u8; 32]>,
}

fn key_of(text: &str) -> Result<Zeroizing<[u8; 32]>, CaDocumentError> {
    let bytes = Zeroizing::new(STANDARD.decode(text).map_err(|_| CaDocumentError::Key)?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CaDocumentError::Key)?;
    Ok(Zeroizing::new(key))
}

impl CaDocument {
    pub fn new(ca: UserCa, created_at_ms: i64) -> Self {
        Self {
            ca,
            created_at_ms,
            retired: Vec::new(),
        }
    }
    /// The document with a new CA; the current key is remembered so its lines are still found.
    #[must_use]
    pub fn replaced(&self, ca: UserCa, now_ms: i64) -> Self {
        let mut retired = self.retired.clone();
        retired.insert(0, self.ca.public_key());
        retired.truncate(MAX_RETIRED);
        Self {
            ca,
            created_at_ms: now_ms,
            retired,
        }
    }
    pub fn ca(&self) -> &UserCa {
        &self.ca
    }
    pub fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }
    /// Public keys of replaced CAs, newest first.
    pub fn retired(&self) -> &[[u8; 32]] {
        &self.retired
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CaDocumentError> {
        let stored = Stored {
            format: FORMAT,
            seed: STANDARD.encode(self.ca.seed()),
            created_at_ms: self.created_at_ms,
            retired: self
                .retired
                .iter()
                .map(|key| STANDARD.encode(key))
                .collect(),
        };
        serde_json::to_vec(&stored)
            .map(Zeroizing::new)
            .map_err(CaDocumentError::Json)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CaDocumentError> {
        if bytes.len() > MAX_CA_DOCUMENT_BYTES {
            return Err(CaDocumentError::Format);
        }
        let stored: Stored = serde_json::from_slice(bytes).map_err(CaDocumentError::Json)?;
        if stored.format != FORMAT || stored.retired.len() > MAX_RETIRED {
            return Err(CaDocumentError::Format);
        }
        let seed = key_of(&stored.seed)?;
        let retired = stored
            .retired
            .iter()
            .map(|key| key_of(key).map(|key| *key))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            ca: UserCa::from_seed(*seed),
            created_at_ms: stored.created_at_ms,
            retired,
        })
    }
}
impl std::fmt::Debug for CaDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaDocument")
            .field("ca", &self.ca)
            .field("created_at_ms", &self.created_at_ms)
            .field("retired", &self.retired.len())
            .finish()
    }
}
