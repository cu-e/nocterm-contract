//! `cloud-hub-trust` / `hub-authority-v1`: the account's pin of the hub's Cloud authority key.
//!
//! Layout (no outer length): context ‖ authority (32), where context is
//! `nocterm/private-hub-trust/v1` ‖ u16 len ‖ origin ‖ u16 len ‖ raw hub id ‖ u16 len ‖
//! account id ‖ SHA-256(account public key). The origin is the `host:port` the native device
//! configured; a browser does not know it, so it reads the context back from the record and
//! checks the parts it does know ([`HubTrustRecord::matches`]).
use super::{Reader, StoredObject, collection_uuid, push_u16_text};
use crate::{AccountScope, CloudDeviceError};
use nocterm_keys::CollectionKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const HUB_TRUST_KIND: &str = "cloud-hub-trust";
pub const HUB_TRUST_OBJECT: &str = "hub-authority-v1";
const LABEL: &[u8] = b"nocterm/private-hub-trust/v1";
const COLLECTION_LABEL: &[u8] = b"nocterm/private-hub-trust/collection/v1";
const MAX_PLAINTEXT: usize = 4 * 1024;
const MAX_ORIGIN: usize = 2048;
const MAX_ID: usize = 128;

/// One decoded hub-trust record. Its authority is the pin the capability proof must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubTrustRecord {
    origin: String,
    raw_hub: String,
    account_id: String,
    account_key_digest: [u8; 32],
    authority: [u8; 32],
}
impl HubTrustRecord {
    pub fn new(
        origin: &str,
        raw_hub: &str,
        account_id: &str,
        account_key_digest: [u8; 32],
        authority: [u8; 32],
    ) -> Result<Self, CloudDeviceError> {
        if origin.len() > MAX_ORIGIN
            || raw_hub.is_empty()
            || raw_hub.len() > MAX_ID
            || account_id.is_empty()
            || account_id.len() > MAX_ID
        {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(Self {
            origin: origin.to_owned(),
            raw_hub: raw_hub.to_owned(),
            account_id: account_id.to_owned(),
            account_key_digest,
            authority,
        })
    }
    /// The native origin (`host:port`) the record was created for; display only.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn raw_hub(&self) -> &str {
        &self.raw_hub
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn account_key_digest(&self) -> [u8; 32] {
        self.account_key_digest
    }
    /// The pinned Ed25519 Cloud authority public key.
    pub fn authority(&self) -> [u8; 32] {
        self.authority
    }
    /// True when this record was made for this raw hub id, account and account key.
    pub fn matches(&self, raw_hub: &str, account_id: &str, account_public_key: &[u8; 32]) -> bool {
        self.raw_hub == raw_hub
            && self.account_id == account_id
            && <[u8; 32]>::from(Sha256::digest(account_public_key)) == self.account_key_digest
    }
    /// The account scope this pin establishes.
    pub fn scope(&self) -> Result<AccountScope, CloudDeviceError> {
        let fingerprint: [u8; 32] = Sha256::digest(self.authority).into();
        AccountScope::from_parts(
            nocterm_hub_model::cloud::hub_namespace_id(&self.raw_hub, fingerprint)?.as_str(),
            fingerprint,
            &self.account_id,
            self.account_key_digest,
        )
    }
    pub fn context(&self) -> Result<Vec<u8>, CloudDeviceError> {
        let mut bytes = Vec::with_capacity(
            LABEL.len() + 6 + self.origin.len() + self.raw_hub.len() + self.account_id.len() + 32,
        );
        bytes.extend_from_slice(LABEL);
        for text in [&self.origin, &self.raw_hub, &self.account_id] {
            push_u16_text(&mut bytes, text)?;
        }
        bytes.extend_from_slice(&self.account_key_digest);
        Ok(bytes)
    }
    /// The personal collection that holds this record.
    pub fn collection_id(&self) -> Result<String, CloudDeviceError> {
        let mut hash = Sha256::new();
        hash.update(COLLECTION_LABEL);
        hash.update(self.context()?);
        Ok(collection_uuid(&hash.finalize()))
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CloudDeviceError> {
        let mut bytes = Zeroizing::new(self.context()?);
        bytes.extend_from_slice(&self.authority);
        if bytes.len() > MAX_PLAINTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(bytes)
    }
    pub fn decode(plaintext: &[u8]) -> Result<Self, CloudDeviceError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        let mut reader = Reader::new(plaintext);
        if reader.take(LABEL.len())? != LABEL {
            return Err(CloudDeviceError::Format);
        }
        let mut texts = [""; 3];
        for text in &mut texts {
            let length = usize::from(reader.u16()?);
            *text = reader.text(length)?;
        }
        let digest = reader.array()?;
        let authority = reader.array()?;
        reader.finish()?;
        let [origin, raw_hub, account] = texts;
        let record = Self::new(origin, raw_hub, account, digest, authority)?;
        if record.encode()?.as_slice() != plaintext {
            return Err(CloudDeviceError::Format);
        }
        Ok(record)
    }
    /// Opens `hub-authority-v1` from a listed `cloud-hub-trust` collection and checks that the
    /// collection id is the one the record's own context derives.
    pub fn open(key: &CollectionKey, object: &StoredObject<'_>) -> Result<Self, CloudDeviceError> {
        let plaintext = object.open(
            key,
            (object.collection_id, HUB_TRUST_OBJECT, HUB_TRUST_KIND),
            Some(1),
            MAX_PLAINTEXT,
        )?;
        let record = Self::decode(&plaintext)?;
        if record.collection_id()? != object.collection_id {
            return Err(CloudDeviceError::Binding);
        }
        Ok(record)
    }
}
