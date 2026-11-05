//! `cloud-chat-material` (the chat key wrapped for the account) and `cloud-chat-grant` (the
//! sealed grant of that key to the runner, stored before it is published).
//!
//! Both kinds live in one personal collection per account scope and kind, whose id is
//! UUIDv8(SHA-256(`nocterm/cloud/account-material-collection/v1` ‖ for hub namespace, account
//! id and kind: u64 len ‖ bytes ‖ authority fingerprint ‖ account key digest)). The object id of
//! a chat generation is hex(SHA-256(chat coordinate ‖ authority fingerprint ‖ account key
//! digest)), the same in both collections.
//!
//! Material plaintext: 1 ‖ u8 len ‖ hub namespace ‖ u8 len ‖ account id ‖ authority fingerprint
//! ‖ account key digest ‖ runner id (16) ‖ runner key epoch u64 ‖ chat id (16) ‖ chat key epoch
//! u64 ‖ encryption ‖ signing ‖ proof pins ‖ wrapped key (74). Grant plaintext: 1 ‖ publication
//! id (16) ‖ sealed grant (1..=1024 bytes).
use super::{RunnerPins, StoredObject, collection_uuid};
use crate::{AccountScope, CloudDeviceError};
use nocterm_hub_model::cloud::{ChatCoordinate, RunnerCoordinate};
use nocterm_keys::{AccountKey, CollectionKey, cloud::ChatKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const CHAT_MATERIAL_KIND: &str = "cloud-chat-material";
pub const CHAT_GRANT_KIND: &str = "cloud-chat-grant";
const COLLECTION_LABEL: &[u8] = b"nocterm/cloud/account-material-collection/v1";
const VERSION: u8 = 1;
const WRAPPED_KEY: usize = 74;
const MAX_MATERIAL: usize = 1024;
const MAX_GRANT_CIPHERTEXT: usize = 1024;
const MAX_GRANT: usize = 1 + 16 + MAX_GRANT_CIPHERTEXT;

/// The personal collection of one account object kind (`cloud-chat-material` or
/// `cloud-chat-grant`).
pub fn account_collection_id(scope: &AccountScope, kind: &str) -> Result<String, CloudDeviceError> {
    let mut hash = Sha256::new();
    hash.update(COLLECTION_LABEL);
    for field in [
        scope.hub_instance().as_bytes(),
        scope.account_id().as_bytes(),
        kind.as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.update(scope.authority_fingerprint());
    hash.update(scope.account_key_digest());
    Ok(collection_uuid(&hash.finalize()))
}

/// One chat key generation of one runner in one account scope, with the pins it was made for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatSelector {
    scope: AccountScope,
    runner: RunnerCoordinate,
    chat_id: [u8; 16],
    key_epoch: u64,
    pins: RunnerPins,
}
impl ChatSelector {
    pub fn new(
        scope: AccountScope,
        runner: RunnerCoordinate,
        chat_id: [u8; 16],
        key_epoch: u64,
        pins: RunnerPins,
    ) -> Result<Self, CloudDeviceError> {
        let selector = Self {
            scope,
            runner,
            chat_id,
            key_epoch,
            pins,
        };
        selector.coordinate()?;
        Ok(selector)
    }
    pub fn scope(&self) -> &AccountScope {
        &self.scope
    }
    pub fn runner(&self) -> RunnerCoordinate {
        self.runner
    }
    pub fn chat_id(&self) -> [u8; 16] {
        self.chat_id
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn pins(&self) -> RunnerPins {
        self.pins
    }
    pub fn coordinate(&self) -> Result<ChatCoordinate, CloudDeviceError> {
        Ok(ChatCoordinate::new(
            self.scope.namespace(),
            self.runner,
            self.chat_id,
            self.key_epoch,
        )?)
    }
    /// The object id of this generation in both the material and the grant collection.
    pub fn object_id(&self) -> Result<String, CloudDeviceError> {
        let mut hash = Sha256::new();
        hash.update(self.coordinate()?.canonical_bytes()?);
        hash.update(self.scope.authority_fingerprint());
        hash.update(self.scope.account_key_digest());
        Ok(hex::encode(hash.finalize()))
    }
    fn prefix(&self) -> Result<Vec<u8>, CloudDeviceError> {
        let hub = self.scope.hub_instance().as_bytes();
        let account = self.scope.account_id().as_bytes();
        let mut bytes = Vec::with_capacity(MAX_MATERIAL - WRAPPED_KEY);
        bytes.push(VERSION);
        bytes.push(u8::try_from(hub.len()).map_err(|_| CloudDeviceError::Capacity)?);
        bytes.extend_from_slice(hub);
        bytes.push(u8::try_from(account.len()).map_err(|_| CloudDeviceError::Capacity)?);
        bytes.extend_from_slice(account);
        bytes.extend_from_slice(&self.scope.authority_fingerprint());
        bytes.extend_from_slice(&self.scope.account_key_digest());
        bytes.extend_from_slice(&self.runner.id);
        bytes.extend_from_slice(&self.runner.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.chat_id);
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.pins.encryption);
        bytes.extend_from_slice(&self.pins.signing);
        bytes.extend_from_slice(&self.pins.proof);
        Ok(bytes)
    }
}

/// The chat key of one generation, wrapped by the account key. Pins are authenticated payload,
/// not selectors: another pin for the same generation is a different, conflicting record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatMaterialRecord {
    selector: ChatSelector,
    wrapped: Vec<u8>,
}
impl ChatMaterialRecord {
    pub fn new(selector: ChatSelector, wrapped: Vec<u8>) -> Result<Self, CloudDeviceError> {
        if wrapped.len() != WRAPPED_KEY {
            return Err(CloudDeviceError::Format);
        }
        Ok(Self { selector, wrapped })
    }
    /// Wraps `key` for the account under the selector's coordinate.
    pub fn wrap(
        selector: ChatSelector,
        key: &ChatKey,
        account: &AccountKey,
    ) -> Result<Self, CloudDeviceError> {
        let wrapped = key.seal_for_account(account, &selector.coordinate()?)?;
        Self::new(selector, wrapped)
    }
    pub fn selector(&self) -> &ChatSelector {
        &self.selector
    }
    pub fn wrapped(&self) -> &[u8] {
        &self.wrapped
    }
    pub fn collection_id(scope: &AccountScope) -> Result<String, CloudDeviceError> {
        account_collection_id(scope, CHAT_MATERIAL_KIND)
    }
    /// Opens the chat key. Use it for one operation and drop it.
    pub fn open_key(&self, account: &AccountKey) -> Result<ChatKey, CloudDeviceError> {
        Ok(ChatKey::open_for_account(
            account,
            &self.selector.coordinate()?,
            &self.wrapped,
        )?)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CloudDeviceError> {
        let mut bytes = Zeroizing::new(self.selector.prefix()?);
        bytes.extend_from_slice(&self.wrapped);
        if bytes.len() > MAX_MATERIAL {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(bytes)
    }
    pub fn decode(selector: ChatSelector, plaintext: &[u8]) -> Result<Self, CloudDeviceError> {
        if plaintext.len() > MAX_MATERIAL {
            return Err(CloudDeviceError::Capacity);
        }
        let prefix = selector.prefix()?;
        let wrapped = plaintext
            .strip_prefix(prefix.as_slice())
            .filter(|rest| rest.len() == WRAPPED_KEY)
            .ok_or(CloudDeviceError::Binding)?
            .to_vec();
        Self::new(selector, wrapped)
    }
    /// Opens the record of `selector` and checks the wrapped key opens under `account`.
    pub fn open(
        key: &CollectionKey,
        selector: ChatSelector,
        object: &StoredObject<'_>,
        account: &AccountKey,
    ) -> Result<Self, CloudDeviceError> {
        let collection = Self::collection_id(selector.scope())?;
        let id = selector.object_id()?;
        let plaintext = object.open(
            key,
            (&collection, &id, CHAT_MATERIAL_KIND),
            Some(1),
            MAX_MATERIAL,
        )?;
        let record = Self::decode(selector, &plaintext)?;
        drop(record.open_key(account)?);
        Ok(record)
    }
    /// The sealed object for a compare-create `PutObject` at expected version 0.
    pub fn seal(&self, key: &CollectionKey) -> Result<Vec<u8>, CloudDeviceError> {
        let collection = Self::collection_id(self.selector.scope())?;
        Ok(key.seal_object(
            &collection,
            &self.selector.object_id()?,
            CHAT_MATERIAL_KIND,
            &self.encode()?,
        )?)
    }
}

/// The sealed chat key grant first stored for a generation; every publication and retry sends
/// exactly these bytes under this publication id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatGrantRecord {
    publication_id: [u8; 16],
    ciphertext: Vec<u8>,
}
impl ChatGrantRecord {
    pub fn new(publication_id: [u8; 16], ciphertext: Vec<u8>) -> Result<Self, CloudDeviceError> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_GRANT_CIPHERTEXT {
            return Err(CloudDeviceError::Capacity);
        }
        Ok(Self {
            publication_id,
            ciphertext,
        })
    }
    pub fn publication_id(&self) -> [u8; 16] {
        self.publication_id
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn collection_id(scope: &AccountScope) -> Result<String, CloudDeviceError> {
        account_collection_id(scope, CHAT_GRANT_KIND)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(17 + self.ciphertext.len());
        bytes.push(VERSION);
        bytes.extend_from_slice(&self.publication_id);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }
    pub fn decode(plaintext: &[u8]) -> Result<Self, CloudDeviceError> {
        if plaintext.len() > MAX_GRANT {
            return Err(CloudDeviceError::Capacity);
        }
        let (version, rest) = plaintext.split_first().ok_or(CloudDeviceError::Format)?;
        if *version != VERSION || rest.len() <= 16 {
            return Err(CloudDeviceError::Format);
        }
        let (id, ciphertext) = rest.split_at(16);
        Self::new(
            id.try_into().map_err(|_| CloudDeviceError::Format)?,
            ciphertext.to_vec(),
        )
    }
    pub fn open(
        key: &CollectionKey,
        selector: &ChatSelector,
        object: &StoredObject<'_>,
    ) -> Result<Self, CloudDeviceError> {
        let collection = Self::collection_id(selector.scope())?;
        let id = selector.object_id()?;
        let plaintext =
            object.open(key, (&collection, &id, CHAT_GRANT_KIND), Some(1), MAX_GRANT)?;
        Self::decode(&plaintext)
    }
    pub fn seal(
        &self,
        key: &CollectionKey,
        selector: &ChatSelector,
    ) -> Result<Vec<u8>, CloudDeviceError> {
        let collection = Self::collection_id(selector.scope())?;
        Ok(key.seal_object(
            &collection,
            &selector.object_id()?,
            CHAT_GRANT_KIND,
            &Zeroizing::new(self.encode()),
        )?)
    }
}
