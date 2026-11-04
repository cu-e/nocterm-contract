//! Building blocks of a new chat for an enrolled runner (ADR 0122 of the native client).
//!
//! The order is the caller's: create the chat material with a compare-create `PutObject`
//! (expected version 0), store the grant record the same way, and only then publish
//! [`NewChat::grant_publication`] to the runner inbox. A device that finds stored records
//! (another device won, or a retry after reload) uses those instead and republishes the stored
//! grant with [`grant_publication`]; it never seals a second grant for the same generation.
use crate::{
    AccountScope, CloudDeviceError,
    command::Publication,
    records::{ChatGrantRecord, ChatMaterialRecord, ChatSelector, TrustedRunner},
    trust::HubCapabilities,
};
use nocterm_hub_model::cloud::relay::RelayBinding;
use nocterm_keys::{
    AccountKey, AccountKeyPair, PublicKey,
    cloud::{ChatKey, seal_chat_key_to_runner},
    random_bytes,
};

/// The first key epoch of a chat.
pub const FIRST_KEY_EPOCH: u64 = 1;

/// A fresh random chat id.
pub fn new_chat_id() -> Result<[u8; 16], CloudDeviceError> {
    Ok(random_bytes()?)
}

/// The records and publication of a chat that does not exist yet.
#[derive(Debug)]
pub struct NewChat {
    material: ChatMaterialRecord,
    grant: ChatGrantRecord,
}
impl NewChat {
    /// Generates the chat key, wraps it for the account and seals its grant to the runner.
    /// The chat key itself is dropped before this returns.
    pub fn create(
        scope: &AccountScope,
        runner: &TrustedRunner,
        chat_id: [u8; 16],
        account: &AccountKey,
        account_pair: &AccountKeyPair,
    ) -> Result<Self, CloudDeviceError> {
        if !scope.is_account_key(&account_pair.public_key().to_bytes()) {
            return Err(CloudDeviceError::Binding);
        }
        let selector = ChatSelector::new(
            scope.clone(),
            runner.runner(),
            chat_id,
            FIRST_KEY_EPOCH,
            runner.pins(),
        )?;
        let key = ChatKey::generate()?;
        let pinned = PublicKey::from_bytes(&runner.pins().encryption)
            .map_err(|_| CloudDeviceError::Binding)?;
        let sealed = seal_chat_key_to_runner(&key, account_pair, &pinned, &selector.coordinate()?)?;
        let material = ChatMaterialRecord::wrap(selector, &key, account)?;
        let grant = ChatGrantRecord::new(random_bytes()?, sealed)?;
        Ok(Self { material, grant })
    }
    pub fn selector(&self) -> &ChatSelector {
        self.material.selector()
    }
    /// Store first, under `cloud-chat-material`.
    pub fn material(&self) -> &ChatMaterialRecord {
        &self.material
    }
    /// Store second, under `cloud-chat-grant`.
    pub fn grant(&self) -> &ChatGrantRecord {
        &self.grant
    }
    /// Publish last, to the runner inbox.
    pub fn grant_publication(
        &self,
        capabilities: &HubCapabilities,
    ) -> Result<Publication, CloudDeviceError> {
        grant_publication(self.selector(), &self.grant, capabilities)
    }
}

/// The inbox publication of a stored grant, with the grant's own publication id so every retry
/// is the same publication.
pub fn grant_publication(
    selector: &ChatSelector,
    grant: &ChatGrantRecord,
    capabilities: &HubCapabilities,
) -> Result<Publication, CloudDeviceError> {
    if !capabilities.chat_key_material() {
        return Err(CloudDeviceError::Unsupported);
    }
    Publication::with_id(
        grant.publication_id(),
        RelayBinding::chat_key_grant(selector.coordinate()?),
        grant.ciphertext().to_vec(),
        capabilities,
    )
}

#[cfg(test)]
mod tests;
