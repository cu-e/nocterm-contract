//! Immutable purpose10 material, source-bound independently of execution commands.
use super::{CloudClient, CloudError, Credentials};
use crate::Keyset;
use nocterm_hub_model::cloud::{
    ChatCoordinate,
    capabilities::CLOUD_FEATURE_CHAT_KEY_MATERIAL,
    relay::{PublicationMetadata, RelayBinding},
};
use nocterm_keys::{
    PublicKey,
    cloud::{ChatKey, seal_chat_key_to_runner},
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{Arc, Weak},
};

/// Persist the exact metadata and sealed bytes in the account-owned collection
/// before publishing. Reconnects and newly signed-in devices reuse that same
/// envelope, not a fresh random sealing for an already installed key generation.
/// A receiver must authenticate purpose10 against configured pins; this value
/// carries neither CommandAccepted nor inference/tool authority.
pub struct PreparedChatKeyGrant {
    metadata: PublicationMetadata,
    ciphertext: Vec<u8>,
    source: Weak<Credentials>,
    generation: u64,
}
impl PreparedChatKeyGrant {
    pub(super) fn seal(
        client: &CloudClient,
        keyset: &Keyset,
        pinned_runner: &PublicKey,
        chat: ChatCoordinate,
        key: &ChatKey,
        publication_id: [u8; 16],
    ) -> Result<Self, CloudError> {
        client.check_source()?;
        if keyset.account_id() != client.namespace().account_id.as_str() {
            return Err(CloudError::SourceChanged);
        }
        Self::require_coordinate(client, &chat)?;
        let ciphertext = seal_chat_key_to_runner(key, keyset.key_pair(), pinned_runner, &chat)?;
        Self::stage(client, chat, publication_id, ciphertext)
    }
    pub(super) fn stage(
        client: &CloudClient,
        chat: ChatCoordinate,
        publication_id: [u8; 16],
        ciphertext: Vec<u8>,
    ) -> Result<Self, CloudError> {
        Self::require_coordinate(client, &chat)?;
        if ciphertext.len()
            > usize::try_from(client.limits().max_envelope_bytes)
                .map_err(|_| CloudError::Protocol)?
        {
            return Err(CloudError::Protocol);
        }
        let metadata = PublicationMetadata::new(
            publication_id,
            RelayBinding::chat_key_grant(chat),
            u32::try_from(ciphertext.len()).map_err(|_| CloudError::Protocol)?,
            Sha256::digest(&ciphertext).into(),
        )?;
        client.check_source()?;
        Ok(Self {
            metadata,
            ciphertext,
            source: Arc::downgrade(&client.credentials),
            generation: client.generation,
        })
    }
    fn require_coordinate(client: &CloudClient, chat: &ChatCoordinate) -> Result<(), CloudError> {
        client.check_source()?;
        if client.limits().features & CLOUD_FEATURE_CHAT_KEY_MATERIAL == 0 {
            return Err(CloudError::Unsupported);
        }
        if chat.namespace() != client.namespace() {
            return Err(CloudError::Protocol);
        }
        Ok(())
    }
    pub fn metadata(&self) -> &PublicationMetadata {
        &self.metadata
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub(super) async fn publish(
        &self,
        client: &CloudClient,
    ) -> Result<nocterm_hub_proto::v1::CloudDeliveryReceipt, CloudError> {
        let original = self.source.upgrade().ok_or(CloudError::SourceChanged)?;
        if !Arc::ptr_eq(&original, &client.credentials) || self.generation != client.generation {
            return Err(CloudError::SourceChanged);
        }
        client.check_source()?;
        let mut upload = client.begin_publication(self.metadata.clone())?;
        for chunk in self.ciphertext.chunks(
            usize::try_from(client.limits().max_frame_bytes).map_err(|_| CloudError::Protocol)?,
        ) {
            upload.write(chunk).await?;
        }
        upload.finish().await
    }
}
impl fmt::Debug for PreparedChatKeyGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedChatKeyGrant")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}
