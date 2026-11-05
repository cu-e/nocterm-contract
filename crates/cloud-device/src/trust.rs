//! Which hub authority this device trusts, and the hub's fresh capability proof checked against
//! it. A browser does not know the native `host:port` a hub-trust record was created for, so it
//! lists the account's `cloud-hub-trust` collections and keeps the records whose raw hub id,
//! account id and account key digest match the hub it signed in to.
use crate::{AccountScope, CloudDeviceError, records::HubTrustRecord};
use nocterm_hub_model::cloud::capabilities::{
    CLOUD_FEATURE_CHAT_DIRECTORY, CLOUD_FEATURE_CHAT_KEY_MATERIAL, CLOUD_FEATURE_FRESH_HEAD,
    CLOUD_FEATURE_UNARY_PUBLISH, CapabilityLimits, SignedCapabilities,
};

/// The records among `records` made for this raw hub id, account and account key. Several
/// matches (the account set Cloud up from several native origins) are for the person to choose.
pub fn matching_hub_trust<'a>(
    records: &'a [HubTrustRecord],
    raw_hub: &str,
    account_id: &str,
    account_public_key: &[u8; 32],
) -> Vec<&'a HubTrustRecord> {
    records
        .iter()
        .filter(|record| record.matches(raw_hub, account_id, account_public_key))
        .collect()
}

/// A hub-trust record accepted for the signed-in account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedHub {
    record: HubTrustRecord,
    scope: AccountScope,
}
impl TrustedHub {
    /// Accepts `record` only for the hub and account it names.
    pub fn new(
        record: HubTrustRecord,
        raw_hub: &str,
        account_id: &str,
        account_public_key: &[u8; 32],
    ) -> Result<Self, CloudDeviceError> {
        if !record.matches(raw_hub, account_id, account_public_key) {
            return Err(CloudDeviceError::Binding);
        }
        let scope = record.scope()?;
        Ok(Self { record, scope })
    }
    pub fn record(&self) -> &HubTrustRecord {
        &self.record
    }
    pub fn scope(&self) -> &AccountScope {
        &self.scope
    }
    /// Checks a `CloudService.Capabilities` answer to `nonce` against the pinned authority.
    pub fn verify_capabilities(
        &self,
        claim: &[u8],
        signature: &[u8],
        nonce: &[u8; 16],
        now_ms: i64,
    ) -> Result<HubCapabilities, CloudDeviceError> {
        let claim =
            nocterm_hub_model::cloud::capabilities::CapabilitiesClaim::from_canonical_bytes(claim)?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| nocterm_hub_model::cloud::capabilities::CapabilityError::Malformed)?;
        let proof = SignedCapabilities::new(claim, signature)?;
        proof.require_expected(
            self.record.raw_hub(),
            &self.record.authority(),
            nonce,
            now_ms,
        )?;
        Ok(HubCapabilities {
            limits: proof.claim().limits(),
        })
    }
}

/// The verified limits and optional features of the trusted hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HubCapabilities {
    limits: CapabilityLimits,
}
impl HubCapabilities {
    pub fn limits(&self) -> CapabilityLimits {
        self.limits
    }
    /// Head probes, which reading a chat requires before replay.
    pub fn fresh_head(&self) -> bool {
        self.limits.features & CLOUD_FEATURE_FRESH_HEAD != 0
    }
    /// `CloudService.PublishOne`, which a browser needs to send a command.
    pub fn unary_publish(&self) -> bool {
        self.limits.features & CLOUD_FEATURE_UNARY_PUBLISH != 0
    }
    pub fn fragmented_publish(&self) -> bool {
        self.limits.features
            & nocterm_hub_model::cloud::capabilities::CLOUD_FEATURE_FRAGMENTED_PUBLISH
            != 0
    }
    pub(crate) fn require_publication(&self, bytes: usize) -> Result<(), CloudDeviceError> {
        self.require_commands()?;
        let bytes = u32::try_from(bytes).map_err(|_| CloudDeviceError::Capacity)?;
        if bytes == 0 || bytes > self.limits.max_envelope_bytes {
            return Err(CloudDeviceError::Capacity);
        }
        if bytes > self.limits.max_frame_bytes && !self.fragmented_publish() {
            return Err(CloudDeviceError::LargePublicationUnsupported);
        }
        Ok(())
    }
    /// Chat key grants, which creating a chat needs.
    pub fn chat_key_material(&self) -> bool {
        self.limits.features & CLOUD_FEATURE_CHAT_KEY_MATERIAL != 0
    }
    /// Runner chat directories (ADR 0008), which listing chats with summaries needs.
    pub fn chat_directory(&self) -> bool {
        self.limits.features & CLOUD_FEATURE_CHAT_DIRECTORY != 0
    }
    /// Refuses unless the hub offers what reading chats needs.
    pub fn require_reading(&self) -> Result<(), CloudDeviceError> {
        if self.fresh_head() {
            Ok(())
        } else {
            Err(CloudDeviceError::Unsupported)
        }
    }
    /// Refuses unless the hub also accepts unary publications.
    pub fn require_commands(&self) -> Result<(), CloudDeviceError> {
        self.require_reading()?;
        if self.unary_publish() {
            Ok(())
        } else {
            Err(CloudDeviceError::Unsupported)
        }
    }
}

#[cfg(test)]
mod tests;
