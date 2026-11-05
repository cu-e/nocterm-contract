use crate::CloudDeviceError;
use nocterm_hub_model::cloud::{CloudNamespace, CloudTextId, CommandIssuer, hub_namespace_id};
use sha2::{Digest, Sha256};

/// One account on one Cloud hub, as the account's private records name it: the wire namespace
/// derived from the raw hub id and the pinned hub authority, the authority fingerprint, the
/// account id and the SHA-256 digest of the account's keyset public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountScope {
    hub: CloudTextId,
    authority_fingerprint: [u8; 32],
    account: CloudTextId,
    account_key_digest: [u8; 32],
}
impl AccountScope {
    /// Derives the scope from a pinned hub authority key and the signed-in account.
    pub fn derive(
        raw_hub: &str,
        authority: [u8; 32],
        account_id: &str,
        account_public_key: [u8; 32],
    ) -> Result<Self, CloudDeviceError> {
        let authority_fingerprint: [u8; 32] = Sha256::digest(authority).into();
        Ok(Self {
            hub: hub_namespace_id(raw_hub, authority_fingerprint)?,
            authority_fingerprint,
            account: CloudTextId::new(account_id)?,
            account_key_digest: Sha256::digest(account_public_key).into(),
        })
    }
    /// A scope from already derived parts, as stored records carry them.
    pub fn from_parts(
        hub_instance: &str,
        authority_fingerprint: [u8; 32],
        account_id: &str,
        account_key_digest: [u8; 32],
    ) -> Result<Self, CloudDeviceError> {
        Ok(Self {
            hub: CloudTextId::new(hub_instance)?,
            authority_fingerprint,
            account: CloudTextId::new(account_id)?,
            account_key_digest,
        })
    }
    /// The derived wire namespace (hex), not the raw hub id.
    pub fn hub_instance(&self) -> &str {
        self.hub.as_str()
    }
    pub fn authority_fingerprint(&self) -> [u8; 32] {
        self.authority_fingerprint
    }
    pub fn account_id(&self) -> &str {
        self.account.as_str()
    }
    pub fn account_key_digest(&self) -> [u8; 32] {
        self.account_key_digest
    }
    /// True when `account_public_key` is the key this scope was derived for.
    pub fn is_account_key(&self, account_public_key: &[u8; 32]) -> bool {
        <[u8; 32]>::from(Sha256::digest(account_public_key)) == self.account_key_digest
    }
    pub fn namespace(&self) -> CloudNamespace {
        CloudNamespace {
            hub_instance_id: self.hub.clone(),
            account_id: self.account.clone(),
        }
    }
}

/// The signed-in device as commands and head probes name it. The signing key is the public half
/// of the device key the hub registered; the caller keeps the private half and signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    device: CloudTextId,
    signing_key: [u8; 32],
    access_token_digest: [u8; 32],
    session_expires_at_ms: i64,
}
impl DeviceIdentity {
    /// `access_token` is the current access token (only its SHA-256 digest is kept);
    /// `session_expires_at_ms` is when the signed-in session ends (its refresh expiry), which
    /// caps every deadline this device signs.
    pub fn new(
        device_id: &str,
        signing_key: [u8; 32],
        access_token: &str,
        session_expires_at_ms: i64,
    ) -> Result<Self, CloudDeviceError> {
        Ok(Self {
            device: CloudTextId::new(device_id)?,
            signing_key,
            access_token_digest: Sha256::digest(access_token.as_bytes()).into(),
            session_expires_at_ms,
        })
    }
    pub fn device_id(&self) -> &str {
        self.device.as_str()
    }
    pub fn signing_key(&self) -> [u8; 32] {
        self.signing_key
    }
    pub fn session_expires_at_ms(&self) -> i64 {
        self.session_expires_at_ms
    }
    pub(crate) fn issuer(&self) -> CommandIssuer {
        CommandIssuer {
            device_id: self.device.clone(),
            signing_key: self.signing_key,
            access_token_digest: self.access_token_digest,
        }
    }
}
