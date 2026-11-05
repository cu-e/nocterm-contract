//! What every flow of one signed-in account works with: the unlocked account keys, the trusted
//! hub with its verified capabilities, the trusted runners, and how a chat is named.
use crate::{
    AccountScope, CloudDeviceError,
    nonces::Nonces,
    records::{ChatSelector, TrustedRunner},
    trust::{HubCapabilities, TrustedHub},
};
use core::fmt;
use nocterm_keys::{AccountKey, AccountKeyPair};
use std::{str::FromStr, sync::Arc};

/// The account key and the account's X25519 pair while the keyset is unlocked. Flows share
/// one value; it is dropped with the last flow. `Debug` shows only the account id.
pub struct AccountKeys {
    account_id: String,
    account: AccountKey,
    pair: AccountKeyPair,
}
impl AccountKeys {
    pub fn new(account_id: &str, account: AccountKey, pair: AccountKeyPair) -> Self {
        Self {
            account_id: account_id.to_owned(),
            account,
            pair,
        }
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.pair.public_key().to_bytes()
    }
    pub(crate) fn account(&self) -> &AccountKey {
        &self.account
    }
    pub(crate) fn pair(&self) -> &AccountKeyPair {
        &self.pair
    }
}
impl fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKeys")
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

/// One account on its trusted hub: keys, hub pin, verified capabilities and trusted runners.
#[derive(Debug)]
pub struct CloudSession {
    keys: Arc<AccountKeys>,
    hub: TrustedHub,
    capabilities: HubCapabilities,
    runners: Vec<TrustedRunner>,
    nonces: Nonces,
}
impl CloudSession {
    /// `hub` must be the trust record of the account `keys` unlock.
    pub fn new(
        keys: Arc<AccountKeys>,
        hub: TrustedHub,
        capabilities: HubCapabilities,
        runners: Vec<TrustedRunner>,
    ) -> Result<Self, CloudDeviceError> {
        if !hub.scope().is_account_key(&keys.public_key())
            || hub.scope().account_id() != keys.account_id()
        {
            return Err(CloudDeviceError::Binding);
        }
        Ok(Self {
            keys,
            hub,
            capabilities,
            runners,
            nonces: Nonces::os(),
        })
    }
    /// The same session drawing probe nonces from `nonces`.
    #[must_use]
    pub fn with_nonces(mut self, nonces: Nonces) -> Self {
        self.nonces = nonces;
        self
    }
    pub fn nonces(&self) -> &Nonces {
        &self.nonces
    }
    /// The same session with another runner list (after the registry was read again).
    #[must_use]
    pub fn with_runners(&self, runners: Vec<TrustedRunner>) -> Self {
        Self {
            keys: self.keys.clone(),
            hub: self.hub.clone(),
            capabilities: self.capabilities,
            runners,
            nonces: self.nonces.clone(),
        }
    }
    pub fn keys(&self) -> &Arc<AccountKeys> {
        &self.keys
    }
    pub fn hub(&self) -> &TrustedHub {
        &self.hub
    }
    pub fn scope(&self) -> &AccountScope {
        self.hub.scope()
    }
    pub fn capabilities(&self) -> &HubCapabilities {
        &self.capabilities
    }
    pub fn runners(&self) -> &[TrustedRunner] {
        &self.runners
    }
    pub fn runner(&self, id: &[u8; 16]) -> Result<&TrustedRunner, CloudDeviceError> {
        self.runners
            .iter()
            .find(|row| &row.runner().id == id)
            .ok_or(CloudDeviceError::NoRunner)
    }
    /// The selector of a chat of a trusted runner.
    pub fn selector(&self, chat: &ChatRef) -> Result<ChatSelector, CloudDeviceError> {
        let runner = self.runner(&chat.runner)?;
        ChatSelector::new(
            self.scope().clone(),
            runner.runner(),
            chat.chat_id,
            chat.key_epoch,
            runner.pins(),
        )
    }
}

/// One chat generation of a runner, as lists and links name it: `<runner>-<chat>-<epoch>` with
/// both ids in lowercase hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChatRef {
    pub runner: [u8; 16],
    pub chat_id: [u8; 16],
    pub key_epoch: u64,
}
impl ChatRef {
    pub fn of(selector: &ChatSelector) -> Self {
        Self {
            runner: selector.runner().id,
            chat_id: selector.chat_id(),
            key_epoch: selector.key_epoch(),
        }
    }
}
impl fmt::Display for ChatRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}-{}",
            hex::encode(self.runner),
            hex::encode(self.chat_id),
            self.key_epoch
        )
    }
}
impl FromStr for ChatRef {
    type Err = CloudDeviceError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut parts = text.split('-');
        let id = |part: Option<&str>| -> Result<[u8; 16], CloudDeviceError> {
            let text = part.filter(|part| part.len() == 32 && !part.contains(char::is_uppercase));
            hex::decode(text.ok_or(CloudDeviceError::Format)?)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(CloudDeviceError::Format)
        };
        let runner = id(parts.next())?;
        let chat_id = id(parts.next())?;
        let key_epoch = parts
            .next()
            .and_then(|epoch| epoch.parse::<u64>().ok())
            .filter(|epoch| *epoch > 0)
            .ok_or(CloudDeviceError::Format)?;
        if parts.next().is_some() {
            return Err(CloudDeviceError::Format);
        }
        Ok(Self {
            runner,
            chat_id,
            key_epoch,
        })
    }
}
