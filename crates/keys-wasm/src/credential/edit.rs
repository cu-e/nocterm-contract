//! A credential the vault keeps, as the browser manages it: its name and binding read without its
//! secret, a password saved under a name for no server yet, and a record renamed or a password
//! given other addresses, sealed again with the same secret. The secret is opened only inside
//! WebAssembly and never returned.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

use super::{Binding, FORMAT, KIND, Target};
use crate::{WebCollectionKey, WebError};

/// The longest name native clients keep, in bytes.
const MAX_LABEL_BYTES: usize = 1024;

/// Why a credential is not changed.
#[derive(Debug, thiserror::Error)]
pub enum CredentialRefused {
    #[error("the credential was written by a newer version")]
    UnknownFormat,
    #[error("only a password signs in to addresses of its choosing")]
    NotAPassword,
    #[error("an address needs a host and a user, and a port from 1")]
    InvalidAddress,
    #[error("a name has between 1 and 1024 bytes")]
    InvalidName,
}

/// A stored record. Its secret is wiped when it is dropped.
#[derive(Deserialize)]
struct Stored {
    v: u32,
    label: String,
    binding: serde_json::Value,
    secret: String,
}

impl Drop for Stored {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// A stored record rewritten with another name or binding; the secret is borrowed.
#[derive(Serialize)]
struct Rewritten<'a> {
    v: u32,
    label: &'a str,
    binding: &'a serde_json::Value,
    secret: &'a str,
}

/// An address as the page sends it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Address {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    user: String,
}

fn default_port() -> u16 {
    super::DEFAULT_PORT
}

#[wasm_bindgen]
impl WebCollectionKey {
    /// The name and binding of the credential `object_id`, as JSON
    /// `{"label":…,"binding":…}`; its secret stays sealed.
    #[wasm_bindgen(js_name = openCredentialInfo)]
    pub fn open_credential_info(
        &self,
        object_id: &str,
        ciphertext: &[u8],
    ) -> Result<String, JsError> {
        self.info(object_id, ciphertext).map_err(JsError::from)
    }

    /// Seals a password the person saved under `label` for no address yet, as the credential
    /// `object_id`.
    #[wasm_bindgen(js_name = sealNamedPassword)]
    pub fn seal_named_password(
        &self,
        object_id: &str,
        label: &str,
        password: String,
    ) -> Result<Vec<u8>, JsError> {
        let password = zeroize::Zeroizing::new(password);
        self.named(object_id, label, &password)
            .map_err(JsError::from)
    }

    /// The credential `object_id` named `label`, sealed again with its secret and binding.
    #[wasm_bindgen(js_name = renameCredential)]
    pub fn rename_credential(
        &self,
        object_id: &str,
        ciphertext: &[u8],
        label: &str,
    ) -> Result<Vec<u8>, JsError> {
        self.updated(object_id, ciphertext, Some(label), None)
            .map_err(JsError::from)
    }

    /// The password `object_id` signing in to `addresses` (JSON
    /// `[{"host":…,"port":…,"user":…}]`, the port 22 when left out) and no other, sealed again
    /// with its secret and name.
    #[wasm_bindgen(js_name = setPasswordAddresses)]
    pub fn set_password_addresses(
        &self,
        object_id: &str,
        ciphertext: &[u8],
        addresses: &str,
    ) -> Result<Vec<u8>, JsError> {
        self.updated(object_id, ciphertext, None, Some(addresses))
            .map_err(JsError::from)
    }
}

impl WebCollectionKey {
    fn stored(&self, object_id: &str, ciphertext: &[u8]) -> Result<Stored, WebError> {
        let plain = self
            .key
            .open_object(&self.collection_id, object_id, KIND, ciphertext)?;
        let stored: Stored = serde_json::from_slice(&plain)?;
        if stored.v != FORMAT {
            return Err(CredentialRefused::UnknownFormat.into());
        }
        Ok(stored)
    }

    pub(crate) fn info(&self, object_id: &str, ciphertext: &[u8]) -> Result<String, WebError> {
        let stored = self.stored(object_id, ciphertext)?;
        let info = serde_json::json!({"label": stored.label, "binding": stored.binding});
        Ok(info.to_string())
    }

    pub(crate) fn named(
        &self,
        object_id: &str,
        label: &str,
        password: &str,
    ) -> Result<Vec<u8>, WebError> {
        let label = name(label)?;
        let binding = Binding::Shared {
            targets: Vec::new(),
        };
        self.record(object_id, label, binding, password)
    }

    /// The record `object_id` with another name or, for a password, other addresses; what is
    /// not given stays.
    pub(crate) fn updated(
        &self,
        object_id: &str,
        ciphertext: &[u8],
        label: Option<&str>,
        addresses: Option<&str>,
    ) -> Result<Vec<u8>, WebError> {
        let stored = self.stored(object_id, ciphertext)?;
        let label = match label {
            Some(label) => name(label)?,
            None => stored.label.as_str(),
        };
        let binding = match addresses {
            None => stored.binding.clone(),
            Some(_) if stored.binding.get("kind").and_then(|k| k.as_str()) != Some("password") => {
                return Err(CredentialRefused::NotAPassword.into());
            }
            Some(addresses) => password_binding(addresses)?,
        };
        let mut plaintext = serde_json::to_vec(&Rewritten {
            v: FORMAT,
            label,
            binding: &binding,
            secret: &stored.secret,
        })?;
        let sealed = self
            .key
            .seal_object(&self.collection_id, object_id, KIND, &plaintext);
        plaintext.zeroize();
        Ok(sealed?)
    }
}

/// A name native clients keep.
fn name(label: &str) -> Result<&str, CredentialRefused> {
    let label = label.trim();
    if label.is_empty() || label.len() > MAX_LABEL_BYTES {
        return Err(CredentialRefused::InvalidName);
    }
    Ok(label)
}

/// The binding of a password that signs in to `addresses`, each once, as native clients write
/// it: one address as `target`, any other number as `targets`.
fn password_binding(addresses: &str) -> Result<serde_json::Value, WebError> {
    let parsed: Vec<Address> = serde_json::from_str(addresses)?;
    let mut unique: Vec<Address> = Vec::new();
    for address in parsed {
        if address.host.trim().is_empty() || address.user.trim().is_empty() || address.port == 0 {
            return Err(CredentialRefused::InvalidAddress.into());
        }
        let seen = unique.iter().any(|known| {
            (known.host.as_str(), known.port, known.user.as_str())
                == (address.host.as_str(), address.port, address.user.as_str())
        });
        if !seen {
            unique.push(address);
        }
    }
    let targets: Vec<Target<'_>> = unique
        .iter()
        .map(|address| Target {
            host: &address.host,
            port: address.port,
            user: &address.user,
        })
        .collect();
    let binding = match <[Target<'_>; 1]>::try_from(targets) {
        Ok([target]) => Binding::Password { target },
        Err(targets) => Binding::Shared { targets },
    };
    Ok(serde_json::to_value(&binding)?)
}
