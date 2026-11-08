//! The credentials the browser keeps for a server the person connects: the vault record native
//! clients read, built and sealed here so the secret never returns to JavaScript.
//!
//! A record is an object of kind `credential` whose plaintext is
//! `{"v":1,"label":…,"binding":…,"secret":…}`, the format of the native vault
//! (`nocterm-hub-io`). A password is bound to the address it signs in to
//! (`{"kind":"password","target":{"host":…,["port":…,]"user":…}}`, the port only when it is not
//! 22); a private key to the canonical text of its public half
//! (`{"kind":"private_key","public_key":"<algorithm> <base64>"}`), and its secret is the key's
//! OpenSSH text without a passphrase, which the vault's encryption replaces. Keys follow the
//! native rules (`nocterm-ssh-keys`): Ed25519, ECDSA, and RSA of at least 2048 bits. A password
//! saved under a name may sign in to several addresses, or none yet
//! (`{"kind":"password","targets":[…]}`); [`edit`] reads a record's name and binding and changes
//! them while its secret stays inside WebAssembly.

use serde::Serialize;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{WebCollectionKey, WebError};

/// The kind of the objects that hold credentials.
const KIND: &str = "credential";
/// The record format native clients read.
const FORMAT: u32 = 1;
const DEFAULT_PORT: u16 = 22;
/// The smallest RSA modulus native clients accept, in bits.
const MIN_RSA_BITS: u32 = 2048;

/// Why a private key is not kept.
#[derive(Debug, thiserror::Error)]
pub enum KeyRefused {
    #[error("the private key is not an OpenSSH private key")]
    Malformed(#[source] ssh_key::Error),
    #[error("the private key is protected: enter its passphrase")]
    PassphraseRequired,
    #[error("the passphrase does not open the private key")]
    WrongPassphrase,
    #[error("an RSA key of {bits} bits is too weak; use at least 2048 bits")]
    TooWeak { bits: u32 },
    #[error("keys of type {algorithm} are not supported")]
    Unsupported { algorithm: String },
}

#[derive(Serialize)]
struct Record<'a> {
    v: u32,
    label: &'a str,
    binding: Binding<'a>,
    secret: &'a str,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Binding<'a> {
    /// A password for one address, written as native clients write it.
    Password {
        target: Target<'a>,
    },
    /// A password saved under a name for no address or several.
    #[serde(rename = "password")]
    Shared {
        targets: Vec<Target<'a>>,
    },
    PrivateKey {
        public_key: &'a str,
    },
}

#[derive(Serialize)]
struct Target<'a> {
    host: &'a str,
    #[serde(skip_serializing_if = "is_default_port")]
    port: u16,
    user: &'a str,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes the field by reference"
)]
fn is_default_port(port: &u16) -> bool {
    *port == DEFAULT_PORT
}

/// A private key sealed as a credential, with the public half a profile names it by.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebSealedKey {
    ciphertext: Vec<u8>,
    public_key: String,
    fingerprint: String,
}

#[wasm_bindgen]
impl WebSealedKey {
    /// The sealed record, for `PutObject` with kind `credential`.
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    /// The public half as `"<algorithm> <base64>"`, without a comment.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    /// The `SHA256:…` fingerprint `ssh-keygen -lf` prints.
    pub fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
}

#[wasm_bindgen]
impl WebCollectionKey {
    /// Seals the password the person typed for `user@host:port` as the credential `object_id`.
    #[wasm_bindgen(js_name = sealPassword)]
    pub fn seal_password(
        &self,
        object_id: &str,
        host: &str,
        port: u16,
        user: &str,
        password: String,
    ) -> Result<Vec<u8>, JsError> {
        let password = Zeroizing::new(password);
        self.password(object_id, host, port, user, &password)
            .map_err(JsError::from)
    }

    /// Seals the private key the person pasted as the credential `object_id`, named `label`,
    /// after removing its `passphrase`.
    #[wasm_bindgen(js_name = sealSshKey)]
    pub fn seal_ssh_key(
        &self,
        object_id: &str,
        label: &str,
        private_key: String,
        passphrase: Option<String>,
    ) -> Result<WebSealedKey, JsError> {
        let private_key = Zeroizing::new(private_key);
        let passphrase = passphrase.map(Zeroizing::new);
        self.ssh_key(
            object_id,
            label,
            &private_key,
            passphrase.as_deref().map(String::as_str),
        )
        .map_err(JsError::from)
    }
}

impl WebCollectionKey {
    pub(crate) fn password(
        &self,
        object_id: &str,
        host: &str,
        port: u16,
        user: &str,
        password: &str,
    ) -> Result<Vec<u8>, WebError> {
        let label = if port == DEFAULT_PORT {
            format!("{user}@{host}")
        } else {
            format!("{user}@{host}:{port}")
        };
        let binding = Binding::Password {
            target: Target { host, port, user },
        };
        self.record(object_id, &label, binding, password)
    }

    fn ssh_key(
        &self,
        object_id: &str,
        label: &str,
        private_key: &str,
        passphrase: Option<&str>,
    ) -> Result<WebSealedKey, WebError> {
        let key = accepted(private_key, passphrase)?;
        let normalized = key
            .to_openssh(LineEnding::LF)
            .map_err(KeyRefused::Malformed)?;
        let mut public = key.public_key().clone();
        public.set_comment("");
        let public_key = public.to_openssh().map_err(KeyRefused::Malformed)?;
        let public_key = public_key.trim_end();
        let binding = Binding::PrivateKey { public_key };
        Ok(WebSealedKey {
            ciphertext: self.record(object_id, label, binding, &normalized)?,
            public_key: public_key.to_owned(),
            fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        })
    }

    fn record(
        &self,
        object_id: &str,
        label: &str,
        binding: Binding<'_>,
        secret: &str,
    ) -> Result<Vec<u8>, WebError> {
        let record = Record {
            v: FORMAT,
            label,
            binding,
            secret,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&record)?);
        Ok(self
            .key
            .seal_object(&self.collection_id, object_id, KIND, &plaintext)?)
    }
}

/// The key of `text`, opened with `passphrase` when it has one, if native clients accept it.
fn accepted(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyRefused> {
    let parsed = PrivateKey::from_openssh(text.trim()).map_err(KeyRefused::Malformed)?;
    let key = if parsed.is_encrypted() {
        let passphrase = passphrase
            .filter(|p| !p.is_empty())
            .ok_or(KeyRefused::PassphraseRequired)?;
        parsed.decrypt(passphrase).map_err(|error| match error {
            ssh_key::Error::Crypto => KeyRefused::WrongPassphrase,
            other => KeyRefused::Malformed(other),
        })?
    } else {
        parsed
    };
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => Ok(key),
        Algorithm::Rsa { .. } => {
            let bits = key
                .public_key()
                .key_data()
                .rsa()
                .map_or(0, ssh_key::public::RsaPublicKey::key_size);
            if bits < MIN_RSA_BITS {
                return Err(KeyRefused::TooWeak { bits });
            }
            Ok(key)
        }
        other => Err(KeyRefused::Unsupported {
            algorithm: other.to_string(),
        }),
    }
}

mod edit;
pub use edit::CredentialRefused;

#[cfg(test)]
mod tests;
