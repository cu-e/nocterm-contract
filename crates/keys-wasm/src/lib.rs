//! WebAssembly bindings of the Nocterm vault for the web panel.
//!
//! Owns: the browser-facing surface that derives the login value for the hub (`loginAuth`),
//! creates the first keyset of an account (`createKeysetWithLoginPassword`,
//! `createKeysetWithVaultPassword`), unlocks an account from its password (login or vault
//! password), reads the account's saved server profiles: opens a collection key
//! (`WebAccount.openCollection`) and its profile objects (`WebCollectionKey.openObject`), and
//! saves a server the person connected in the browser: creates a collection
//! (`WebAccount.newCollection`), seals its profile (`WebCollectionKey.sealObject`) and the
//! password or private key the person typed as a native vault record
//! (`WebCollectionKey.sealPassword`, `WebCollectionKey.sealSshKey`).
//! All cryptography is `nocterm-keys`; this crate only converts text and bytes at the
//! JavaScript boundary.
//! Does not own: key storage, the network, or any user interface.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: secrets never cross into JavaScript, except the recovery key of a new keyset,
//! which the page shows once, and the plaintext of profile objects (kind `profile`, which hold
//! no secrets); the account key, collection keys and objects of any other kind (credentials)
//! stay inside WebAssembly; a credential crosses only inward, typed by the person, and its
//! record is built and sealed here, so its secret (a private key without its passphrase
//! included) never returns to JavaScript and is never opened here; errors are typed here and
//! become strings only at the boundary.

use nocterm_keys::{
    AccountKey, CreatedKeyset, KeyError, KeysetMaterialError, LoginError, LoginSecrets, OpenError,
    SealError, UnlockKdf, UnlockKey, UnlockSource, create_keyset,
};
use wasm_bindgen::prelude::*;

mod collection;
mod credential;

pub use collection::{WebCollectionKey, WebNewCollection};
pub use credential::{KeyRefused, WebSealedKey};

/// What can go wrong at the boundary.
#[derive(Debug, thiserror::Error)]
pub enum WebError {
    /// The keyset's key derivation parameters or salt are not acceptable.
    #[error(transparent)]
    Kdf(#[from] nocterm_keys::KdfParseError),
    /// The password could not be turned into keys.
    #[error(transparent)]
    Login(#[from] LoginError),
    /// A sealed key did not open: wrong password or modified data.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// No randomness for a new salt or key.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A new keyset could not be built.
    #[error(transparent)]
    Keyset(#[from] KeysetMaterialError),
    /// Objects of this kind stay sealed in the browser.
    #[error("objects of kind {0:?} are not opened in the browser")]
    SealedKind(String),
    /// Objects of this kind are not written from the browser.
    #[error("objects of kind {0:?} are not sealed in the browser")]
    UnsealableKind(String),
    /// A key or object could not be sealed.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// A private key the person pasted is not one native clients sign in with.
    #[error(transparent)]
    SshKey(#[from] KeyRefused),
    /// A credential record could not be encoded.
    #[error("the credential could not be encoded")]
    Encode(#[from] serde_json::Error),
}

/// An unlocked account: its account key, which opens the account's collection keys. It never
/// leaves WebAssembly.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebAccount {
    account: AccountKey,
}

#[wasm_bindgen]
impl WebAccount {
    /// Unlocks with the login password: derives the unlock key (`login-v1`) and opens the
    /// account key. Costs 64 MiB and a few hundred milliseconds: call it from a worker.
    pub fn unlock(
        password: &str,
        hub_id: &str,
        username: &str,
        account_id: &str,
        wrapped_account_key: &[u8],
    ) -> Result<WebAccount, JsError> {
        Self::open(password, hub_id, username, account_id, wrapped_account_key)
            .map_err(JsError::from)
    }

    /// Unlocks with a separate vault password, using the derivation the keyset records (`kdf`
    /// as `argon2id;m=…;t=…;p=…` and its `salt`). Weak or excessive parameters are refused, so
    /// a hostile hub cannot downgrade the derivation.
    #[wasm_bindgen(js_name = unlockWithPassword)]
    pub fn unlock_with_password(
        password: &str,
        kdf: &str,
        salt: &[u8],
        account_id: &str,
        wrapped_account_key: &[u8],
    ) -> Result<WebAccount, JsError> {
        Self::open_vault(password, kdf, salt, account_id, wrapped_account_key)
            .map_err(JsError::from)
    }
}

impl WebAccount {
    fn open(
        password: &str,
        hub_id: &str,
        username: &str,
        account_id: &str,
        wrapped_account_key: &[u8],
    ) -> Result<Self, WebError> {
        let secrets = LoginSecrets::derive(password, hub_id, username)?;
        let account = AccountKey::open(secrets.unlock(), account_id, wrapped_account_key)?;
        Ok(Self { account })
    }

    fn open_vault(
        password: &str,
        kdf: &str,
        salt: &[u8],
        account_id: &str,
        wrapped_account_key: &[u8],
    ) -> Result<Self, WebError> {
        let kdf = UnlockKdf::parse(kdf, salt)?;
        let unlock = UnlockKey::from_vault_password(password, &kdf)?;
        let account = AccountKey::open(&unlock, account_id, wrapped_account_key)?;
        Ok(Self { account })
    }
}

/// A keyset created in the browser: the values `PutKeyset` stores (send them with
/// `expected_version = 0`), the recovery key to show once, and the unlocked account.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebNewKeyset {
    created: CreatedKeyset,
}

#[wasm_bindgen]
impl WebNewKeyset {
    /// `kdf` of the keyset (`argon2id;m=…;t=…;p=…`).
    pub fn kdf(&self) -> String {
        self.created.material.kdf.clone()
    }

    /// `salt` of the keyset.
    pub fn salt(&self) -> Vec<u8> {
        self.created.material.salt.clone()
    }

    /// `wrapped_account_key`: the account key sealed by the unlock key.
    #[wasm_bindgen(js_name = wrappedAccountKey)]
    pub fn wrapped_account_key(&self) -> Vec<u8> {
        self.created.material.wrapped_account_key.clone()
    }

    /// `recovery_wrapped_account_key`: the account key sealed by the recovery key.
    #[wasm_bindgen(js_name = recoveryWrappedAccountKey)]
    pub fn recovery_wrapped_account_key(&self) -> Vec<u8> {
        self.created.material.recovery_wrapped_account_key.clone()
    }

    /// `unlock_kind` as its wire number: 1 = login password, 2 = vault password.
    #[wasm_bindgen(js_name = unlockKind)]
    pub fn unlock_kind(&self) -> u32 {
        match self.created.material.unlock_source {
            UnlockSource::LoginPassword => 1,
            UnlockSource::VaultPassword => 2,
        }
    }

    /// The recovery key in its display form. Show it once and keep it nowhere.
    #[wasm_bindgen(js_name = recoveryKey)]
    pub fn recovery_key(&self) -> String {
        self.created.recovery.display().to_string()
    }

    /// The unlocked account of the new keyset. Consumes the keyset: read the material first.
    #[wasm_bindgen(js_name = intoAccount)]
    pub fn into_account(self) -> WebAccount {
        WebAccount {
            account: self.created.account_key,
        }
    }
}

/// Creates the first keyset of an account that signs in with a password: the unlock key comes
/// from the login password (`login-v1`, bound to the hub and user name), as on a native
/// client. Costs 64 MiB and a few hundred milliseconds: call it from a worker.
#[wasm_bindgen(js_name = createKeysetWithLoginPassword)]
pub fn create_keyset_with_login_password(
    password: &str,
    hub_id: &str,
    username: &str,
    account_id: &str,
) -> Result<WebNewKeyset, JsError> {
    new_login_keyset(password, hub_id, username, account_id).map_err(JsError::from)
}

/// Creates the first keyset of an account with a separate vault password (an account that
/// signs in through an identity provider): fresh salt, minimum Argon2id parameters.
#[wasm_bindgen(js_name = createKeysetWithVaultPassword)]
pub fn create_keyset_with_vault_password(
    password: &str,
    account_id: &str,
) -> Result<WebNewKeyset, JsError> {
    new_vault_keyset(password, account_id).map_err(JsError::from)
}

fn new_login_keyset(
    password: &str,
    hub_id: &str,
    username: &str,
    account_id: &str,
) -> Result<WebNewKeyset, WebError> {
    let secrets = LoginSecrets::derive(password, hub_id, username)?;
    let created = create_keyset(account_id, secrets.unlock(), secrets.kdf())?;
    Ok(WebNewKeyset { created })
}

fn new_vault_keyset(password: &str, account_id: &str) -> Result<WebNewKeyset, WebError> {
    let kdf = UnlockKdf::random()?;
    let unlock = UnlockKey::from_vault_password(password, &kdf)?;
    let created = create_keyset(account_id, &unlock, &kdf)?;
    Ok(WebNewKeyset { created })
}

/// The value a client sends to the hub where it expects the password (`login-v1`, 64 hex
/// characters). The unlock key derived beside it never leaves WebAssembly. Costs 64 MiB and a
/// few hundred milliseconds: call it from a worker.
#[wasm_bindgen(js_name = loginAuth)]
pub fn login_auth(password: &str, hub_id: &str, username: &str) -> Result<String, JsError> {
    let derive = || -> Result<String, WebError> {
        Ok(LoginSecrets::derive(password, hub_id, username)?
            .auth()
            .to_owned())
    };
    derive().map_err(JsError::from)
}

#[cfg(test)]
mod tests;
