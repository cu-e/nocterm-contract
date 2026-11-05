//! WebAssembly bindings of the Nocterm agent formats.
//!
//! Owns: the browser-facing surface that lets the web panel create the first keyset of an
//! account (`createKeysetWithLoginPassword`, `createKeysetWithVaultPassword`), unlock an
//! account from its password (login or vault), derive the login value for the hub, seal an
//! agent definition (format 1 `sealDefinition`, format 2 `sealDefinitionV2`) to a pool's
//! encryption key, compare a pool's key fingerprint, check offered pool keys against a pin
//! (`checkPoolKeys`), verify a host's runner attestation, and read the account's saved server
//! profiles: open a collection key (`openCollection`, or `openGrantedCollection` under the
//! granter's pinned key), open its profile objects (`WebCollectionKey.openObject`) and show
//! an account key's fingerprint (`accountKeyFingerprint`), and run the account's Cloud chats
//! as a browser device ([`cloud`]: one `CloudDevice` with the flows `connect`, `listChats`,
//! `openChat`, `deliver`, `createChat` and `lease` of `nocterm-cloud-device`, structured values
//! with generated TypeScript declarations, no JSON text; `listChats` lists from the runners'
//! chat directories and hands out sealed directory checkpoints the page stores per runner; an
//! open chat also runs the SSH binding flows `bindServers`, `unbindServers` and `answerSsh` and
//! lists the bound servers a prompt may name, `sessionTargets`).
//! All cryptography is
//! `nocterm-keys`; this crate only converts text and bytes at the JavaScript boundary.
//! Does not own: key storage, the network, or any user interface.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: secrets never cross into JavaScript (only public keys, fingerprints and sealed
//! bytes), except the recovery key of a new keyset, which the page shows the user once, and
//! the plaintext of profile objects (kind `profile`, which hold no secrets); the account key,
//! collection keys, chat keys, provider keys and objects of any other kind (credentials, Cloud
//! records) stay inside WebAssembly, and Cloud flows hand out only effects, sealed bytes,
//! sealed checkpoints and display data; the device key stays in the page's WebCrypto store,
//! and a signature the page supplies is verified against the device key named in the signed
//! bytes before anything is sealed; a granted collection key opens only under the granter key
//! the caller pinned; errors are typed here and become strings only at the boundary (Cloud
//! refusals carry a stable code). Feature `testing` adds `CloudDevice.connectSeeded` for
//! recorded test sessions; a shipped build never enables it.

use nocterm_hub_model::agents::{
    AgentScope, PoolKeys, PoolTrust, ScopeKind, SignedHostRunnerAttestation, check_pool_keys,
};
use nocterm_hub_model::{AgentId, InstanceId, OrgId, PoolId};
use nocterm_keys::agents::{
    AgentDefinitionV1, AgentDefinitionV2, DefinitionContext, DefinitionError, SealDefinitionError,
    seal_definition, seal_definition_v2,
};
use nocterm_keys::{
    AccountKey, AccountKeyPair, CreatedKeyset, KeyError, KeysetMaterialError, LoginError,
    LoginSecrets, OpenError, PublicKey, PublicKeyError, UnlockKdf, UnlockKey, UnlockSource,
    create_keyset,
};
use wasm_bindgen::prelude::*;

pub mod cloud;
mod collection;

pub use collection::{WebCollectionKey, account_key_fingerprint};

/// What can go wrong at the boundary.
#[derive(Debug, thiserror::Error)]
pub enum WebError {
    /// An identifier or enum is not in its text form.
    #[error("invalid {0}")]
    Argument(&'static str),
    /// The keyset's key derivation parameters or salt are not acceptable.
    #[error(transparent)]
    Kdf(#[from] nocterm_keys::KdfParseError),
    /// The password could not be turned into keys.
    #[error(transparent)]
    Login(#[from] LoginError),
    /// A sealed key did not open: wrong password or modified data.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// A public key is not 32 bytes of X25519.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// The definition JSON is not a valid definition.
    #[error("the definition is not valid JSON of the definition format")]
    Json(#[source] serde_json::Error),
    /// The definition violates a limit.
    #[error(transparent)]
    Definition(#[from] DefinitionError),
    /// Sealing failed.
    #[error(transparent)]
    Seal(#[from] SealDefinitionError),
    /// The attestation does not verify.
    #[error(transparent)]
    Attestation(#[from] nocterm_hub_model::agents::AttestationError),
    /// No randomness for a new salt or key.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A new keyset could not be built.
    #[error(transparent)]
    Keyset(#[from] KeysetMaterialError),
    /// The granter's key is not the one the caller pinned.
    #[error(transparent)]
    Pin(#[from] nocterm_keys::PinError),
    /// A new collection key could not be wrapped or its name sealed.
    #[error(transparent)]
    SealCollection(#[from] nocterm_keys::SealError),
    /// Objects of this kind stay sealed in the browser.
    #[error("objects of kind {0:?} are not opened in the browser")]
    SealedKind(String),
}

fn uuid(text: &str, what: &'static str) -> Result<uuid::Uuid, WebError> {
    uuid::Uuid::parse_str(text).map_err(|_| WebError::Argument(what))
}

fn scope(kind: &str, org: Option<String>) -> Result<AgentScope, WebError> {
    let kind = match kind {
        "account" => ScopeKind::Account,
        "org" => ScopeKind::Org,
        "instance" => ScopeKind::Instance,
        _ => return Err(WebError::Argument("scope kind")),
    };
    let org = org
        .map(|o| uuid(&o, "organization id").map(OrgId::from_uuid))
        .transpose()?;
    AgentScope::from_parts(kind, org).map_err(|_| WebError::Argument("scope"))
}

fn bytes32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], WebError> {
    bytes.try_into().map_err(|_| WebError::Argument(what))
}

/// An unlocked account: its account key (which opens the account's own collection keys) and
/// the owner's X25519 pair (which opens keys granted to it). Neither leaves WebAssembly.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebAccount {
    account_id: String,
    account: AccountKey,
    pair: AccountKeyPair,
}

#[wasm_bindgen]
impl WebAccount {
    /// Unlocks with the password: derives the unlock key, opens the account key and then the
    /// key pair the hub published `public_key` for.
    pub fn unlock(
        password: &str,
        hub_id: &str,
        username: &str,
        account_id: &str,
        sealed_account_key: &[u8],
        sealed_private_key: &[u8],
        public_key: &[u8],
    ) -> Result<WebAccount, JsError> {
        Self::open(
            password,
            hub_id,
            username,
            account_id,
            sealed_account_key,
            sealed_private_key,
            public_key,
        )
        .map_err(JsError::from)
    }

    /// Unlocks with a separate vault password, using the derivation the keyset records
    /// (`kdf` as `argon2id;m=…;t=…;p=…` and its `salt`). Weak or excessive parameters are
    /// refused, so a hostile hub cannot downgrade the derivation.
    #[wasm_bindgen(js_name = unlockWithPassword)]
    #[allow(clippy::too_many_arguments)]
    pub fn unlock_with_password(
        password: &str,
        kdf: &str,
        salt: &[u8],
        account_id: &str,
        sealed_account_key: &[u8],
        sealed_private_key: &[u8],
        public_key: &[u8],
    ) -> Result<WebAccount, JsError> {
        Self::open_vault(
            password,
            kdf,
            salt,
            account_id,
            sealed_account_key,
            sealed_private_key,
            public_key,
        )
        .map_err(JsError::from)
    }

    /// The account's public key.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.pair.public_key().to_bytes().to_vec()
    }

    /// Seals a definition (JSON of `AgentDefinitionV1`) to a pool's encryption key.
    #[wasm_bindgen(js_name = sealDefinition)]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_definition(
        &self,
        definition_json: &str,
        agent_id: &str,
        scope_kind: &str,
        org_id: Option<String>,
        pool_id: &str,
        version: u64,
        pool_encryption_key: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.seal(
            definition_json,
            agent_id,
            scope_kind,
            org_id,
            pool_id,
            version,
            pool_encryption_key,
        )
        .map_err(JsError::from)
    }

    /// Seals a version 2 definition (JSON of `AgentDefinitionV2`: the version 1 fields plus
    /// `tools`, `limits` and `pricing`) to a pool's encryption key. Only a host that reads
    /// definition format 2 opens the envelope.
    #[wasm_bindgen(js_name = sealDefinitionV2)]
    #[allow(clippy::too_many_arguments)]
    pub fn seal_definition_v2(
        &self,
        definition_json: &str,
        agent_id: &str,
        scope_kind: &str,
        org_id: Option<String>,
        pool_id: &str,
        version: u64,
        pool_encryption_key: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.seal_v2(
            definition_json,
            agent_id,
            scope_kind,
            org_id,
            pool_id,
            version,
            pool_encryption_key,
        )
        .map_err(JsError::from)
    }
}

fn definition_context(
    agent_id: &str,
    scope_kind: &str,
    org_id: Option<String>,
    pool_id: &str,
    version: u64,
) -> Result<DefinitionContext, WebError> {
    Ok(DefinitionContext {
        agent: AgentId::from_uuid(uuid(agent_id, "agent id")?),
        scope: scope(scope_kind, org_id)?,
        pool: PoolId::from_uuid(uuid(pool_id, "pool id")?),
        version,
    })
}

impl WebAccount {
    fn open(
        password: &str,
        hub_id: &str,
        username: &str,
        account_id: &str,
        sealed_account_key: &[u8],
        sealed_private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, WebError> {
        let secrets = LoginSecrets::derive(password, hub_id, username)?;
        let account = AccountKey::open(secrets.unlock(), account_id, sealed_account_key)?;
        Self::with_account(account_id, account, sealed_private_key, public_key)
    }

    #[allow(clippy::too_many_arguments)]
    fn open_vault(
        password: &str,
        kdf: &str,
        salt: &[u8],
        account_id: &str,
        sealed_account_key: &[u8],
        sealed_private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, WebError> {
        let kdf = UnlockKdf::parse(kdf, salt)?;
        let unlock = UnlockKey::from_vault_password(password, &kdf)?;
        let account = AccountKey::open(&unlock, account_id, sealed_account_key)?;
        Self::with_account(account_id, account, sealed_private_key, public_key)
    }

    /// Opens the key pair the hub published `public_key` for with the opened account key.
    fn with_account(
        account_id: &str,
        account: AccountKey,
        sealed_private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, WebError> {
        let public = PublicKey::from_bytes(public_key)?;
        let pair = AccountKeyPair::open(&account, account_id, sealed_private_key, &public)?;
        Ok(Self {
            account_id: account_id.to_owned(),
            account,
            pair,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn seal(
        &self,
        definition_json: &str,
        agent_id: &str,
        scope_kind: &str,
        org_id: Option<String>,
        pool_id: &str,
        version: u64,
        pool_encryption_key: &[u8],
    ) -> Result<Vec<u8>, WebError> {
        let definition: AgentDefinitionV1 =
            serde_json::from_str(definition_json).map_err(WebError::Json)?;
        let context = definition_context(agent_id, scope_kind, org_id, pool_id, version)?;
        let pool = PublicKey::from_bytes(pool_encryption_key)?;
        Ok(seal_definition(&self.pair, &pool, &context, &definition)?)
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_v2(
        &self,
        definition_json: &str,
        agent_id: &str,
        scope_kind: &str,
        org_id: Option<String>,
        pool_id: &str,
        version: u64,
        pool_encryption_key: &[u8],
    ) -> Result<Vec<u8>, WebError> {
        let definition: AgentDefinitionV2 =
            serde_json::from_str(definition_json).map_err(WebError::Json)?;
        let context = definition_context(agent_id, scope_kind, org_id, pool_id, version)?;
        let pool = PublicKey::from_bytes(pool_encryption_key)?;
        Ok(seal_definition_v2(
            &self.pair,
            &pool,
            &context,
            &definition,
        )?)
    }
}

/// A keyset created in the browser: the values `PutAccountKeyset` stores (send them with
/// `expected_version = 0`), the recovery key to show once, and the unlocked account.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebNewKeyset {
    account_id: String,
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

    /// `public_key`: the account's X25519 public key.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.created.material.public_key.to_bytes().to_vec()
    }

    /// `sealed_private_key`: the private key sealed by the account key.
    #[wasm_bindgen(js_name = sealedPrivateKey)]
    pub fn sealed_private_key(&self) -> Vec<u8> {
        self.created.material.sealed_private_key.clone()
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

    /// The recovery key in its display form. Show it to the user once and keep it nowhere.
    #[wasm_bindgen(js_name = recoveryKey)]
    pub fn recovery_key(&self) -> String {
        self.created.recovery.display().to_string()
    }

    /// The unlocked account of the new keyset, for sealing right after creation. Consumes
    /// the keyset object: read the material first.
    #[wasm_bindgen(js_name = intoAccount)]
    pub fn into_account(self) -> WebAccount {
        WebAccount {
            account_id: self.account_id,
            account: self.created.account_key,
            pair: self.created.pair,
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
    Ok(WebNewKeyset {
        account_id: account_id.to_owned(),
        created,
    })
}

fn new_vault_keyset(password: &str, account_id: &str) -> Result<WebNewKeyset, WebError> {
    let kdf = UnlockKdf::random()?;
    let unlock = UnlockKey::from_vault_password(password, &kdf)?;
    let created = create_keyset(account_id, &unlock, &kdf)?;
    Ok(WebNewKeyset {
        account_id: account_id.to_owned(),
        created,
    })
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

/// The fingerprint people compare to confirm a pool's keys.
#[wasm_bindgen(js_name = poolFingerprint)]
pub fn pool_fingerprint(encryption_key: &[u8], signing_key: &[u8]) -> Result<String, JsError> {
    let keys = PoolKeys {
        encryption: bytes32(encryption_key, "encryption key")?,
        signing: bytes32(signing_key, "signing key")?,
    };
    Ok(keys.fingerprint())
}

/// Compares the keys a hub offers for a pool with this browser's pin (trust on first use), as
/// `nocterm_hub_model::agents::check_pool_keys` decides: `"first_use"` when nothing is pinned
/// (pass neither pinned key), `"pinned"` when both keys equal the pin, `"changed"` otherwise.
/// Seal nothing to a pool that is not `"pinned"`.
#[wasm_bindgen(js_name = checkPoolKeys)]
pub fn check_pool_keys_js(
    pinned_encryption_key: Option<Vec<u8>>,
    pinned_signing_key: Option<Vec<u8>>,
    offered_encryption_key: &[u8],
    offered_signing_key: &[u8],
) -> Result<String, JsError> {
    let check = || -> Result<&'static str, WebError> {
        let pinned = pin_pair(pinned_encryption_key, pinned_signing_key)?;
        pool_trust(
            pinned.as_ref().map(|(e, s)| (e.as_slice(), s.as_slice())),
            offered_encryption_key,
            offered_signing_key,
        )
    };
    check().map(str::to_owned).map_err(JsError::from)
}

/// A pinned encryption and signing key, as JavaScript passes them.
type PinnedPair = (Vec<u8>, Vec<u8>);

/// Both pinned keys or neither.
fn pin_pair(
    encryption: Option<Vec<u8>>,
    signing: Option<Vec<u8>>,
) -> Result<Option<PinnedPair>, WebError> {
    match (encryption, signing) {
        (None, None) => Ok(None),
        (Some(encryption), Some(signing)) => Ok(Some((encryption, signing))),
        _ => Err(WebError::Argument("pin (both keys or neither)")),
    }
}

fn pool_trust(
    pinned: Option<(&[u8], &[u8])>,
    offered_encryption: &[u8],
    offered_signing: &[u8],
) -> Result<&'static str, WebError> {
    let pinned = pinned
        .map(|(encryption, signing)| -> Result<PoolKeys, WebError> {
            Ok(PoolKeys {
                encryption: bytes32(encryption, "pinned encryption key")?,
                signing: bytes32(signing, "pinned signing key")?,
            })
        })
        .transpose()?;
    let offered = PoolKeys {
        encryption: bytes32(offered_encryption, "encryption key")?,
        signing: bytes32(offered_signing, "signing key")?,
    };
    Ok(match check_pool_keys(pinned.as_ref(), &offered) {
        Ok(PoolTrust::FirstUse) => "first_use",
        Ok(PoolTrust::Pinned) => "pinned",
        Err(_) => "changed",
    })
}

/// Verifies a host's runner attestation under the pinned pool signing key.
#[wasm_bindgen(js_name = verifyRunnerAttestation)]
pub fn verify_runner_attestation(
    pool_signing_key: &[u8],
    pool_id: &str,
    instance_id: &str,
    attestation: &[u8],
    signature: &[u8],
) -> Result<(), JsError> {
    let check = || -> Result<(), WebError> {
        let signed = SignedHostRunnerAttestation::from_wire(attestation, signature)?;
        signed.verify(
            &bytes32(pool_signing_key, "signing key")?,
            PoolId::from_uuid(uuid(pool_id, "pool id")?),
            InstanceId::from_uuid(uuid(instance_id, "instance id")?),
        )?;
        Ok(())
    };
    check().map_err(JsError::from)
}

#[cfg(test)]
mod tests;
