//! WebAssembly bindings of the Nocterm agent formats.
//!
//! Owns: the browser-facing surface that lets the web panel unlock an account from its
//! password (login or vault), derive the login value for the hub, seal an agent definition to a pool's encryption key, compare a pool's key
//! fingerprint and verify a host's runner attestation. All cryptography is `nocterm-keys`;
//! this crate only converts text and bytes at the JavaScript boundary.
//! Does not own: key storage, the network, or any user interface.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: secrets never cross into JavaScript (only public keys, fingerprints and sealed
//! bytes); errors are typed here and become strings only at the boundary.

use nocterm_hub_model::agents::{AgentScope, PoolKeys, ScopeKind, SignedHostRunnerAttestation};
use nocterm_hub_model::{AgentId, InstanceId, OrgId, PoolId};
use nocterm_keys::agents::{
    AgentDefinitionV1, DefinitionContext, DefinitionError, SealDefinitionError, seal_definition,
};
use nocterm_keys::{
    AccountKey, AccountKeyPair, LoginError, LoginSecrets, OpenError, PublicKey, PublicKeyError,
    UnlockKdf, UnlockKey,
};
use wasm_bindgen::prelude::*;

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

/// An unlocked account: the owner's X25519 pair. The private half never leaves WebAssembly.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebAccount {
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
        let public = PublicKey::from_bytes(public_key)?;
        let pair = AccountKeyPair::open(&account, account_id, sealed_private_key, &public)?;
        Ok(Self { pair })
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
        let public = PublicKey::from_bytes(public_key)?;
        let pair = AccountKeyPair::open(&account, account_id, sealed_private_key, &public)?;
        Ok(Self { pair })
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
        let context = DefinitionContext {
            agent: AgentId::from_uuid(uuid(agent_id, "agent id")?),
            scope: scope(scope_kind, org_id)?,
            pool: PoolId::from_uuid(uuid(pool_id, "pool id")?),
            version,
        };
        let pool = PublicKey::from_bytes(pool_encryption_key)?;
        Ok(seal_definition(&self.pair, &pool, &context, &definition)?)
    }
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
mod tests {
    use super::*;

    #[test]
    fn scopes_and_identifiers_are_parsed_strictly() {
        assert_eq!(scope("account", None).unwrap(), AgentScope::Account);
        assert!(scope("org", None).is_err());
        assert!(scope("account", Some(uuid::Uuid::nil().to_string())).is_err());
        assert!(scope("galaxy", None).is_err());
        assert!(uuid("nope", "agent id").is_err());
    }

    #[test]
    fn an_unlocked_account_seals_a_definition_the_pool_opens() {
        use nocterm_keys::agents::open_definition;
        let (hub, user, account_id) = ("hub", "ann", "acc-1");
        let secrets = LoginSecrets::derive("correct horse battery", hub, user).unwrap();
        let account = AccountKey::generate().unwrap();
        let pair = AccountKeyPair::generate().unwrap();
        let sealed_account = account.seal(secrets.unlock(), account_id).unwrap();
        let sealed_pair = pair.seal(&account, account_id).unwrap();
        let web = WebAccount::open(
            "correct horse battery",
            hub,
            user,
            account_id,
            &sealed_account,
            &sealed_pair,
            &pair.public_key().to_bytes(),
        )
        .unwrap();
        assert!(
            WebAccount::open(
                "wrong password!!",
                hub,
                user,
                account_id,
                &sealed_account,
                &sealed_pair,
                &pair.public_key().to_bytes()
            )
            .is_err()
        );

        let pool_pair = AccountKeyPair::generate().unwrap();
        let (agent, pool) = (AgentId::new(), PoolId::new());
        let json = r#"{"name":"A","instructions":"","provider":{"kind":"k","endpoint":"","models":["m"],"api_key":null},"secrets":[],"allowed_hosts":[],"ssh_targets":[]}"#;
        let sealed = web
            .seal(
                json,
                &agent.to_string(),
                "account",
                None,
                &pool.to_string(),
                2,
                &pool_pair.public_key().to_bytes(),
            )
            .unwrap();
        let context = DefinitionContext {
            agent,
            scope: AgentScope::Account,
            pool,
            version: 2,
        };
        let opened = open_definition(&pool_pair, &pair.public_key(), &context, &sealed).unwrap();
        assert_eq!(opened.name, "A");
    }

    #[test]
    fn a_vault_password_unlocks_only_with_the_recorded_derivation() {
        let kdf = UnlockKdf::random().unwrap();
        let unlock = UnlockKey::from_vault_password("vault password!", &kdf).unwrap();
        let (account_id, account) = ("acc-2", AccountKey::generate().unwrap());
        let pair = AccountKeyPair::generate().unwrap();
        let sealed_account = account.seal(&unlock, account_id).unwrap();
        let sealed_pair = pair.seal(&account, account_id).unwrap();
        let public = pair.public_key().to_bytes();
        let open = |password: &str, description: &str| {
            WebAccount::open_vault(
                password,
                description,
                kdf.salt(),
                account_id,
                &sealed_account,
                &sealed_pair,
                &public,
            )
        };

        let web = open("vault password!", &kdf.description()).unwrap();
        assert_eq!(web.pair.public_key().to_bytes(), public);
        assert!(open("another password", &kdf.description()).is_err());
        assert!(open("vault password!", "argon2id;m=8;t=1;p=1").is_err());
    }

    #[test]
    fn login_auth_is_the_native_clients_value() {
        let secrets = LoginSecrets::derive("correct horse battery", "hub-0001", "alice").unwrap();
        assert_eq!(secrets.auth().len(), 64);
        assert_eq!(
            LoginSecrets::derive("correct horse battery", "hub-0001", " alice ")
                .unwrap()
                .auth(),
            secrets.auth()
        );
    }
}
