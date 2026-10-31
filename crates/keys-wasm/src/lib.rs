//! WebAssembly bindings of the Nocterm agent formats.
//!
//! Owns: the browser-facing surface that lets the web panel create the first keyset of an
//! account (`createKeysetWithLoginPassword`, `createKeysetWithVaultPassword`), unlock an
//! account from its password (login or vault), derive the login value for the hub, seal an
//! agent definition (format 1 `sealDefinition`, format 2 `sealDefinitionV2`) to a pool's
//! encryption key, compare a pool's key fingerprint and verify a
//! host's runner attestation. All cryptography is `nocterm-keys`; this crate only converts
//! text and bytes at the JavaScript boundary.
//! Does not own: key storage, the network, or any user interface.
//! Ports used/provided: none. Settings: none. Globals: none.
//! Invariants: secrets never cross into JavaScript (only public keys, fingerprints and sealed
//! bytes), except the recovery key of a new keyset, which the page shows the user once;
//! errors are typed here and become strings only at the boundary.

use nocterm_hub_model::agents::{AgentScope, PoolKeys, ScopeKind, SignedHostRunnerAttestation};
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
    fn a_version_two_definition_from_json_opens_with_its_policy() {
        use nocterm_keys::agents::{
            AgentDefinition, DEFINITION_FORMAT_VERSION_V2, ToolApproval, open_definition_any,
            sealed_definition_version,
        };
        let pair = AccountKeyPair::generate().unwrap();
        let web = WebAccount { pair };
        let pool_pair = AccountKeyPair::generate().unwrap();
        let (agent, pool) = (AgentId::new(), PoolId::new());
        let json = r#"{"name":"A","instructions":"","provider":{"kind":"k","endpoint":"","models":["m"],"api_key":null},"secrets":[],"allowed_hosts":[],"ssh_targets":[],
            "tools":{"allowed":{"only":["read_file"]},"approval":"always"},
            "limits":{"max_turns":20,"max_output_tokens":null,"max_spend_micros_per_run":null,"max_spend_micros_per_chat":1000000},
            "pricing":[{"model":"m","input_micros_per_mtok":1,"output_micros_per_mtok":2,"cached_input_micros_per_mtok":null,"revision":"r1"}]}"#;
        let sealed = web
            .seal_v2(
                json,
                &agent.to_string(),
                "account",
                None,
                &pool.to_string(),
                4,
                &pool_pair.public_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(
            sealed_definition_version(&sealed),
            Some(DEFINITION_FORMAT_VERSION_V2)
        );
        let context =
            definition_context(&agent.to_string(), "account", None, &pool.to_string(), 4).unwrap();
        let AgentDefinition::V2(opened) =
            open_definition_any(&pool_pair, &web.pair.public_key(), &context, &sealed).unwrap()
        else {
            panic!("expected a version 2 definition");
        };
        assert_eq!(opened.tools.approval, ToolApproval::Always);
        assert_eq!(opened.limits.max_turns, Some(20));
        assert_eq!(opened.price("m").unwrap().revision, "r1");
        let invalid = json.replace("\"max_turns\":20", "\"max_turns\":0");
        assert!(matches!(
            web.seal_v2(
                &invalid,
                &agent.to_string(),
                "account",
                None,
                &pool.to_string(),
                4,
                &pool_pair.public_key().to_bytes(),
            ),
            Err(WebError::Seal(_))
        ));
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
    fn a_keyset_created_in_the_browser_unlocks_like_a_native_one() {
        let (hub, user, account_id) = ("hub", "ann", "acc-3");
        let created = new_login_keyset("correct horse battery", hub, user, account_id).unwrap();
        assert_eq!(created.unlock_kind(), 1);
        assert_eq!(created.kdf(), "argon2id;m=65536;t=3;p=4");
        let web = WebAccount::open(
            "correct horse battery",
            hub,
            user,
            account_id,
            &created.wrapped_account_key(),
            &created.sealed_private_key(),
            &created.public_key(),
        )
        .unwrap();
        assert_eq!(web.public_key(), created.public_key());
        let recovery = nocterm_keys::RecoveryKey::parse(&created.recovery_key()).unwrap();
        recovery
            .unwrap(account_id, &created.recovery_wrapped_account_key())
            .unwrap();
        assert_eq!(created.into_account().public_key(), web.public_key());
    }

    #[test]
    fn a_vault_keyset_records_its_derivation_and_refuses_short_passwords() {
        let created = new_vault_keyset("vault password!", "acc-4").unwrap();
        assert_eq!(created.unlock_kind(), 2);
        let web = WebAccount::open_vault(
            "vault password!",
            &created.kdf(),
            &created.salt(),
            "acc-4",
            &created.wrapped_account_key(),
            &created.sealed_private_key(),
            &created.public_key(),
        )
        .unwrap();
        assert_eq!(web.public_key(), created.public_key());
        assert!(matches!(
            new_vault_keyset("short", "acc-4"),
            Err(WebError::Login(LoginError::PasswordTooShort { .. }))
        ));
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
