//! A model edit is sealed without making the old definition or its secrets visible to JS.
use nocterm_keys::agents::{
    AgentModelPatch, DefinitionBase, MAX_DEFINITION_BYTES, seal_definition_patch,
};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::{WebAccount, WebError, definition_context};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    agent_id: String,
    scope_kind: String,
    org_id: Option<String>,
    pool_id: String,
    base_version: u64,
    version: u64,
    models: Vec<String>,
}

#[wasm_bindgen]
impl WebAccount {
    /// Seals a format 3 model edit. `request_json` holds `agentId`, `scopeKind`, optional
    /// `orgId`, `poolId`, `baseVersion`, `version` and `models`. `base_envelope` is the exact
    /// pool envelope of that base version. Its owner must be this account's key, as for a
    /// complete definition; only the pool host opens the old settings.
    #[wasm_bindgen(js_name = sealDefinitionPatch)]
    pub fn seal_definition_patch(
        &self,
        request_json: &str,
        base_envelope: &[u8],
        pool_encryption_key: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.seal_patch(request_json, base_envelope, pool_encryption_key)
            .map_err(JsError::from)
    }
}

impl WebAccount {
    fn seal_patch(
        &self,
        request_json: &str,
        base_envelope: &[u8],
        pool_encryption_key: &[u8],
    ) -> Result<Vec<u8>, WebError> {
        if request_json.len() > MAX_DEFINITION_BYTES {
            return Err(WebError::Argument("model edit request size"));
        }
        let request: Request = serde_json::from_str(request_json).map_err(WebError::Json)?;
        let context = definition_context(
            &request.agent_id,
            &request.scope_kind,
            request.org_id,
            &request.pool_id,
            request.version,
        )?;
        let pool = nocterm_keys::PublicKey::from_bytes(pool_encryption_key)?;
        Ok(seal_definition_patch(
            &self.pair,
            &pool,
            &context,
            &DefinitionBase {
                version: request.base_version,
                envelope: base_envelope,
            },
            &AgentModelPatch {
                models: request.models,
            },
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocterm_hub_model::agents::AgentScope;
    use nocterm_hub_model::{AgentId, PoolId};
    use nocterm_keys::agents::{
        AgentDefinitionV1, DefinitionContext, open_definition_any, seal_definition,
    };
    use nocterm_keys::{AccountKey, AccountKeyPair};

    #[test]
    fn a_browser_edits_models_while_the_provider_key_stays_inside_the_old_envelope() {
        let web = WebAccount {
            account_id: "owner".into(),
            account: AccountKey::generate().unwrap(),
            pair: AccountKeyPair::generate().unwrap(),
        };
        let pool = AccountKeyPair::generate().unwrap();
        let context = DefinitionContext {
            agent: AgentId::new(),
            scope: AgentScope::Account,
            pool: PoolId::new(),
            version: 2,
        };
        let json = r#"{"name":"A","instructions":"keep prompt","provider":{"kind":"openai_chat","endpoint":"https://provider.example","models":["a"],"api_key":"keep-key"},"secrets":[["TOKEN","keep-secret"]],"allowed_hosts":[],"ssh_targets":[]}"#;
        let original: AgentDefinitionV1 = serde_json::from_str(json).unwrap();
        let base = seal_definition(&web.pair, &pool.public_key(), &context, &original).unwrap();
        let request = serde_json::json!({ "agentId": context.agent.to_string(), "scopeKind": "account",
            "poolId": context.pool.to_string(), "baseVersion": 2, "version": 5, "models": ["a", "b"] });
        let patch = web
            .seal_definition_patch(&request.to_string(), &base, &pool.public_key().to_bytes())
            .unwrap();
        let opened = open_definition_any(
            &pool,
            &web.pair.public_key(),
            &DefinitionContext {
                version: 5,
                ..context
            },
            &patch,
        )
        .unwrap()
        .into_v2();
        assert_eq!(opened.provider.models, ["a", "b"]);
        assert_eq!(opened.provider.api_key, original.provider.api_key);
        assert_eq!(opened.instructions, original.instructions);
        assert_eq!(opened.secrets, original.secrets);
        let oversized = "x".repeat(MAX_DEFINITION_BYTES + 1);
        assert!(
            web.seal_patch(&oversized, &base, &pool.public_key().to_bytes())
                .is_err()
        );
    }
}
