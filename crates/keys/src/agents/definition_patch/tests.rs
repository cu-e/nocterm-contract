use super::*;
use crate::agents::{
    DEFINITION_FORMAT_VERSION_V2, ToolApproval, seal_definition, seal_definition_v2,
};
use nocterm_hub_model::agents::AgentScope;
use nocterm_hub_model::{AgentId, OrgId, PoolId};

struct World {
    owner: AccountKeyPair,
    pool: AccountKeyPair,
    context: DefinitionContext,
}

fn world() -> World {
    World {
        owner: AccountKeyPair::generate().unwrap(),
        pool: AccountKeyPair::generate().unwrap(),
        context: DefinitionContext {
            agent: AgentId::new(),
            scope: AgentScope::Account,
            pool: PoolId::new(),
            version: 7,
        },
    }
}

fn patch(w: &World, base: &[u8], base_version: u64, models: &[&str]) -> Vec<u8> {
    seal_definition_patch(
        &w.owner,
        &w.pool.public_key(),
        &w.context,
        &DefinitionBase {
            version: base_version,
            envelope: base,
        },
        &AgentModelPatch {
            models: models.iter().map(|id| (*id).to_owned()).collect(),
        },
    )
    .unwrap()
}

#[test]
fn editing_models_preserves_every_hidden_setting_and_surviving_price() {
    let w = world();
    let mut base_context = w.context;
    base_context.version = 2;
    let original = crate::agents::definition_v2::sample_v2();
    let base =
        seal_definition_v2(&w.owner, &w.pool.public_key(), &base_context, &original).unwrap();
    let models = [&original.provider.models[0][..], "second-model"];
    let edited = patch(&w, &base, 2, &models);
    assert_eq!(
        sealed_definition_version(&edited),
        Some(DEFINITION_FORMAT_VERSION_PATCH)
    );
    let opened = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &edited).unwrap();
    assert_eq!(opened.format_version(), DEFINITION_FORMAT_VERSION_PATCH);
    let mut expected = original.clone();
    expected.provider.models = models.map(str::to_owned).to_vec();
    assert_eq!(opened.into_v2(), expected);
    // An older format-specific decoder cannot mistake a patch for a full definition.
    let mut relabelled = edited.clone();
    relabelled[0] = DEFINITION_FORMAT_VERSION_V2;
    assert!(open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &relabelled).is_err());
}

#[test]
fn removing_a_model_removes_only_its_price_and_version_one_keeps_its_meaning() {
    let w = world();
    let mut base_context = w.context;
    base_context.version = 1;
    let original = crate::agents::definition_v2::sample_v2();
    let base =
        seal_definition_v2(&w.owner, &w.pool.public_key(), &base_context, &original).unwrap();
    let edited = patch(&w, &base, 1, &["new-model"]);
    let opened = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &edited)
        .unwrap()
        .into_v2();
    assert!(opened.pricing.is_empty());
    assert_eq!(opened.provider.api_key, original.provider.api_key);
    let v1 = crate::agents::definition::sample();
    let base = seal_definition(&w.owner, &w.pool.public_key(), &base_context, &v1).unwrap();
    let edited = patch(&w, &base, 1, &["new-model"]);
    let opened = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &edited)
        .unwrap()
        .into_v2();
    assert_eq!(opened.tools.approval, ToolApproval::Ask);
    assert_eq!(opened.provider.api_key, v1.provider.api_key);
}

#[test]
fn edits_authenticate_every_context_value_owner_and_manifest() {
    let w = world();
    let mut base_context = w.context;
    base_context.version = 1;
    let base = seal_definition_v2(
        &w.owner,
        &w.pool.public_key(),
        &base_context,
        &crate::agents::definition_v2::sample_v2(),
    )
    .unwrap();
    let edited = patch(&w, &base, 1, &["m"]);
    for context in [
        DefinitionContext {
            agent: AgentId::new(),
            ..w.context
        },
        DefinitionContext {
            scope: AgentScope::Org(OrgId::new()),
            ..w.context
        },
        DefinitionContext {
            pool: PoolId::new(),
            ..w.context
        },
        DefinitionContext {
            version: 8,
            ..w.context
        },
    ] {
        assert!(open_definition_any(&w.pool, &w.owner.public_key(), &context, &edited).is_err());
    }
    let stranger = AccountKeyPair::generate().unwrap();
    assert!(open_definition_any(&w.pool, &stranger.public_key(), &w.context, &edited).is_err());
    assert!(open_definition_any(&stranger, &w.owner.public_key(), &w.context, &edited).is_err());
    let mut damaged = edited.clone();
    damaged[2] ^= 1;
    assert!(open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &damaged).is_err());
    let wrong_version = patch(&w, &base, 2, &["m"]);
    assert!(
        open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &wrong_version).is_err()
    );
    let foreign_base = seal_definition_v2(
        &stranger,
        &w.pool.public_key(),
        &base_context,
        &crate::agents::definition_v2::sample_v2(),
    )
    .unwrap();
    let edited = patch(&w, &foreign_base, 1, &["m"]);
    assert!(open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &edited).is_err());
}

#[test]
fn repeated_edits_keep_one_base_and_constant_size_for_a_fresh_host() {
    let mut w = world();
    w.context.version = 1;
    let original = seal_definition_v2(
        &w.owner,
        &w.pool.public_key(),
        &w.context,
        &crate::agents::definition_v2::sample_v2(),
    )
    .unwrap();
    let mut base = original.clone();
    let mut first_size = 0;
    for edit in 1..=100 {
        w.context.version += 1;
        base = patch(&w, &base, w.context.version - 1, &["m"]);
        if edit == 1 {
            first_size = base.len();
        }
        assert_eq!(
            base.len(),
            first_size,
            "each edit retains one stable base only"
        );
        assert_eq!(
            base.windows(original.len())
                .filter(|window| *window == original)
                .count(),
            1
        );
    }
    let opened = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &base).unwrap();
    assert_eq!(opened.into_v2().provider.models, ["m"]);
}

#[test]
fn a_tampered_base_or_wrong_previous_version_is_refused_before_resealing() {
    let mut w = world();
    let original_context = DefinitionContext {
        version: 1,
        ..w.context
    };
    let original = seal_definition_v2(
        &w.owner,
        &w.pool.public_key(),
        &original_context,
        &crate::agents::definition_v2::sample_v2(),
    )
    .unwrap();
    let edited = patch(&w, &original, 1, &["m"]);
    let previous_version = w.context.version;
    w.context.version += 1;
    let request = AgentModelPatch {
        models: vec!["m".into(), "n".into()],
    };
    let reseal = |bytes: &[u8], version| {
        seal_definition_patch(
            &w.owner,
            &w.pool.public_key(),
            &w.context,
            &DefinitionBase {
                version,
                envelope: bytes,
            },
            &request,
        )
    };
    for offset in [2, 18, edited.len() - 1] {
        let mut tampered = edited.clone();
        tampered[offset] ^= 1;
        assert!(reseal(&tampered, previous_version).is_err());
    }
    assert!(reseal(&edited, previous_version - 1).is_err());
    assert!(reseal(&vec![0; MAX_ENVELOPE_BYTES + 1], previous_version).is_err());
}

#[test]
fn the_owner_does_not_reseal_a_manifest_under_another_identity_or_pool_key() {
    let mut w = world();
    let original_context = DefinitionContext {
        version: 1,
        ..w.context
    };
    let original = seal_definition_v2(
        &w.owner,
        &w.pool.public_key(),
        &original_context,
        &crate::agents::definition_v2::sample_v2(),
    )
    .unwrap();
    let edited = patch(&w, &original, 1, &["m"]);
    let previous_version = w.context.version;
    w.context.version += 1;
    let request = AgentModelPatch {
        models: vec!["m".into(), "n".into()],
    };
    for context in [
        DefinitionContext {
            agent: AgentId::new(),
            ..w.context
        },
        DefinitionContext {
            scope: AgentScope::Instance,
            ..w.context
        },
        DefinitionContext {
            pool: PoolId::new(),
            ..w.context
        },
    ] {
        assert!(
            seal_definition_patch(
                &w.owner,
                &w.pool.public_key(),
                &context,
                &DefinitionBase {
                    version: previous_version,
                    envelope: &edited
                },
                &request
            )
            .is_err()
        );
    }
    let stranger = AccountKeyPair::generate().unwrap();
    assert!(
        seal_definition_patch(
            &stranger,
            &w.pool.public_key(),
            &w.context,
            &DefinitionBase {
                version: previous_version,
                envelope: &edited
            },
            &request
        )
        .is_err()
    );
    assert!(
        seal_definition_patch(
            &w.owner,
            &stranger.public_key(),
            &w.context,
            &DefinitionBase {
                version: previous_version,
                envelope: &edited
            },
            &request
        )
        .is_err()
    );
}

#[test]
fn removing_and_readding_a_base_model_retains_its_original_owner_price() {
    let mut w = world();
    let context = DefinitionContext {
        version: 1,
        ..w.context
    };
    let original = crate::agents::definition_v2::sample_v2();
    let base = seal_definition_v2(&w.owner, &w.pool.public_key(), &context, &original).unwrap();
    let removed = patch(&w, &base, 1, &["other"]);
    let resolved = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &removed)
        .unwrap()
        .into_v2();
    assert!(resolved.pricing.is_empty());
    let previous = w.context.version;
    w.context.version += 1;
    let restored = patch(&w, &removed, previous, &[&original.provider.models[0]]);
    let resolved = open_definition_any(&w.pool, &w.owner.public_key(), &w.context, &restored)
        .unwrap()
        .into_v2();
    assert_eq!(resolved, original);
}

#[test]
fn a_model_edit_rejects_empty_duplicate_oversized_and_unknown_fields() {
    let w = world();
    let context = DefinitionContext {
        version: 1,
        ..w.context
    };
    let base = seal_definition_v2(
        &w.owner,
        &w.pool.public_key(),
        &context,
        &crate::agents::definition_v2::sample_v2(),
    )
    .unwrap();
    for models in [
        vec![],
        vec![String::new()],
        vec!["m".into(), "m".into()],
        vec!["x".repeat(MAX_MODEL_ID_BYTES + 1)],
        vec!["m".into(); MAX_MODELS + 1],
    ] {
        assert!(
            seal_definition_patch(
                &w.owner,
                &w.pool.public_key(),
                &w.context,
                &DefinitionBase {
                    version: 1,
                    envelope: &base
                },
                &AgentModelPatch { models }
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_str::<AgentModelPatch>(r#"{"models":["m"],"api_key":"discard"}"#).is_err()
    );
}
