//! Recorded format 3 bytes pin the public header, box context and manifest MAC layout.
use super::*;
use crate::agents::{AgentDefinitionV2, seal_definition_v2};
use nocterm_hub_model::{AgentId, PoolId, agents::AgentScope};

fn coordinates() -> (AccountKeyPair, AccountKeyPair, DefinitionContext) {
    let owner = AccountKeyPair::from_seed(&[0x11; 32]);
    let pool = AccountKeyPair::from_seed(&[0x22; 32]);
    let context = DefinitionContext {
        agent: AgentId::from_uuid(uuid::Uuid::from_bytes([0x33; 16])),
        scope: AgentScope::Account,
        pool: PoolId::from_uuid(uuid::Uuid::from_bytes([0x44; 16])),
        version: 7,
    };
    (owner, pool, context)
}

fn expected() -> AgentDefinitionV2 {
    let mut definition = crate::agents::definition_v2::sample_v2();
    definition.provider.models.push("second".into());
    definition
}

#[test]
fn the_published_model_edit_vector_keeps_its_owner_context_and_private_settings() {
    let (owner, pool, context) = coordinates();
    let bytes =
        hex::decode(include_str!("../../../../../fixtures/agents-v3/model-edit.hex").trim())
            .unwrap();
    assert_eq!(
        sealed_definition_version(&bytes),
        Some(DEFINITION_FORMAT_VERSION_PATCH)
    );
    let opened = open_definition_any(&pool, &owner.public_key(), &context, &bytes).unwrap();
    assert_eq!(opened.into_v2(), expected());
}

#[test]
#[ignore = "writes the recorded format 3 fixture; run explicitly after a format change"]
fn write_model_edit_fixture() {
    let (owner, pool, context) = coordinates();
    let definition = crate::agents::definition_v2::sample_v2();
    let base = seal_definition_v2(
        &owner,
        &pool.public_key(),
        &DefinitionContext {
            version: 1,
            ..context
        },
        &definition,
    )
    .unwrap();
    let edited = seal_definition_patch(
        &owner,
        &pool.public_key(),
        &context,
        &DefinitionBase {
            version: 1,
            envelope: &base,
        },
        &AgentModelPatch {
            models: expected().provider.models.clone(),
        },
    )
    .unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/agents-v3");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("model-edit.hex"), hex::encode(edited) + "\n").unwrap();
}
