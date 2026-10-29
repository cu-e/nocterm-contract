use super::*;
use crate::{DeviceKey, cloud::RunnerSigningKey};
use nocterm_hub_model::cloud::head::{
    HeadWitness, MAX_HEAD_QUERY_ENVELOPE_BYTES, MAX_HEAD_REPLY_ENVELOPE_BYTES,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-head-v1")
        .join(format!("{name}.hex"));
    Ok(hex::decode(std::fs::read_to_string(path)?.trim())?)
}
#[test]
fn independent_boxes_verify_purpose_pins_challenge_and_deleted_head_without_chat_key() -> TestResult
{
    let account = AccountKeyPair::from_seed(&[0x31; 32]);
    let runner = RunnerEncryptionKey::from_seed(&[0x41; 32]);
    let query = HeadQuery::from_canonical_bytes(&fixture("query-chat")?)?;
    let opened = open_head_query(
        &runner,
        &query.scope,
        query.probe_id,
        &fixture("sealed-query")?,
        100_001,
    )?;
    assert_eq!(opened.query(), &query);
    let witness = open_head_witness(&account, &query, &fixture("sealed-witness")?, 100_001)?;
    assert_eq!(
        witness.witness(),
        &HeadWitness::from_canonical_bytes(&fixture("witness-chat")?)?
    );
    // Production uses the original locally pending query, never offered context.
    let deleted = HeadWitness::from_canonical_bytes(&fixture("witness-deleted")?)?;
    assert_eq!(
        open_head_witness(
            &account,
            &deleted.query,
            &fixture("sealed-deleted")?,
            100_001
        )?
        .witness(),
        &deleted
    );
    Ok(())
}
#[test]
fn random_authenticated_boxes_roundtrip_only_with_exact_original_request() -> TestResult {
    let account = AccountKeyPair::from_seed(&[0x31; 32]);
    let runner = RunnerEncryptionKey::from_seed(&[0x41; 32]);
    let device = DeviceKey::from_seed(&[0x61; 32]);
    let query = HeadQuery::from_canonical_bytes(&fixture("query-chat")?)?;
    let device_query = SignedHeadQuery::new(query.clone(), device.sign(&query.canonical_bytes()?))?;
    let sealed = seal_head_query(&account, &device_query)?;
    assert_eq!(
        open_head_query(&runner, &query.scope, query.probe_id, &sealed, 100_001)?.query(),
        &query
    );
    let value = HeadWitness::from_canonical_bytes(&fixture("witness-chat")?)?;
    let signing_identity = RunnerSigningKey::from_seed(&[0x51; 32]);
    let sealed = seal_head_witness(&runner, &signing_identity.attest_head(value.clone())?)?;
    assert_eq!(
        open_head_witness(&account, &query, &sealed, 100_001)?.witness(),
        &value
    );
    let mut changed = query.clone();
    changed.challenge[0] ^= 1;
    assert!(open_head_witness(&account, &changed, &sealed, 100_001).is_err());
    changed = query.clone();
    changed.scope.keys.runner_signing[0] ^= 1;
    assert!(open_head_witness(&account, &changed, &sealed, 100_001).is_err());
    assert!(
        open_head_witness(
            &AccountKeyPair::from_seed(&[0x32; 32]),
            &query,
            &sealed,
            100_001
        )
        .is_err()
    );
    assert!(open_head_query(&runner, &query.scope, query.probe_id, &sealed, 100_001).is_err());
    assert!(open_head_witness(&account, &query, &sealed, 110_000).is_err());
    assert!(open_head_witness(&account, &query, &sealed, 99_999).is_err());
    Ok(())
}
#[test]
fn valid_outer_box_cannot_hide_wrong_inner_challenge_signature_or_purpose() -> TestResult {
    let account = AccountKeyPair::from_seed(&[0x31; 32]);
    let query = HeadQuery::from_canonical_bytes(&fixture("query-chat")?)?;
    for name in [
        "wrong-inner-challenge",
        "bad-inner-signature",
        "sealed-query",
    ] {
        assert!(open_head_witness(&account, &query, &fixture(name)?, 100_001).is_err());
    }
    let mut sealed = fixture("sealed-witness")?;
    let end = sealed.len() - 1;
    sealed[end] ^= 1;
    assert!(open_head_witness(&account, &query, &sealed, 100_001).is_err());
    assert!(
        open_head_witness(
            &account,
            &query,
            &vec![0; MAX_HEAD_REPLY_ENVELOPE_BYTES + 1],
            100_001
        )
        .is_err()
    );
    let runner = RunnerEncryptionKey::from_seed(&[0x41; 32]);
    assert!(
        open_head_query(
            &runner,
            &query.scope,
            query.probe_id,
            &vec![0; MAX_HEAD_QUERY_ENVELOPE_BYTES + 1],
            100_001
        )
        .is_err()
    );
    Ok(())
}
