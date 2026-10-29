use super::*;
use crate::cloud::{RecordKind, runner_request::RunnerMethod};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloud-head-v1")
        .join(format!("{name}.hex"));
    Ok(hex::decode(std::fs::read_to_string(path)?.trim())?)
}
#[test]
fn independent_query_and_witness_vectors_have_exact_canonical_bytes_and_signatures() -> TestResult {
    let scope = fixture("scope")?;
    assert_eq!(
        HeadProbeScope::from_canonical_bytes(&scope)?.canonical_bytes()?,
        scope
    );
    for name in ["catalog", "catalog-next", "chat", "receipt"] {
        let bytes = fixture(&format!("query-{name}"))?;
        let value = HeadQuery::from_canonical_bytes(&bytes)?;
        assert_eq!(value.canonical_bytes()?, bytes);
        let bytes = fixture(&format!("signed-query-{name}"))?;
        let signed = SignedHeadQuery::from_canonical_bytes(&bytes)?;
        assert_eq!(signed.query(), &value);
        assert_eq!(signed.canonical_bytes()?, bytes);
    }
    for name in [
        "empty",
        "catalog-first",
        "catalog-last",
        "chat",
        "deleted",
        "receipt",
        "receipt-unknown",
    ] {
        let bytes = fixture(&format!("witness-{name}"))?;
        let value = HeadWitness::from_canonical_bytes(&bytes)?;
        assert_eq!(value.canonical_bytes()?, bytes);
        let bytes = fixture(&format!("signed-witness-{name}"))?;
        let signed = SignedHeadWitness::from_canonical_bytes(&bytes)?;
        assert_eq!(signed.witness(), &value);
        assert_eq!(signed.canonical_bytes()?, bytes);
    }
    Ok(())
}
#[test]
fn exact_pending_query_and_both_original_clock_limits_fence_witness_acceptance() -> TestResult {
    let signed = SignedHeadWitness::from_canonical_bytes(&fixture("signed-witness-chat")?)?;
    let original = &signed.witness().query;
    signed.require_query(original, 100_001)?;
    for time in [99_999, 110_000, i64::MAX] {
        assert!(signed.require_query(original, time).is_err());
    }
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.challenge[0] ^= 1,
            1 => changed.probe_id[0] ^= 1,
            2 => changed.scope.keys.account[0] ^= 1,
            3 => changed.scope.keys.runner_signing[0] ^= 1,
            4 => changed.scope.keys.runner_encryption[0] ^= 1,
            5 => changed.scope.runner.key_epoch += 1,
            6 => changed.issuer.access_token_digest[0] ^= 1,
            _ => changed.window.expires_at_ms -= 1,
        }
        assert!(signed.require_query(&changed, 100_001).is_err());
    }
    Ok(())
}
#[test]
fn catalog_pages_bind_known_revision_root_sorting_and_complete_chat_count() -> TestResult {
    let first = HeadWitness::from_canonical_bytes(&fixture("witness-catalog-first")?)?;
    let last = HeadWitness::from_canonical_bytes(&fixture("witness-catalog-last")?)?;
    let (HeadValue::Catalog(a), HeadValue::Catalog(b)) = (&first.value, &last.value) else {
        return Err("catalog".into());
    };
    assert_eq!(a.next_cursor().as_ref(), b.after.as_ref());
    assert!(b.next_cursor().is_none());
    for invalid in 0..5 {
        let mut changed = first.clone();
        let HeadValue::Catalog(page) = &mut changed.value else {
            return Err("catalog".into());
        };
        match invalid {
            0 => page.has_more = false,
            1 => page.total_chats = 0,
            2 => page.chats.clear(),
            3 => page.chats.push(page.chats[0].clone()),
            _ => {
                page.after = b.after.clone();
                changed.query.target = HeadTarget::Catalog {
                    after: page.after.clone(),
                };
                page.revision += 1;
            }
        }
        assert!(changed.canonical_bytes().is_err());
    }
    Ok(())
}
#[test]
fn empty_and_deleted_heads_preserve_real_current_writer_and_retained_snapshot_identity()
-> TestResult {
    let empty = HeadWitness::from_canonical_bytes(&fixture("witness-empty")?)?;
    let HeadValue::Catalog(page) = empty.value else {
        return Err("catalog".into());
    };
    assert!(page.chats.is_empty());
    let mut value = HeadWitness::from_canonical_bytes(&fixture("witness-deleted")?)?;
    let HeadValue::Chat(head) = &mut value.value else {
        return Err("chat".into());
    };
    assert!(head.deleted);
    assert_eq!(head.current_writer, Some(4));
    assert_eq!(head.head.as_ref().ok_or("head")?.position.writer_epoch, 2);
    assert!(head.snapshot.is_none());
    head.deleted = false;
    assert!(value.canonical_bytes().is_err());
    let mut value = HeadWitness::from_canonical_bytes(&fixture("witness-chat")?)?;
    let HeadValue::Chat(head) = &mut value.value else {
        return Err("chat".into());
    };
    let mut snapshot = head.head.clone().ok_or("head")?;
    snapshot.kind = RecordKind::Snapshot;
    head.head = Some(snapshot.clone());
    head.retained_from = snapshot.position.sequence;
    head.snapshot = Some(snapshot);
    value.validate()?;
    let HeadValue::Chat(head) = &mut value.value else {
        return Err("chat".into());
    };
    head.snapshot.as_mut().ok_or("snapshot")?.ciphertext_digest[0] ^= 1;
    assert!(value.validate().is_err());
    Ok(())
}
#[test]
fn closed_tags_eof_and_limits_refuse_malformed_head_inputs() -> TestResult {
    for name in ["query-catalog", "query-chat", "query-receipt"] {
        let bytes = fixture(name)?;
        for end in 0..bytes.len() {
            assert!(HeadQuery::from_canonical_bytes(&bytes[..end]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(HeadQuery::from_canonical_bytes(&extra).is_err());
    }
    let mut query = fixture("query-catalog")?;
    let length = query.len();
    query[length - 2] = 99;
    assert!(HeadQuery::from_canonical_bytes(&query).is_err());
    assert!(HeadQuery::from_canonical_bytes(&vec![0; MAX_HEAD_QUERY_BYTES + 1]).is_err());
    assert!(HeadWitness::from_canonical_bytes(&vec![0; MAX_HEAD_WITNESS_BYTES + 1]).is_err());
    let mut witness = fixture("signed-witness-chat")?;
    let end = witness.len() - 1;
    witness[end] ^= 1;
    assert!(SignedHeadWitness::from_canonical_bytes(&witness).is_err());
    Ok(())
}
#[test]
fn fresh_head_transport_never_expands_runner_methods_to_device_or_store_services() {
    for method in ["NextHeadProbe", "ReplyHeadProbe"] {
        assert_eq!(
            RunnerMethod::from_rpc("nocterm.hub.v1.CloudService", method).map(RunnerMethod::name),
            Ok(method)
        );
    }
    for method in ["ProbeHead", "CreateRunnerGrant", "RedeemRunnerGrant"] {
        assert!(RunnerMethod::from_rpc("nocterm.hub.v1.CloudService", method).is_err());
    }
    assert!(RunnerMethod::from_rpc("nocterm.hub.v1.StoreService", "NextHeadProbe").is_err());
}
