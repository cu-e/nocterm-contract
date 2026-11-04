//! The runner's chat directory in the recorded session (ADR 0008): one signed and sealed
//! summary of the chat at the recorded head, one later summary that arrives by Watch with the
//! later record, and one after the chat's SSH binding that names its servers.
use nocterm_cloud_device::records::ChatSelector;
use nocterm_hub_model::cloud::{
    CloudTextId,
    head::HeadRecordAnchor,
    relay::RelayBinding,
    summary::{
        BoundServer, ChatState, ChatSummary, SUMMARY_FEATURE_SSH_BINDING, SummaryContext,
        SummaryHead, SummaryHost, SummaryModel, title_from_prompt,
    },
};
use nocterm_keys::{
    PublicKey,
    cloud::{RunnerEncryptionKey, RunnerSigningKey, seal_summary},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    ACCOUNT, NOW, PROMPT, RUNNER_ENCRYPTION_SEED, RUNNER_ID, RUNNER_PROOF, RUNNER_SIGNING_SEED,
};
use crate::WebAccount;

/// The managed agent whose seat serves the recorded chat (the panel's fixture hub lists it).
pub(super) const AGENT_ID: &str = "ag-1";

/// The summary at revision `revision` of a chat whose newest record is `head` (the event at
/// control revision `head.position.sequence`, at `last_activity_ms`).
fn summary(head: &HeadRecordAnchor, last_activity_ms: i64) -> ChatSummary {
    ChatSummary {
        head: Some(SummaryHead {
            sequence: head.position.sequence,
            ciphertext_digest: head.ciphertext_digest,
        }),
        control_revision: head.position.sequence,
        created_at_ms: NOW - 600_000 + 1_000,
        last_activity_ms,
        title: title_from_prompt(PROMPT),
        host: SummaryHost::Managed {
            agent_id: CloudTextId::new(AGENT_ID).unwrap(),
        },
        model: Some(SummaryModel {
            provider: CloudTextId::new("managed").unwrap(),
            model: CloudTextId::new("gpt-5-mini").unwrap(),
        }),
        state: ChatState::WaitingApproval,
        pending_approvals: 1,
        servers: Vec::new(),
        features: 0,
    }
}

/// The directory record of `summary` at `revision`, at directory cursor `cursor`.
fn record(
    selector: &ChatSelector,
    account: &WebAccount,
    revision: u64,
    cursor: u64,
    summary: ChatSummary,
) -> Value {
    let context = SummaryContext::new(selector.coordinate().unwrap(), revision).unwrap();
    let signed = RunnerSigningKey::from_seed(&RUNNER_SIGNING_SEED)
        .attest_summary(context.clone(), summary)
        .unwrap();
    let account_key = PublicKey::from_bytes(&account.pair.public_key().to_bytes()).unwrap();
    let sealed = seal_summary(
        &RunnerEncryptionKey::from_seed(&RUNNER_ENCRYPTION_SEED),
        &account_key,
        &signed,
    )
    .unwrap();
    let digest: [u8; 32] = Sha256::digest(&sealed).into();
    json!({
        "publicationId": hex::encode(context.publication_id().unwrap()),
        "binding": hex::encode(RelayBinding::summary(context).canonical_bytes().unwrap()),
        "totalBytes": sealed.len(),
        "ciphertextSha256": hex::encode(digest),
        "cursor": cursor,
        "originAccountId": ACCOUNT,
        "originSigningKey": hex::encode(RUNNER_PROOF),
        "originRunnerId": hex::encode(RUNNER_ID),
        "data": hex::encode(&sealed),
    })
}

/// The directory records: revision 1 at the recorded head, and revision 2 after the later
/// record (`later_at_ms`), which arrives by Watch.
pub(super) fn records(
    selector: &ChatSelector,
    account: &WebAccount,
    head: &HeadRecordAnchor,
    later: &HeadRecordAnchor,
    later_at_ms: i64,
) -> (Value, Value) {
    let first = record(
        selector,
        account,
        1,
        1,
        summary(head, NOW - 600_000 + 6_000),
    );
    let second = record(selector, account, 2, 2, summary(later, later_at_ms));
    (first, second)
}

/// The directory record at revision 3 (cursor 3) of the chat whose newest record is `head` (its
/// SSH access, at `at_ms`): it names the bound `servers` and the SSH binding feature.
pub(super) fn bound(
    selector: &ChatSelector,
    account: &WebAccount,
    head: &HeadRecordAnchor,
    at_ms: i64,
    servers: Vec<BoundServer>,
) -> Value {
    let summary = ChatSummary {
        servers,
        features: SUMMARY_FEATURE_SSH_BINDING,
        ..summary(head, at_ms)
    };
    record(selector, account, 3, 3, summary)
}
