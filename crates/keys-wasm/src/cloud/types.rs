//! The structured values that cross the JavaScript boundary of [`super::CloudDevice`], with
//! generated TypeScript declarations (tsify). Identifiers of chats are `ChatRef` text
//! (`<runner hex>-<chat hex>-<epoch>`), other ids lowercase hex, bytes `Uint8Array`, times and
//! counters numbers (milliseconds, at most 2^53).
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;

/// The signed-in device: the hub's device id, the public half of its WebCrypto Ed25519 key,
/// the current access token (only its digest is kept) and the refresh expiry.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInput {
    pub device_id: String,
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub signing_key: Vec<u8>,
    pub access_token: String,
    pub session_expires_at_ms: f64,
}

/// One step of a flow.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FlowStep {
    /// Perform `effect`, then `resolve(id, …)` (and `frame(id, …)` for replay and watch).
    Effect {
        id: u32,
        effect: WireEffect,
    },
    Output {
        output: FlowOutput,
    },
    /// Call `next` again after an answer, a frame, or once `untilMs` has passed.
    #[serde(rename_all = "camelCase")]
    Idle {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        until_ms: Option<f64>,
    },
    Done,
    Failed {
        error: WireError,
    },
}

/// A refusal: a stable code (`no_runner`, `withheld`, …) and a message for logs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi)]
pub struct WireError {
    pub code: String,
    pub message: String,
}

/// `CloudSelector`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireSelector {
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub runner_id: Vec<u8>,
    pub runner_key_epoch: u64,
    /// The chat stream; absent for the runner inbox and the directory.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    #[tsify(optional, type = "Uint8Array")]
    pub chat_id: Option<Vec<u8>>,
    /// True for the runner's chat directory (`CloudSelector.directory`, capability bit 256).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[tsify(optional)]
    pub directory: bool,
}

/// `CloudPublication` (the header of `PublishOne`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WirePublication {
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub publication_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub binding: Vec<u8>,
    pub total_bytes: u32,
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub ciphertext_sha256: Vec<u8>,
}

/// What the client performs. Each maps to one RPC (or the WebCrypto signature).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WireEffect {
    /// Ed25519 over `bytes` with the device key whose public half is `signingKey`; answer
    /// `{kind: "signature"}`.
    #[serde(rename_all = "camelCase")]
    Sign {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        bytes: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        signing_key: Vec<u8>,
    },
    /// `StoreService.ListCollections { kind: collectionKind }` (all pages); answer
    /// `collections`.
    #[serde(rename_all = "camelCase")]
    ListCollections { collection_kind: String },
    /// `StoreService.GetCollectionKey`; answer `collectionKey` or `failed: not_found`.
    #[serde(rename_all = "camelCase")]
    GetCollectionKey { collection_id: String },
    /// `StoreService.GetObject`; answer `object` or `failed: not_found`.
    #[serde(rename_all = "camelCase")]
    GetObject {
        collection_id: String,
        object_id: String,
    },
    /// `StoreService.PutObject`; answer `stored` or `failed: conflict`.
    #[serde(rename_all = "camelCase")]
    PutObject {
        collection_id: String,
        object_id: String,
        /// `PutObjectRequest.kind`.
        object_kind: String,
        expected_version: u64,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        ciphertext: Vec<u8>,
    },
    /// `StoreService.CreateCollection` (personal, this id); answer `done` or
    /// `failed: already_exists`.
    #[serde(rename_all = "camelCase")]
    CreateCollection {
        collection_id: String,
        /// `CreateCollectionRequest.kind`.
        collection_kind: String,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        wrapped_key: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        sealed_name: Vec<u8>,
    },
    /// `CloudService.Capabilities`; answer `capabilities`.
    Capabilities {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        nonce: Vec<u8>,
    },
    /// `CloudService.ProbeHead`; answer `probeReply`, or `failed: unavailable` once
    /// `expiresAtMs` passed without one.
    #[serde(rename_all = "camelCase")]
    Probe {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        scope: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        probe_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        ciphertext: Vec<u8>,
        expires_at_ms: f64,
    },
    /// `CloudService.Replay`; every `CloudReplayFrame` goes to `frame(id, …)`; a page end or
    /// gap completes it; a failed stream answers `failed`.
    #[serde(rename_all = "camelCase")]
    Replay {
        selector: WireSelector,
        after_cursor: u64,
        max_records: u32,
        max_bytes: u32,
    },
    /// `CloudService.Watch`; every `CloudHint` goes to `frame(id, {kind: "hint"})`; when the
    /// stream ends answer `failed: ended` (or the failure).
    #[serde(rename_all = "camelCase")]
    Watch {
        selector: WireSelector,
        after_cursor: u64,
    },
    /// `CloudService.PublishOne { header: publication, data }`; answer `receipt`. Send exactly
    /// these bytes.
    Publish {
        publication: WirePublication,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        data: Vec<u8>,
    },
    /// `AgentService.StartInstance`; answer `instance`.
    #[serde(rename_all = "camelCase")]
    StartInstance {
        agent_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[tsify(optional)]
        chat_id: Option<String>,
    },
    /// `AgentService.ListInstances` (all pages, every agent); answer `instances`.
    ListInstances,
    /// `CloudService.RunnerStatus`; answer `runnerStatus`.
    #[serde(rename_all = "camelCase")]
    RunnerStatus {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        runner_id: Vec<u8>,
    },
}

/// `StoreService` collection row.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireCollection {
    pub collection_id: String,
    pub kind: String,
    /// No organization.
    pub personal: bool,
    pub deleted: bool,
}

/// `StoreService.GetObject` result.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireObject {
    pub collection_id: String,
    pub object_id: String,
    pub kind: String,
    pub version: u64,
    pub deleted: bool,
    #[serde(with = "serde_bytes")]
    #[tsify(type = "Uint8Array")]
    pub ciphertext: Vec<u8>,
}

/// An agent seat (`Instance`); `state` is `provisioning`, `awaiting_enrolment`, `ready`,
/// `suspended`, `deleting`, `failed` or `unknown`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct WireInstance {
    pub instance_id: String,
    pub agent_id: String,
    /// The Cloud runner id in lowercase hex, once the host created it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub runner_id: Option<String>,
    pub state: String,
}

/// The answer to an effect.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum EffectInput {
    Signature {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        signature: Vec<u8>,
    },
    Collections {
        collections: Vec<WireCollection>,
    },
    /// `grantedBy` is absent (or empty) for a personal collection.
    #[serde(rename_all = "camelCase")]
    CollectionKey {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        wrapped_key: Vec<u8>,
        #[serde(default)]
        #[tsify(optional)]
        granted_by: Option<String>,
    },
    Object {
        object: WireObject,
    },
    Stored {
        version: u64,
    },
    Done,
    Capabilities {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        claim: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        signature: Vec<u8>,
    },
    #[serde(rename_all = "camelCase")]
    ProbeReply {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        scope: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        probe_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        ciphertext: Vec<u8>,
    },
    /// `CloudDeliveryReceipt`.
    #[serde(rename_all = "camelCase")]
    Receipt {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        publication_id: Vec<u8>,
        cursor: u64,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        ciphertext_sha256: Vec<u8>,
    },
    Instance {
        instance: WireInstance,
    },
    Instances {
        instances: Vec<WireInstance>,
    },
    #[serde(rename_all = "camelCase")]
    RunnerStatus {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        signed_status: Vec<u8>,
    },
    /// `failure`: `not_found`, `already_exists`, `conflict` (a lost compare-and-set),
    /// `unavailable` (not sent, or no answer in time), `unknown` (sent, outcome unknown),
    /// `refused` (any other refusal) or `ended` (a watch closed without error).
    Failed {
        failure: String,
    },
}

/// One `CloudReplayFrame` or `CloudHint`.
#[derive(Clone, Debug, Serialize, Deserialize, Tsify)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StreamFrame {
    #[serde(rename_all = "camelCase")]
    Header {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        publication_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        binding: Vec<u8>,
        total_bytes: u32,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        ciphertext_sha256: Vec<u8>,
        cursor: u64,
        origin_account_id: String,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        origin_signing_key: Vec<u8>,
        /// `issuer.runnerId`; absent when the origin names a device.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
        #[tsify(optional, type = "Uint8Array")]
        origin_runner_id: Option<Vec<u8>>,
    },
    Data {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        bytes: Vec<u8>,
    },
    #[serde(rename_all = "camelCase")]
    End {
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        publication_id: Vec<u8>,
    },
    #[serde(rename_all = "camelCase")]
    PageEnd { through_cursor: u64, has_more: bool },
    #[serde(rename_all = "camelCase")]
    Gap {
        retained_from: u64,
        #[serde(with = "serde_bytes")]
        #[tsify(type = "Uint8Array")]
        snapshot_publication_id: Vec<u8>,
    },
    #[serde(rename_all = "camelCase")]
    Hint { head_cursor: u64 },
}

pub use super::listing::{ListOptions, WireChat, WireServer, WireSummary};
pub use super::ssh::{
    BindOptions, SshServerInput, WireBinding, WireBoundServer, WireSsh, WireSshRequest,
    WireSshTrust,
};
pub use super::view::{
    ChatActionInput, FlowOutput, ModelInput, NewChatHost, RunnerInfo, WireApproval, WireDelta,
    WireFreshness, WirePending, WireRow, WireRun, WireSession, WireTool, WireUsage,
};
