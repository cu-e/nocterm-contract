//! Cloud chats on the web panel's browser device, over `nocterm-cloud-device`.
//!
//! The page drives the network; everything that needs a key or decides trust happens here:
//! - hub trust: a `cloud-hub-trust` object opens into a [`WebHubTrust`] that says whether it was
//!   made for this hub and account; the page lists the matches (none: Cloud is set up on a
//!   native device first; several: the person chooses by origin);
//! - [`WebCloud::accept`] checks the hub's capability proof against that pin and keeps the
//!   account scope, the verified features, the trusted runner registry and every head a runner
//!   witnessed to a probe of this page;
//! - head probes ([`WebProbe`]) and commands ([`chat::WebCommand`]) are built here, signed by the
//!   page with the device's non-extractable WebCrypto key over `signingBytes()`, and sealed here
//!   after the signature verifies under the device key the bytes name;
//! - a chat ([`chat::WebChat`]) verifies its replay frames against a witnessed head, opens the
//!   chat key from its wrapped material for each record and drops it again, and reduces the
//!   events into a transcript the page reads as JSON;
//! - a new chat ([`create::WebNewChat`]) makes the chat key, its wrapped material and its sealed
//!   grant.
//!
//! The account key, the account key pair, collection keys and chat keys never cross into
//! JavaScript; the page receives identifiers, sealed bytes, public display data and JSON.
use nocterm_cloud_device::{
    CloudDeviceError, DeviceIdentity,
    probe::{ProbeTarget, SealedHeadProbe, UnsignedHeadProbe},
    records::{
        CHAT_GRANT_KIND, CHAT_MATERIAL_KIND, ChatGrantRecord, ChatMaterialRecord, HubTrustRecord,
        RunnerRegistry, StoredObject, TrustedRunner,
    },
    trust::{HubCapabilities, TrustedHub},
};
use nocterm_hub_model::cloud::head::{ChatHead, HeadValue};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

use crate::{WebAccount, WebCollectionKey};

pub mod chat;
pub mod create;
mod json;

/// The most witnessed chat heads one page keeps (16 runners with large catalogs).
const MAX_HEADS: usize = 4096;

/// Why a Cloud operation was refused at the boundary. The message starts with a stable code in
/// brackets (`[unsupported] …`), which the page maps to what it tells the person.
#[derive(Debug, thiserror::Error)]
pub enum WebCloudError {
    #[error("[{code}] {0}", code = device_code(.0))]
    Device(#[from] CloudDeviceError),
    #[error("[argument] invalid {0}")]
    Argument(&'static str),
    #[error("[no_registry] the account's trusted runners were not opened")]
    NoRegistry,
    #[error("[no_runner] the runner is not among the account's trusted runners")]
    NoRunner,
    #[error("[no_head] no runner witnessed this chat's head to a fresh probe")]
    NoHead,
    #[error("[no_run] the transcript has no such run")]
    NoRun,
    #[error("[no_model] the chat has no model to prompt with")]
    NoModel,
    #[error("[used] this value was already sealed or consumed")]
    Used,
    #[error("[witness] the runner witnessed something this probe did not ask")]
    Witness,
}

/// The stable code of a device refusal.
fn device_code(error: &CloudDeviceError) -> &'static str {
    use CloudDeviceError as E;
    match error {
        E::Capacity => "capacity",
        E::Format => "format",
        E::Binding => "binding",
        E::Deleted => "deleted",
        E::ObjectVersion(_) => "object_version",
        E::Unsupported => "unsupported",
        E::Signature(_) => "signature",
        E::SessionTooShort => "session_too_short",
        E::Time => "time",
        E::Policy => "policy",
        E::ReplayOrder => "replay_order",
        E::ReplaySource => "replay_source",
        E::ReplayIntegrity => "replay_integrity",
        E::Withheld => "withheld",
        E::SnapshotRequired => "snapshot_required",
        E::NoApproval => "no_approval",
        E::Capability(_) => "capability",
        E::Probe(_) | E::HeadCrypto(_) => "probe",
        E::Open(_) | E::Material(_) => "open",
        _ => "refused",
    }
}

pub(crate) type CloudResult<T> = Result<T, WebCloudError>;

/// A refusal becomes text only here, at the JavaScript boundary.
pub(crate) fn js<T>(result: CloudResult<T>) -> Result<T, JsError> {
    result.map_err(JsError::from)
}

pub(crate) fn array<const N: usize>(bytes: &[u8], what: &'static str) -> CloudResult<[u8; N]> {
    bytes.try_into().map_err(|_| WebCloudError::Argument(what))
}

/// A JavaScript time in milliseconds as the contract's signed milliseconds.
pub(crate) fn millis(value: f64, what: &'static str) -> CloudResult<i64> {
    if !value.is_finite() || value.fract() != 0.0 || value.abs() > 9.007_199_254_740_991e15 {
        return Err(WebCloudError::Argument(what));
    }
    // An integral value within ±2^53 converts exactly.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "checked integral and in range"
    )]
    Ok(value as i64)
}

fn hex_id<const N: usize>(text: &str, what: &'static str) -> CloudResult<[u8; N]> {
    let bytes = hex::decode(text).map_err(|_| WebCloudError::Argument(what))?;
    array(&bytes, what)
}

/// One `StoreService.GetObject` row, as the page received it.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebStoredObject {
    collection_id: String,
    object_id: String,
    kind: String,
    version: u64,
    deleted: bool,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl WebStoredObject {
    #[wasm_bindgen(constructor)]
    pub fn new(
        collection_id: String,
        object_id: String,
        kind: String,
        version: u64,
        deleted: bool,
        ciphertext: Vec<u8>,
    ) -> WebStoredObject {
        Self {
            collection_id,
            object_id,
            kind,
            version,
            deleted,
            ciphertext,
        }
    }
}

impl WebStoredObject {
    pub(crate) fn view(&self) -> StoredObject<'_> {
        StoredObject {
            collection_id: &self.collection_id,
            object_id: &self.object_id,
            kind: &self.kind,
            version: self.version,
            deleted: self.deleted,
            ciphertext: &self.ciphertext,
        }
    }
}

/// The signed-in device as commands and probes name it: the hub's device id, the public half of
/// the WebCrypto key, the current access token (only its digest is kept) and when the session
/// ends (its refresh expiry), which caps every deadline the device signs.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebDevice {
    identity: DeviceIdentity,
}

#[wasm_bindgen]
impl WebDevice {
    #[wasm_bindgen(constructor)]
    pub fn new(
        device_id: &str,
        signing_key: &[u8],
        access_token: &str,
        session_expires_at_ms: f64,
    ) -> Result<WebDevice, JsError> {
        js(Self::identified(
            device_id,
            signing_key,
            access_token,
            session_expires_at_ms,
        ))
    }
}

impl WebDevice {
    pub(crate) fn identified(
        device_id: &str,
        signing_key: &[u8],
        access_token: &str,
        session_expires_at_ms: f64,
    ) -> CloudResult<Self> {
        Ok(Self {
            identity: DeviceIdentity::new(
                device_id,
                array(signing_key, "device signing key")?,
                access_token,
                millis(session_expires_at_ms, "session expiry")?,
            )?,
        })
    }
    pub(crate) fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }
}

/// One opened `cloud-hub-trust` record. Its origin is display data; `matches` says whether it
/// was made for the hub and account the page signed in to.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebHubTrust {
    record: HubTrustRecord,
    matches: bool,
}

#[wasm_bindgen]
impl WebHubTrust {
    /// The native `host:port` the record was created for.
    pub fn origin(&self) -> String {
        self.record.origin().to_owned()
    }
    /// True when the record names this raw hub id, account and account key.
    pub fn matches(&self) -> bool {
        self.matches
    }
}

#[wasm_bindgen]
impl WebCollectionKey {
    /// Opens `hub-authority-v1` of a `cloud-hub-trust` collection for the hub `raw_hub`.
    #[wasm_bindgen(js_name = openHubTrust)]
    pub fn open_hub_trust(
        &self,
        account: &WebAccount,
        raw_hub: &str,
        object: &WebStoredObject,
    ) -> Result<WebHubTrust, JsError> {
        js(self.hub_trust(account, raw_hub, object))
    }
}

impl WebCollectionKey {
    pub(crate) fn hub_trust(
        &self,
        account: &WebAccount,
        raw_hub: &str,
        object: &WebStoredObject,
    ) -> CloudResult<WebHubTrust> {
        let view = object.view();
        if view.collection_id != self.collection_id {
            return Err(CloudDeviceError::Binding.into());
        }
        let record = HubTrustRecord::open(&self.key, &view)?;
        let matches = record.matches(raw_hub, &account.account_id, &account_public(account));
        Ok(WebHubTrust { record, matches })
    }
}

pub(crate) fn account_public(account: &WebAccount) -> [u8; 32] {
    account.pair.public_key().to_bytes()
}

/// A head a runner witnessed to one of this page's probes.
#[derive(Debug)]
struct Witnessed {
    runner: [u8; 16],
    head: ChatHead,
}

/// The trusted hub of the signed-in account: scope, verified features, trusted runners and the
/// heads runners witnessed. It holds no secret.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebCloud {
    hub: TrustedHub,
    capabilities: HubCapabilities,
    registry: Option<RunnerRegistry>,
    heads: Vec<Witnessed>,
}

#[wasm_bindgen]
impl WebCloud {
    /// Accepts `trust` for the hub `raw_hub` once its `CloudService.Capabilities` answer to
    /// `nonce` (16 random bytes the page sent) verifies under the pinned authority.
    pub fn accept(
        account: &WebAccount,
        trust: &WebHubTrust,
        raw_hub: &str,
        claim: &[u8],
        signature: &[u8],
        nonce: &[u8],
        now_ms: f64,
    ) -> Result<WebCloud, JsError> {
        js(Self::accepted(
            account,
            trust,
            raw_hub,
            (claim, signature, nonce),
            now_ms,
        ))
    }

    /// The hub answers head probes, so chats can be read.
    #[wasm_bindgen(js_name = canRead)]
    pub fn can_read(&self) -> bool {
        self.capabilities.require_reading().is_ok()
    }
    /// The hub accepts unary publications, so the browser can send commands.
    #[wasm_bindgen(js_name = canCommand)]
    pub fn can_command(&self) -> bool {
        self.capabilities.require_commands().is_ok()
    }
    /// The hub also relays chat key grants, so the browser can create chats.
    #[wasm_bindgen(js_name = canCreate)]
    pub fn can_create(&self) -> bool {
        self.can_command() && self.capabilities.chat_key_material()
    }
    /// The personal collection of the trusted runner registry.
    #[wasm_bindgen(js_name = registryCollectionId)]
    pub fn registry_collection_id(&self) -> Result<String, JsError> {
        js(RunnerRegistry::collection_id(self.hub.scope()).map_err(Into::into))
    }
    /// The personal collection of wrapped chat keys (`cloud-chat-material`).
    #[wasm_bindgen(js_name = materialCollectionId)]
    pub fn material_collection_id(&self) -> Result<String, JsError> {
        js(ChatMaterialRecord::collection_id(self.hub.scope()).map_err(Into::into))
    }
    /// The personal collection of stored chat key grants (`cloud-chat-grant`).
    #[wasm_bindgen(js_name = grantCollectionId)]
    pub fn grant_collection_id(&self) -> Result<String, JsError> {
        js(ChatGrantRecord::collection_id(self.hub.scope()).map_err(Into::into))
    }
    /// The kind of the wrapped chat key collection, as `CreateCollection` names it.
    #[wasm_bindgen(js_name = materialKind)]
    pub fn material_kind() -> String {
        CHAT_MATERIAL_KIND.to_owned()
    }
    /// The kind of the stored chat key grant collection.
    #[wasm_bindgen(js_name = grantKind)]
    pub fn grant_kind() -> String {
        CHAT_GRANT_KIND.to_owned()
    }

    /// Opens `trusted-runners-v1` and keeps it; returns the runners as JSON
    /// (`[{"runnerId", "keyEpoch", "label"}]`, ids in lowercase hex).
    #[wasm_bindgen(js_name = openRegistry)]
    pub fn open_registry(
        &mut self,
        key: &WebCollectionKey,
        object: &WebStoredObject,
    ) -> Result<String, JsError> {
        js(self.registry_from(key, object))
    }

    /// Starts a head probe of a trusted runner. `target` is JSON: `{"catalog": null}` for the
    /// first catalog page, `{"catalog": <next>}` with the `next` value of a page, or
    /// `{"chat": {"chatId": <hex>, "keyEpoch": <n>}}`.
    #[wasm_bindgen(js_name = prepareProbe)]
    pub fn prepare_probe(
        &self,
        account: &WebAccount,
        device: &WebDevice,
        runner_id: &[u8],
        target: &str,
        now_ms: f64,
    ) -> Result<WebProbe, JsError> {
        js(self.probe(account, device, runner_id, target, now_ms, None))
    }

    /// Opens a runner's answer to `probe` and keeps the heads it witnessed. Returns JSON:
    /// `{"kind":"catalog","chats":[…],"hasMore","next","totalChats"}` or
    /// `{"kind":"chat","chat":{…}}`.
    #[wasm_bindgen(js_name = openProbeReply)]
    pub fn open_probe_reply(
        &mut self,
        account: &WebAccount,
        probe: &WebProbe,
        reply_scope: &[u8],
        reply_probe_id: &[u8],
        ciphertext: &[u8],
        now_ms: f64,
    ) -> Result<String, JsError> {
        js(self.reply(
            account,
            probe,
            (reply_scope, reply_probe_id, ciphertext),
            now_ms,
        ))
    }
}

impl WebCloud {
    pub(crate) fn accepted(
        account: &WebAccount,
        trust: &WebHubTrust,
        raw_hub: &str,
        (claim, signature, nonce): (&[u8], &[u8], &[u8]),
        now_ms: f64,
    ) -> CloudResult<Self> {
        let hub = TrustedHub::new(
            trust.record.clone(),
            raw_hub,
            &account.account_id,
            &account_public(account),
        )?;
        let capabilities = hub.verify_capabilities(
            claim,
            signature,
            &array(nonce, "nonce")?,
            millis(now_ms, "time")?,
        )?;
        Ok(Self {
            hub,
            capabilities,
            registry: None,
            heads: Vec::new(),
        })
    }
    pub(crate) fn hub(&self) -> &TrustedHub {
        &self.hub
    }
    pub(crate) fn capabilities(&self) -> &HubCapabilities {
        &self.capabilities
    }
    pub(crate) fn runner(&self, runner_id: &[u8]) -> CloudResult<&TrustedRunner> {
        let registry = self.registry.as_ref().ok_or(WebCloudError::NoRegistry)?;
        registry
            .runner(&array(runner_id, "runner id")?)
            .ok_or(WebCloudError::NoRunner)
    }
    /// The latest witnessed head of one chat generation of `runner`.
    pub(crate) fn head(
        &self,
        runner: [u8; 16],
        chat_id: [u8; 16],
        epoch: u64,
    ) -> Option<&ChatHead> {
        self.heads
            .iter()
            .find(|seen| seen.is(runner, chat_id, epoch))
            .map(|seen| &seen.head)
    }

    pub(crate) fn registry_from(
        &mut self,
        key: &WebCollectionKey,
        object: &WebStoredObject,
    ) -> CloudResult<String> {
        let view = object.view();
        if view.collection_id != key.collection_id {
            return Err(CloudDeviceError::Binding.into());
        }
        let registry = RunnerRegistry::open(&key.key, self.hub.scope(), &view)?;
        let runners: Vec<Value> = registry
            .runners()
            .iter()
            .map(|row| {
                json!({
                    "runnerId": hex::encode(row.runner().id),
                    "keyEpoch": row.runner().key_epoch,
                    "label": row.label(),
                })
            })
            .collect();
        self.registry = Some(registry);
        Ok(Value::Array(runners).to_string())
    }

    /// A probe with fresh nonces, or with `nonces` (fixtures only: a reused challenge is not a
    /// freshness proof).
    pub(crate) fn probe(
        &self,
        account: &WebAccount,
        device: &WebDevice,
        runner_id: &[u8],
        target: &str,
        now_ms: f64,
        nonces: Option<([u8; 16], [u8; 32])>,
    ) -> CloudResult<WebProbe> {
        let runner = self.runner(runner_id)?;
        let target = probe_target(target)?;
        let (scope, public, now) = (
            self.hub.scope(),
            account_public(account),
            millis(now_ms, "time")?,
        );
        let unsigned = match nonces {
            None => UnsignedHeadProbe::new(
                scope,
                public,
                runner,
                device.identity(),
                target.clone(),
                now,
            )?,
            Some(nonces) => UnsignedHeadProbe::with_nonces(
                scope,
                public,
                runner,
                device.identity(),
                target.clone(),
                now,
                nonces,
            )?,
        };
        Ok(WebProbe {
            runner: runner.runner().id,
            target,
            state: ProbeState::Unsigned(Box::new(unsigned)),
        })
    }

    pub(crate) fn reply(
        &mut self,
        account: &WebAccount,
        probe: &WebProbe,
        (scope, probe_id, ciphertext): (&[u8], &[u8], &[u8]),
        now_ms: f64,
    ) -> CloudResult<String> {
        let ProbeState::Sealed(sealed) = &probe.state else {
            return Err(WebCloudError::Used);
        };
        let value = sealed.open_reply(
            &account.pair,
            scope,
            probe_id,
            ciphertext,
            millis(now_ms, "time")?,
        )?;
        match (value, &probe.target) {
            (HeadValue::Catalog(page), ProbeTarget::Catalog(_)) => {
                let answer = json::catalog(&page);
                for head in page.chats {
                    self.witness(probe.runner, head);
                }
                Ok(answer.to_string())
            }
            (HeadValue::Chat(head), ProbeTarget::Chat { chat_id, key_epoch })
                if head.chat_id == *chat_id && head.chat_key_epoch == *key_epoch =>
            {
                let answer = json!({ "kind": "chat", "chat": json::head(&head) });
                self.witness(probe.runner, *head);
                Ok(answer.to_string())
            }
            _ => Err(WebCloudError::Witness),
        }
    }

    fn witness(&mut self, runner: [u8; 16], head: ChatHead) {
        self.heads
            .retain(|seen| !seen.is(runner, head.chat_id, head.chat_key_epoch));
        if self.heads.len() == MAX_HEADS {
            self.heads.remove(0);
        }
        self.heads.push(Witnessed { runner, head });
    }
}

impl Witnessed {
    fn is(&self, runner: [u8; 16], chat_id: [u8; 16], epoch: u64) -> bool {
        self.runner == runner && self.head.chat_id == chat_id && self.head.chat_key_epoch == epoch
    }
}

fn probe_target(text: &str) -> CloudResult<ProbeTarget> {
    let value: Value = serde_json::from_str(text).map_err(|_| WebCloudError::Argument("target"))?;
    if let Some(after) = value.get("catalog") {
        return Ok(ProbeTarget::Catalog(match after {
            Value::Null => None,
            cursor => Some(json::cursor(cursor).ok_or(WebCloudError::Argument("catalog cursor"))?),
        }));
    }
    let chat = value.get("chat").ok_or(WebCloudError::Argument("target"))?;
    Ok(ProbeTarget::Chat {
        chat_id: hex_id(
            chat.get("chatId")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "chat id",
        )?,
        key_epoch: chat
            .get("keyEpoch")
            .and_then(Value::as_u64)
            .ok_or(WebCloudError::Argument("key epoch"))?,
    })
}

#[derive(Debug)]
enum ProbeState {
    Unsigned(Box<UnsignedHeadProbe>),
    Sealed(Box<SealedHeadProbe>),
    Spent,
}

/// One head probe: `signingBytes()` for the device signature, `seal(signature)`, then the
/// `CloudHeadProbe` fields. It answers once, within its window.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebProbe {
    runner: [u8; 16],
    target: ProbeTarget,
    state: ProbeState,
}

#[wasm_bindgen]
impl WebProbe {
    /// The exact bytes the device signs (Ed25519).
    #[wasm_bindgen(js_name = signingBytes)]
    pub fn signing_bytes(&self) -> Result<Vec<u8>, JsError> {
        js(self.bytes())
    }
    /// Verifies the device signature and seals the query to the runner.
    pub fn seal(&mut self, account: &WebAccount, signature: &[u8]) -> Result<(), JsError> {
        js(self.sealed_with(account, signature))
    }
    /// `CloudHeadProbe.scope`.
    pub fn scope(&self) -> Result<Vec<u8>, JsError> {
        js(self.sealed().map(|probe| probe.scope().to_vec()))
    }
    /// `CloudHeadProbe.probe_id`.
    #[wasm_bindgen(js_name = probeId)]
    pub fn probe_id(&self) -> Result<Vec<u8>, JsError> {
        js(self.sealed().map(|probe| probe.probe_id().to_vec()))
    }
    /// `CloudHeadProbe.ciphertext`.
    pub fn ciphertext(&self) -> Result<Vec<u8>, JsError> {
        js(self.sealed().map(|probe| probe.ciphertext().to_vec()))
    }
    /// `CloudHeadProbe.expires_at_ms`; stop waiting for the answer at this time.
    #[wasm_bindgen(js_name = expiresAtMs)]
    pub fn expires_at_ms(&self) -> Result<f64, JsError> {
        #[allow(
            clippy::cast_precision_loss,
            reason = "a time in milliseconds fits 2^53"
        )]
        js(self.sealed().map(|probe| probe.expires_at_ms() as f64))
    }
}

impl WebProbe {
    pub(crate) fn bytes(&self) -> CloudResult<Vec<u8>> {
        match &self.state {
            ProbeState::Unsigned(probe) => Ok(probe.signing_bytes()?),
            _ => Err(WebCloudError::Used),
        }
    }
    pub(crate) fn sealed_with(
        &mut self,
        account: &WebAccount,
        signature: &[u8],
    ) -> CloudResult<()> {
        let ProbeState::Unsigned(probe) = std::mem::replace(&mut self.state, ProbeState::Spent)
        else {
            return Err(WebCloudError::Used);
        };
        self.state = ProbeState::Sealed(Box::new(probe.seal(&account.pair, signature)?));
        Ok(())
    }
    pub(crate) fn sealed(&self) -> CloudResult<&SealedHeadProbe> {
        match &self.state {
            ProbeState::Sealed(probe) => Ok(probe),
            _ => Err(WebCloudError::Used),
        }
    }
}

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
