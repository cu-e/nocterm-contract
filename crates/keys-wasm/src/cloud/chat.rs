//! One open chat: verified replay into its transcript, and the commands it sends.
use nocterm_cloud_device::{
    CloudDeviceError,
    command::{CommandAction, Publication, SealedCommand, UnsignedCommand},
    policy::{MANAGED_PROVIDER, PromptPolicy},
    records::{ChatMaterialRecord, ChatSelector},
    replay::{ChatReplay, DeliveredOrigin, DeliveredRecord, PageEnd},
    transcript::Transcript,
};
use nocterm_hub_model::cloud::payload::ApprovalChoice;
use serde_json::Value;
use wasm_bindgen::prelude::*;

use super::{
    CloudResult, WebCloud, WebCloudError, WebDevice, WebStoredObject, account_public, hex_id, js,
    json, millis,
};
use crate::{WebAccount, WebCollectionKey};

/// A replay in progress: its verifier and the transcript it rebuilds from the start.
#[derive(Debug)]
struct Replaying {
    verifier: ChatReplay,
    transcript: Transcript,
}

/// One chat generation of a trusted runner, with its wrapped chat key. The transcript the page
/// reads is the last one a complete replay verified; a replay in progress builds the next one.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebChat {
    material: ChatMaterialRecord,
    transcript: Transcript,
    replay: Option<Replaying>,
}

#[wasm_bindgen]
impl WebCloud {
    /// The object id of a chat generation in the material and grant collections.
    #[wasm_bindgen(js_name = chatObjectId)]
    pub fn chat_object_id(
        &self,
        runner_id: &[u8],
        chat_id: &str,
        key_epoch: u64,
    ) -> Result<String, JsError> {
        js(self
            .selector(runner_id, chat_id, key_epoch)
            .and_then(|selector| Ok(selector.object_id()?)))
    }

    /// Opens a chat from its `cloud-chat-material` object (`GetObject` at
    /// [`Self::chat_object_id`] in [`Self::material_collection_id`]); the wrapped key must open
    /// under the account key.
    #[wasm_bindgen(js_name = openChat)]
    pub fn open_chat(
        &self,
        account: &WebAccount,
        key: &WebCollectionKey,
        runner_id: &[u8],
        chat_id: &str,
        key_epoch: u64,
        object: &WebStoredObject,
    ) -> Result<WebChat, JsError> {
        js(self.chat(account, key, (runner_id, chat_id, key_epoch), object))
    }
}

impl WebCloud {
    pub(crate) fn chat(
        &self,
        account: &WebAccount,
        key: &WebCollectionKey,
        (runner_id, chat_id, key_epoch): (&[u8], &str, u64),
        object: &WebStoredObject,
    ) -> CloudResult<WebChat> {
        let selector = self.selector(runner_id, chat_id, key_epoch)?;
        let material =
            ChatMaterialRecord::open(&key.key, selector, &object.view(), &account.account)?;
        Ok(WebChat::new(material))
    }
    pub(crate) fn selector(
        &self,
        runner_id: &[u8],
        chat_id: &str,
        key_epoch: u64,
    ) -> CloudResult<ChatSelector> {
        let runner = self.runner(runner_id)?;
        Ok(ChatSelector::new(
            self.hub().scope().clone(),
            runner.runner(),
            hex_id(chat_id, "chat id")?,
            key_epoch,
            runner.pins(),
        )?)
    }
}

#[wasm_bindgen]
impl WebChat {
    /// The chat id in lowercase hex (`StartInstance.chat_id`).
    #[wasm_bindgen(js_name = chatId)]
    pub fn chat_id(&self) -> String {
        hex::encode(self.selector().chat_id())
    }
    #[wasm_bindgen(js_name = keyEpoch)]
    pub fn key_epoch(&self) -> u64 {
        self.selector().key_epoch()
    }
    /// `CloudSelector.runner_id`.
    #[wasm_bindgen(js_name = runnerId)]
    pub fn runner_id(&self) -> Vec<u8> {
        self.selector().runner().id.to_vec()
    }
    /// `CloudSelector.runner_key_epoch`.
    #[wasm_bindgen(js_name = runnerKeyEpoch)]
    pub fn runner_key_epoch(&self) -> u64 {
        self.selector().runner().key_epoch
    }
    /// `CloudSelector.chat_id`.
    #[wasm_bindgen(js_name = chatIdBytes)]
    pub fn chat_id_bytes(&self) -> Vec<u8> {
        self.selector().chat_id().to_vec()
    }

    /// Starts verifying a replay from cursor 0 against the latest head a runner witnessed for
    /// this chat (probe it first). Returns `Replay.after_cursor`.
    #[wasm_bindgen(js_name = beginReplay)]
    pub fn begin_replay(&mut self, cloud: &WebCloud) -> Result<u64, JsError> {
        js(self.begin(cloud))
    }
    /// `Replay.max_records`.
    #[wasm_bindgen(js_name = maxPageRecords)]
    pub fn max_page_records() -> u32 {
        ChatReplay::max_page_records()
    }
    /// The next `Replay.after_cursor`.
    pub fn cursor(&self) -> Result<u64, JsError> {
        js(self
            .replay
            .as_ref()
            .map(|replay| replay.verifier.cursor())
            .ok_or(WebCloudError::Used))
    }

    /// A `CloudDeliveredRecord` header frame. `origin_runner_id` is `issuer.runner_id`, absent
    /// when the origin names a device.
    #[wasm_bindgen(js_name = recordHeader)]
    #[allow(
        clippy::too_many_arguments,
        clippy::needless_pass_by_value,
        reason = "the frame's fields as wasm-bindgen passes them"
    )]
    pub fn record_header(
        &mut self,
        publication_id: &[u8],
        binding: &[u8],
        total_bytes: u32,
        ciphertext_sha256: &[u8],
        cursor: u64,
        origin_account_id: &str,
        origin_signing_key: &[u8],
        origin_runner_id: Option<Vec<u8>>,
    ) -> Result<(), JsError> {
        let header = DeliveredRecord {
            publication_id,
            binding,
            total_bytes,
            ciphertext_sha256,
            cursor,
            origin: DeliveredOrigin {
                account_id: origin_account_id,
                signing_key: origin_signing_key,
                runner_id: origin_runner_id.as_deref(),
            },
        };
        js(self.header(&header))
    }
    /// A data frame of the current record.
    #[wasm_bindgen(js_name = recordData)]
    pub fn record_data(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        js(self.data(bytes))
    }
    /// The end of the current record: opens the chat key for this record only, verifies the
    /// record under the pinned runner and applies it.
    #[wasm_bindgen(js_name = recordEnd)]
    pub fn record_end(
        &mut self,
        account: &WebAccount,
        publication_id: &[u8],
    ) -> Result<(), JsError> {
        js(self.end(account, publication_id))
    }
    /// The end of a page: `false` asks for the next page from [`Self::cursor`]; `true` means the
    /// replay reached the witnessed head and its transcript is now the chat's.
    #[wasm_bindgen(js_name = pageEnd)]
    pub fn page_end(&mut self, through_cursor: u64, has_more: bool) -> Result<bool, JsError> {
        js(self.page(through_cursor, has_more))
    }
    /// A gap frame: replay again from the returned cursor with `max_records = 1` to fetch the
    /// retained snapshot.
    pub fn gap(
        &mut self,
        retained_from: u64,
        snapshot_publication_id: &[u8],
    ) -> Result<u64, JsError> {
        js(self.gap_at(retained_from, snapshot_publication_id))
    }
    /// Drops a replay that will not finish (a failed request); the transcript stays as it was.
    #[wasm_bindgen(js_name = abandonReplay)]
    pub fn abandon_replay(&mut self) {
        self.replay = None;
    }

    /// The verified transcript as JSON (rows, runs, the active run, pending approvals, control
    /// revision, deleted and omitted-history flags).
    pub fn transcript(&self) -> String {
        self.transcript_json().to_string()
    }

    /// Starts a command. `action` is JSON:
    /// `{"kind":"prompt","text":…,"model"?:{"provider":…,"model":…}}` (without a model, the
    /// latest run's), `{"kind":"stop","run":<hex>}`, `{"kind":"allow","run":<hex>}` (the
    /// inference grant of a run this device prompted, with that run's model) or
    /// `{"kind":"answer","intent":<hex>,"choice":"approve"|"deny"}`.
    #[wasm_bindgen(js_name = prepareCommand)]
    pub fn prepare_command(
        &self,
        account: &WebAccount,
        device: &WebDevice,
        action: &str,
        now_ms: f64,
    ) -> Result<WebCommand, JsError> {
        js(self.command(account, device, action, now_ms))
    }
}

impl WebChat {
    pub(crate) fn new(material: ChatMaterialRecord) -> Self {
        Self {
            material,
            transcript: Transcript::new(),
            replay: None,
        }
    }
    fn selector(&self) -> &ChatSelector {
        self.material.selector()
    }
    /// Runs one replay step; any refusal ends the replay.
    fn step<T>(&mut self, apply: impl FnOnce(&mut Replaying) -> CloudResult<T>) -> CloudResult<T> {
        let replay = self.replay.as_mut().ok_or(WebCloudError::Used)?;
        apply(replay).inspect_err(|_| self.replay = None)
    }
    pub(crate) fn begin(&mut self, cloud: &WebCloud) -> CloudResult<u64> {
        let selector = self.selector();
        let head = cloud
            .head(
                selector.runner().id,
                selector.chat_id(),
                selector.key_epoch(),
            )
            .ok_or(WebCloudError::NoHead)?
            .clone();
        let verifier = ChatReplay::new(selector, head, cloud.capabilities())?;
        let cursor = verifier.cursor();
        self.replay = Some(Replaying {
            verifier,
            transcript: Transcript::new(),
        });
        Ok(cursor)
    }
    pub(crate) fn header(&mut self, header: &DeliveredRecord<'_>) -> CloudResult<()> {
        self.step(|replay| Ok(replay.verifier.record_header(header)?))
    }
    pub(crate) fn data(&mut self, bytes: &[u8]) -> CloudResult<()> {
        self.step(|replay| Ok(replay.verifier.record_data(bytes)?))
    }
    pub(crate) fn end(&mut self, account: &WebAccount, publication_id: &[u8]) -> CloudResult<()> {
        let key = self
            .material
            .open_key(&account.account)
            .inspect_err(|_| self.replay = None)?;
        self.step(|replay| {
            replay
                .verifier
                .record_end(publication_id, &key, &mut replay.transcript)?;
            Ok(())
        })
    }
    pub(crate) fn page(&mut self, through_cursor: u64, has_more: bool) -> CloudResult<bool> {
        let end = self.step(|replay| Ok(replay.verifier.page_end(through_cursor, has_more)?))?;
        if end == PageEnd::Complete
            && let Some(replay) = self.replay.take()
        {
            self.transcript = replay.transcript;
            return Ok(true);
        }
        Ok(false)
    }
    pub(crate) fn gap_at(&mut self, retained_from: u64, snapshot: &[u8]) -> CloudResult<u64> {
        self.step(|replay| Ok(replay.verifier.gap(retained_from, snapshot)?.after_cursor))
    }
    pub(crate) fn transcript_json(&self) -> Value {
        json::transcript(&self.transcript)
    }

    pub(crate) fn command(
        &self,
        account: &WebAccount,
        device: &WebDevice,
        action: &str,
        now_ms: f64,
    ) -> CloudResult<WebCommand> {
        let value: Value =
            serde_json::from_str(action).map_err(|_| WebCloudError::Argument("command"))?;
        let text = |name: &str| value.get(name).and_then(Value::as_str);
        let run = || -> CloudResult<_> {
            let id: [u8; 16] = hex_id(text("run").unwrap_or_default(), "run")?;
            self.transcript
                .runs()
                .iter()
                .find(|state| state.run.id == id)
                .ok_or(WebCloudError::NoRun)
        };
        let policy;
        let action = match text("kind") {
            Some("prompt") => {
                policy = self.prompt_policy(value.get("model"))?;
                CommandAction::Prompt {
                    policy: &policy,
                    text: text("text").ok_or(WebCloudError::Argument("prompt text"))?,
                }
            }
            Some("stop") => CommandAction::Stop { run: run()?.run },
            Some("allow") => {
                let state = run()?;
                policy = PromptPolicy::runner_default(state.model.clone())?;
                CommandAction::Allow {
                    policy: &policy,
                    run: state.run,
                }
            }
            Some("answer") => CommandAction::Answer {
                approval: self
                    .transcript
                    .approval(&hex_id(text("intent").unwrap_or_default(), "intent")?)
                    .ok_or(CloudDeviceError::NoApproval)?,
                choice: match text("choice") {
                    Some("approve") => ApprovalChoice::Approve,
                    Some("deny") => ApprovalChoice::Deny,
                    _ => return Err(WebCloudError::Argument("choice")),
                },
            },
            _ => return Err(WebCloudError::Argument("command kind")),
        };
        let unsigned = UnsignedCommand::prepare(
            self.selector(),
            account_public(account),
            device.identity(),
            action,
            self.transcript.control_revision(),
            millis(now_ms, "time")?,
        )?;
        Ok(WebCommand {
            unsigned: Some(unsigned),
        })
    }

    /// The model a prompt names: the one given, else the latest run's.
    fn prompt_policy(&self, model: Option<&Value>) -> CloudResult<PromptPolicy> {
        let field = |name: &str| {
            model
                .and_then(|value| value.get(name))
                .and_then(Value::as_str)
        };
        match (field("provider"), field("model")) {
            (Some(MANAGED_PROVIDER), Some(model)) => Ok(PromptPolicy::managed(model)?),
            (Some(provider), Some(model)) => Ok(PromptPolicy::own(provider, model)?),
            _ => {
                let last = self
                    .transcript
                    .runs()
                    .last()
                    .ok_or(WebCloudError::NoModel)?;
                Ok(PromptPolicy::runner_default(last.model.clone())?)
            }
        }
    }
}

/// A command waiting for the device signature.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebCommand {
    unsigned: Option<UnsignedCommand>,
}

#[wasm_bindgen]
impl WebCommand {
    /// The exact bytes the device signs (Ed25519).
    #[wasm_bindgen(js_name = signingBytes)]
    pub fn signing_bytes(&self) -> Result<Vec<u8>, JsError> {
        js(self.bytes())
    }
    /// The command id in lowercase hex.
    #[wasm_bindgen(js_name = commandId)]
    pub fn command_id(&self) -> Result<String, JsError> {
        js(self
            .unsigned
            .as_ref()
            .map(|command| hex::encode(command.command_id()))
            .ok_or(WebCloudError::Used))
    }
    /// Verifies the device signature and seals the command to the pinned runner.
    pub fn seal(
        &mut self,
        account: &WebAccount,
        cloud: &WebCloud,
        signature: &[u8],
    ) -> Result<WebPublication, JsError> {
        js(self.sealed(account, cloud, signature))
    }
}

impl WebCommand {
    pub(crate) fn bytes(&self) -> CloudResult<Vec<u8>> {
        Ok(self
            .unsigned
            .as_ref()
            .ok_or(WebCloudError::Used)?
            .signing_bytes()?)
    }
    pub(crate) fn sealed(
        &mut self,
        account: &WebAccount,
        cloud: &WebCloud,
        signature: &[u8],
    ) -> CloudResult<WebPublication> {
        let command = self.unsigned.take().ok_or(WebCloudError::Used)?;
        let sealed: SealedCommand = command.seal(&account.pair, signature, cloud.capabilities())?;
        Ok(WebPublication {
            publication: sealed.publication().clone(),
            accept_before_ms: Some(sealed.accept_before_ms()),
        })
    }
}

/// One relay publication (`CloudPublishOne { header, data }`). Resend exactly these bytes on
/// retry: the publication id makes delivery idempotent.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebPublication {
    publication: Publication,
    accept_before_ms: Option<i64>,
}

#[wasm_bindgen]
impl WebPublication {
    #[wasm_bindgen(js_name = publicationId)]
    pub fn publication_id(&self) -> Vec<u8> {
        self.publication.publication_id().to_vec()
    }
    pub fn binding(&self) -> Result<Vec<u8>, JsError> {
        js(self.publication.binding().map_err(Into::into))
    }
    #[wasm_bindgen(js_name = totalBytes)]
    pub fn total_bytes(&self) -> u32 {
        self.publication.total_bytes()
    }
    #[wasm_bindgen(js_name = ciphertextSha256)]
    pub fn ciphertext_sha256(&self) -> Vec<u8> {
        self.publication.ciphertext_sha256().to_vec()
    }
    /// `CloudPublishOne.data`.
    pub fn data(&self) -> Vec<u8> {
        self.publication.ciphertext().to_vec()
    }
    /// After this time the runner refuses a command; stop retrying. Absent for a grant.
    #[wasm_bindgen(js_name = acceptBeforeMs)]
    pub fn accept_before_ms(&self) -> Option<f64> {
        #[allow(
            clippy::cast_precision_loss,
            reason = "a time in milliseconds fits 2^53"
        )]
        self.accept_before_ms.map(|ms| ms as f64)
    }
    /// True when a `CloudDeliveryReceipt` acknowledges this publication.
    #[wasm_bindgen(js_name = isReceipt)]
    pub fn is_receipt(&self, publication_id: &[u8], cursor: u64, ciphertext_sha256: &[u8]) -> bool {
        self.publication
            .is_receipt(publication_id, cursor, ciphertext_sha256)
    }
}

impl WebPublication {
    #[cfg(test)]
    pub(crate) fn publication(&self) -> &Publication {
        &self.publication
    }
    pub(crate) fn grant(publication: Publication) -> Self {
        Self {
            publication,
            accept_before_ms: None,
        }
    }
}
