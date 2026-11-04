//! A new chat for a trusted runner (ADR 0122 of the native client), and the personal
//! collections that hold its records.
//!
//! The page stores [`WebNewChat::seal_material`] with a compare-create `PutObject` (expected
//! version 0) in the material collection, then [`WebNewChat::seal_grant`] in the grant
//! collection, and only then publishes [`WebNewChat::grant_publication`] to the runner inbox,
//! resending the same publication until the runner claims the chat.
use nocterm_cloud_device::create::{NewChat, new_chat_id};
use nocterm_keys::CollectionKey;
use wasm_bindgen::prelude::*;

use super::{
    CloudResult, WebCloud, WebCloudError,
    chat::{WebChat, WebPublication},
    hex_id, js,
};
use crate::{WebAccount, WebCollectionKey, WebError};

/// The records and grant of a chat that does not exist yet. The chat key was dropped when they
/// were made; only its wrapped and sealed forms remain.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebNewChat {
    chat: Option<NewChat>,
}

/// A fresh random chat id in lowercase hex. A managed agent's seat is started for the chat
/// (`StartInstance.chat_id`) before its runner, and so the chat's records, are known.
#[wasm_bindgen(js_name = newCloudChatId)]
pub fn new_cloud_chat_id() -> Result<String, JsError> {
    js(new_chat_id().map(hex::encode).map_err(WebCloudError::from))
}

#[wasm_bindgen]
impl WebCloud {
    /// Makes the records of chat `chat_id` (from [`new_cloud_chat_id`]) for a trusted runner.
    #[wasm_bindgen(js_name = newChat)]
    pub fn new_chat(
        &self,
        account: &WebAccount,
        runner_id: &[u8],
        chat_id: &str,
    ) -> Result<WebNewChat, JsError> {
        js(self.created(account, runner_id, chat_id))
    }
}

impl WebCloud {
    pub(crate) fn created(
        &self,
        account: &WebAccount,
        runner_id: &[u8],
        chat_id: &str,
    ) -> CloudResult<WebNewChat> {
        let runner = self.runner(runner_id)?;
        let chat = NewChat::create(
            self.hub().scope(),
            runner,
            hex_id(chat_id, "chat id")?,
            &account.account,
            &account.pair,
        )?;
        Ok(WebNewChat { chat: Some(chat) })
    }
}

#[wasm_bindgen]
impl WebNewChat {
    /// The chat id in lowercase hex (`StartInstance.chat_id`).
    #[wasm_bindgen(js_name = chatId)]
    pub fn chat_id(&self) -> Result<String, JsError> {
        js(self
            .chat()
            .map(|chat| hex::encode(chat.selector().chat_id())))
    }
    /// The object id of both records.
    #[wasm_bindgen(js_name = objectId)]
    pub fn object_id(&self) -> Result<String, JsError> {
        js(self
            .chat()
            .and_then(|chat| Ok(chat.selector().object_id()?)))
    }
    /// The sealed `cloud-chat-material` object for the material collection's key.
    #[wasm_bindgen(js_name = sealMaterial)]
    pub fn seal_material(&self, key: &WebCollectionKey) -> Result<Vec<u8>, JsError> {
        js(self
            .chat()
            .and_then(|chat| Ok(chat.material().seal(&key.key)?)))
    }
    /// The sealed `cloud-chat-grant` object for the grant collection's key.
    #[wasm_bindgen(js_name = sealGrant)]
    pub fn seal_grant(&self, key: &WebCollectionKey) -> Result<Vec<u8>, JsError> {
        js(self
            .chat()
            .and_then(|chat| Ok(chat.grant().seal(&key.key, chat.selector())?)))
    }
    /// The runner-inbox publication of the stored grant; every call names the same
    /// publication id and bytes.
    #[wasm_bindgen(js_name = grantPublication)]
    pub fn grant_publication(&self, cloud: &WebCloud) -> Result<WebPublication, JsError> {
        js(self.publication(cloud))
    }
    /// The chat, to probe and replay once the runner claimed it. Ends this value.
    #[wasm_bindgen(js_name = intoChat)]
    pub fn into_chat(&mut self) -> Result<WebChat, JsError> {
        js(self.take_chat())
    }
}

impl WebNewChat {
    pub(crate) fn take_chat(&mut self) -> CloudResult<WebChat> {
        let chat = self.chat.take().ok_or(WebCloudError::Used)?;
        Ok(WebChat::new(chat.material().clone()))
    }
    pub(crate) fn chat(&self) -> CloudResult<&NewChat> {
        self.chat.as_ref().ok_or(WebCloudError::Used)
    }
    pub(crate) fn publication(&self, cloud: &WebCloud) -> CloudResult<WebPublication> {
        Ok(WebPublication::grant(
            self.chat()?.grant_publication(cloud.capabilities())?,
        ))
    }
}

/// A personal collection made in the browser: send `wrappedKey` and `sealedName` with
/// `CreateCollection` (the client-chosen id), then use the key.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebNewCollection {
    wrapped_key: Vec<u8>,
    sealed_name: Vec<u8>,
    key: Option<WebCollectionKey>,
}

#[wasm_bindgen]
impl WebAccount {
    /// A new key for the personal collection `collection_id`, wrapped by the account key, and
    /// the collection's name (`kind`) sealed by it, as native devices create Cloud collections.
    #[wasm_bindgen(js_name = createCollection)]
    pub fn create_collection(
        &self,
        collection_id: &str,
        kind: &str,
    ) -> Result<WebNewCollection, JsError> {
        self.new_collection(collection_id, kind)
            .map_err(JsError::from)
    }
}

impl WebAccount {
    pub(crate) fn new_collection(
        &self,
        collection_id: &str,
        kind: &str,
    ) -> Result<WebNewCollection, WebError> {
        let key = CollectionKey::generate()?;
        Ok(WebNewCollection {
            wrapped_key: key.seal_for(&self.account, collection_id)?,
            sealed_name: key.seal_name(collection_id, kind)?,
            key: Some(WebCollectionKey {
                collection_id: collection_id.to_owned(),
                key,
            }),
        })
    }
}

#[wasm_bindgen]
impl WebNewCollection {
    /// `CreateCollectionRequest.wrapped_key`.
    #[wasm_bindgen(js_name = wrappedKey)]
    pub fn wrapped_key(&self) -> Vec<u8> {
        self.wrapped_key.clone()
    }
    /// `CreateCollectionRequest.sealed_name`.
    #[wasm_bindgen(js_name = sealedName)]
    pub fn sealed_name(&self) -> Vec<u8> {
        self.sealed_name.clone()
    }
    /// The collection key, once the hub created the collection. Ends this value.
    #[wasm_bindgen(js_name = intoKey)]
    pub fn into_key(&mut self) -> Result<WebCollectionKey, JsError> {
        js(self.take_key())
    }
}

impl WebNewCollection {
    pub(crate) fn take_key(&mut self) -> CloudResult<WebCollectionKey> {
        self.key.take().ok_or(WebCloudError::Used)
    }
}
