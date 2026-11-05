//! [`CloudDevice`]: the signed-in account's browser device and the flows it starts.
use std::{cell::RefCell, rc::Rc, sync::Arc};

use nocterm_cloud_device::{
    DeviceIdentity,
    context::{AccountKeys, ChatRef, CloudSession},
    create::{ChatHost, CreateChat},
    directory::VerifiedDirectory,
    discover::Discover,
    list::ListChats,
    nonces::Nonces,
    open::OpenChat,
    provider::ProviderLease,
    reader::VerifiedChat,
    records::TrustedRunner,
};
use wasm_bindgen::prelude::*;

use super::{
    CloudResult, WebCloudError,
    flow::{Running, WebChat, WebFlow},
    from_js, hex_id, js, millis,
    types::{DeviceInput, ListOptions, NewChatHost},
    view::RunnerInfo,
};
use crate::WebAccount;

/// What every flow of one device shares: the unlocked keys, the device and, once `connect`
/// reported `ready`, the trusted hub session.
#[derive(Debug)]
pub(crate) struct Shared {
    keys: Arc<AccountKeys>,
    device: DeviceIdentity,
    session: Option<Arc<CloudSession>>,
}
impl Shared {
    pub(super) fn set_session(&mut self, session: Arc<CloudSession>) {
        self.session = Some(session);
    }
    pub(super) fn set_runners(&mut self, runners: Vec<TrustedRunner>) {
        if let Some(session) = &self.session {
            self.session = Some(Arc::new(session.with_runners(runners)));
        }
    }
    fn session(&self) -> CloudResult<Arc<CloudSession>> {
        self.session.clone().ok_or(WebCloudError::NotReady)
    }
}

pub(super) fn identity(device: DeviceInput) -> CloudResult<DeviceIdentity> {
    let DeviceInput {
        device_id,
        signing_key,
        access_token,
        session_expires_at_ms,
    } = device;
    let signing_key: [u8; 32] = signing_key
        .try_into()
        .map_err(|_| WebCloudError::Argument("device signing key"))?;
    Ok(DeviceIdentity::new(
        &device_id,
        signing_key,
        &access_token,
        millis(session_expires_at_ms, "session expiry")?,
    )?)
}

/// The account's Cloud device in this browser. Start with `connect`; the other flows need the
/// `ready` it reports.
#[wasm_bindgen]
#[derive(Debug)]
pub struct CloudDevice {
    shared: Rc<RefCell<Shared>>,
}

#[wasm_bindgen]
impl CloudDevice {
    /// The device of the unlocked `account`; the keys stay inside WebAssembly.
    #[wasm_bindgen(constructor)]
    pub fn new(
        account: &WebAccount,
        #[wasm_bindgen(unchecked_param_type = "DeviceInput")] device: JsValue,
    ) -> Result<CloudDevice, JsError> {
        js(from_js(device, "device").and_then(|device| Self::made(account, device)))
    }
    /// The device after a token refresh; flows started later name it.
    #[wasm_bindgen(js_name = setDevice)]
    pub fn set_device(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "DeviceInput")] device: JsValue,
    ) -> Result<(), JsError> {
        let identity = js(from_js(device, "device").and_then(identity))?;
        self.shared.borrow_mut().device = identity;
        Ok(())
    }
    /// Finds the account's trust in hub `rawHub` (`GetHubInfo.hub_id`), checks the capability
    /// proof and reads the trusted runners. `origin` is the person's earlier choice.
    pub fn connect(&self, raw_hub: &str, origin: Option<String>) -> WebFlow {
        self.discover(raw_hub, origin, Nonces::os())
    }
    /// As `connect`, with probe and capability nonces drawn from `seed` (recorded test sessions
    /// only; present in a `testing` build).
    #[cfg(feature = "testing")]
    #[wasm_bindgen(js_name = connectSeeded)]
    pub fn connect_seeded(
        &self,
        raw_hub: &str,
        origin: Option<String>,
        seed: &[u8],
    ) -> Result<WebFlow, JsError> {
        let seed: [u8; 32] = js(seed.try_into().map_err(|_| WebCloudError::Argument("seed")))?;
        Ok(self.discover(raw_hub, origin, Nonces::seeded(seed)))
    }
    /// True once `connect` reported `ready`.
    pub fn ready(&self) -> bool {
        self.shared.borrow().session.is_some()
    }
    /// The trusted runners.
    pub fn runners(&self) -> Vec<RunnerInfo> {
        self.shared
            .borrow()
            .session
            .as_ref()
            .map(|session| session.runners().iter().map(RunnerInfo::from).collect())
            .unwrap_or_default()
    }
    /// Every trusted runner's chats: its directory of signed summaries (from the stored
    /// `options.directories` checkpoints on) confirmed by a fresh catalog witness, never a
    /// replay of a chat. With `options.watch` new summaries keep arriving and the flow never
    /// ends.
    #[wasm_bindgen(js_name = listChats)]
    pub fn list_chats(
        &self,
        #[wasm_bindgen(unchecked_optional_param_type = "ListOptions | null")] options: JsValue,
    ) -> Result<WebFlow, JsError> {
        js(from_js::<Option<ListOptions>>(options, "list options")
            .and_then(|options| self.listing_with(options.unwrap_or_default())))
    }
    /// Opens chat `chatId` (`ChatRef` text), resuming at `checkpoint` (the bytes of its last
    /// `checkpoint` output) when there is one.
    #[wasm_bindgen(js_name = openChat)]
    pub fn open_chat(
        &self,
        chat_id: &str,
        checkpoint: Option<Vec<u8>>,
    ) -> Result<WebChat, JsError> {
        js(self.opened(chat_id, checkpoint))
    }
    /// Creates a chat on `host`; `chatId` (32 hex) repeats an earlier attempt.
    #[wasm_bindgen(js_name = createChat)]
    pub fn create_chat(
        &self,
        #[wasm_bindgen(unchecked_param_type = "NewChatHost")] host: JsValue,
        chat_id: Option<String>,
    ) -> Result<WebFlow, JsError> {
        js(from_js(host, "chat host").and_then(|host| self.creating(host, chat_id)))
    }
    /// Wakes the enrolled seat of managed agent `agentId`, for chat `chatId` (`ChatRef` text)
    /// when one is named: `listInstances`, then `startInstance` of that seat's pool.
    #[wasm_bindgen(js_name = wakeSeat)]
    pub fn wake_seat(&self, agent_id: &str, chat_id: Option<String>) -> Result<WebFlow, JsError> {
        let chat = js(chat_id
            .map(|text| {
                text.parse::<nocterm_cloud_device::context::ChatRef>()
                    .map_err(|_| super::WebCloudError::Argument("chat id"))
            })
            .transpose())?;
        Ok(WebFlow::new(
            super::flow::Running::Wake(nocterm_cloud_device::seat::WakeSeat::new(
                agent_id,
                chat.map(|chat| chat.chat_id),
            )),
            self.shared.clone(),
        ))
    }
    /// Leases `agentId`'s own provider key to the runner of `chat` and renews it while the flow
    /// runs.
    pub fn lease(&self, chat: &WebChat, agent_id: &str) -> Result<WebFlow, JsError> {
        js(self.leasing(chat, agent_id))
    }
}

impl CloudDevice {
    pub(crate) fn made(account: &WebAccount, device: DeviceInput) -> CloudResult<Self> {
        let keys = AccountKeys::new(
            &account.account_id,
            account.account.clone(),
            account.pair.clone(),
        );
        Ok(Self {
            shared: Rc::new(RefCell::new(Shared {
                keys: Arc::new(keys),
                device: identity(device)?,
                session: None,
            })),
        })
    }
    pub(crate) fn discover(
        &self,
        raw_hub: &str,
        origin: Option<String>,
        nonces: Nonces,
    ) -> WebFlow {
        let keys = self.shared.borrow().keys.clone();
        WebFlow::new(
            Running::Discover(Discover::with_nonces(keys, raw_hub, origin, nonces)),
            self.shared.clone(),
        )
    }
    fn parts(&self) -> CloudResult<(Arc<CloudSession>, DeviceIdentity)> {
        let shared = self.shared.borrow();
        Ok((shared.session()?, shared.device.clone()))
    }
    #[cfg(test)]
    pub(crate) fn listing(&self) -> CloudResult<WebFlow> {
        self.listing_with(ListOptions::default())
    }
    pub(crate) fn listing_with(&self, options: ListOptions) -> CloudResult<WebFlow> {
        let (session, device) = self.parts()?;
        let checkpoints: Vec<VerifiedDirectory> = options
            .directories
            .unwrap_or_default()
            .into_iter()
            .map(|bytes| VerifiedDirectory::from_bytes(bytes.into_vec()))
            .collect();
        let mut flow = ListChats::new(session, device).with_directories(&checkpoints);
        if options.watch.unwrap_or_default() {
            flow = flow.watching();
        }
        Ok(WebFlow::new(Running::List(flow), self.shared.clone()))
    }
    pub(crate) fn opened(
        &self,
        chat_id: &str,
        checkpoint: Option<Vec<u8>>,
    ) -> CloudResult<WebChat> {
        let (session, device) = self.parts()?;
        let chat: ChatRef = chat_id.parse()?;
        let checkpoint = checkpoint.map(VerifiedChat::from_bytes);
        let open = OpenChat::new(session, device, &chat, checkpoint.as_ref())?;
        Ok(WebChat::new(open, self.shared.clone()))
    }
    pub(crate) fn creating(
        &self,
        host: NewChatHost,
        chat_id: Option<String>,
    ) -> CloudResult<WebFlow> {
        let (session, device) = self.parts()?;
        let host = match host {
            NewChatHost::Managed { agent_id } => ChatHost::Managed { agent_id },
            NewChatHost::Own { runner_id } => ChatHost::Own {
                runner: hex_id(&runner_id, "runner id")?,
            },
        };
        let chat_id = chat_id.map(|id| hex_id(&id, "chat id")).transpose()?;
        Ok(WebFlow::new(
            Running::Create(CreateChat::new(session, device, host, chat_id)?),
            self.shared.clone(),
        ))
    }
    pub(crate) fn leasing(&self, chat: &WebChat, agent_id: &str) -> CloudResult<WebFlow> {
        let (session, device) = self.parts()?;
        let lease = ProviderLease::new(session, device, &chat.chat_ref(), agent_id, 0)?;
        Ok(WebFlow::new(
            Running::Lease(lease, chat.handle()),
            self.shared.clone(),
        ))
    }
}
