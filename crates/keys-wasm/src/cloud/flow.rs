//! The flows as the page drives them: [`WebFlow`] for the finite ones and [`WebChat`] for an
//! open chat, with the conversion between the core's effect protocol and the structured
//! values of [`super::types`].
use std::{
    cell::RefCell,
    rc::{Rc, Weak},
};

use nocterm_cloud_device::{
    command::Deliver,
    create::CreateChat,
    discover::{Discover, Discovery},
    flow::{
        CollectionEntry, Effect, EffectFailure, Flow, Frame, Input, InstanceEntry, InstanceState,
        ObjectEntry, RecordHeader, Step, StreamKind, StreamSelector,
    },
    list::ListChats,
    open::{ChatAction, ChatUpdate, ModelChoice, OpenChat},
    provider::ProviderLease,
};
use wasm_bindgen::prelude::*;

use super::{
    CloudResult, WebCloudError,
    device::Shared,
    from_js, hex_id, js, millis,
    types::{
        ChatActionInput, EffectInput, FlowOutput, FlowStep, StreamFrame, WireEffect, WireInstance,
        WirePublication, WireSelector,
    },
    view::{RunnerInfo, WireDelta, WireFreshness, command_state, ms},
};

/// A finite flow: `connect`, `listChats`, `deliver`, `createChat` or `lease`.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebFlow {
    running: Running,
    shared: Rc<RefCell<Shared>>,
}

#[derive(Debug)]
pub(super) enum Running {
    Discover(Discover),
    List(ListChats),
    Deliver(Deliver, Weak<RefCell<OpenChat>>),
    Create(CreateChat),
    Lease(ProviderLease, Weak<RefCell<OpenChat>>),
}

#[wasm_bindgen]
impl WebFlow {
    /// The next step at `nowMs`.
    pub fn next(&mut self, now_ms: f64) -> Result<FlowStep, JsError> {
        js(self.step(now_ms))
    }
    /// The answer to effect `id`. An answer that does not match `EffectInput` is refused and
    /// changes nothing.
    pub fn resolve(
        &mut self,
        id: u32,
        #[wasm_bindgen(unchecked_param_type = "EffectInput")] input: JsValue,
    ) -> Result<(), JsError> {
        js(from_js(input, "effect input").and_then(|input| self.resolve_input(id, input)))
    }
    /// One stream frame of effect `id` (a replay or watch). A frame that does not match
    /// `StreamFrame` is refused and changes nothing.
    pub fn frame(
        &mut self,
        id: u32,
        #[wasm_bindgen(unchecked_param_type = "StreamFrame")] frame: JsValue,
    ) -> Result<(), JsError> {
        let frame = js(from_js(frame, "stream frame"))?;
        self.frame_input(id, frame);
        Ok(())
    }
}

impl WebFlow {
    pub(super) fn new(running: Running, shared: Rc<RefCell<Shared>>) -> Self {
        Self { running, shared }
    }
    pub(crate) fn step(&mut self, now_ms: f64) -> CloudResult<FlowStep> {
        let now = millis(now_ms, "time")?;
        let shared = &self.shared;
        Ok(match &mut self.running {
            Running::Discover(flow) => convert(flow.next(now), |outcome| {
                discovery(&mut shared.borrow_mut(), outcome)
            }),
            Running::List(flow) => convert(flow.next(now), super::listing::listed),
            Running::Deliver(flow, chat) => convert(flow.next(now), |update| {
                if let Some(chat) = chat.upgrade() {
                    chat.borrow_mut().delivery(&update);
                }
                FlowOutput::Delivery {
                    command_id: hex::encode(update.command_id),
                    state: command_state(update.state),
                    cursor: update.cursor,
                }
            }),
            Running::Create(flow) => convert(flow.next(now), |created| {
                let runners_reloaded = created.runners.is_some();
                if let Some(runners) = created.runners {
                    shared.borrow_mut().set_runners(runners);
                }
                FlowOutput::Created {
                    chat_id: created.chat.to_string(),
                    instance_id: created.instance_id,
                    runners_reloaded,
                }
            }),
            Running::Lease(flow, chat) => {
                if let Some(chat) = chat.upgrade() {
                    flow.set_control_revision(chat.borrow().transcript().control_revision());
                }
                convert(flow.next(now), |lease| FlowOutput::Lease {
                    grant: hex::encode(lease.grant),
                    provider: lease.provider,
                    model: lease.model,
                    expires_at_ms: ms(lease.expires_at_ms),
                    renew_at_ms: ms(lease.renew_at_ms),
                })
            }
        })
    }
    pub(crate) fn resolve_input(&mut self, id: u32, input: EffectInput) -> CloudResult<()> {
        let input = input_of(input)?;
        match &mut self.running {
            Running::Discover(flow) => flow.resolve(id, input),
            Running::List(flow) => flow.resolve(id, input),
            Running::Deliver(flow, _) => flow.resolve(id, input),
            Running::Create(flow) => flow.resolve(id, input),
            Running::Lease(flow, _) => flow.resolve(id, input),
        }
        Ok(())
    }
    pub(crate) fn frame_input(&mut self, id: u32, frame: StreamFrame) {
        let frame = frame_of(frame);
        match &mut self.running {
            Running::Discover(flow) => flow.frame(id, frame),
            Running::List(flow) => flow.frame(id, frame),
            Running::Deliver(flow, _) => flow.frame(id, frame),
            Running::Create(flow) => flow.frame(id, frame),
            Running::Lease(flow, _) => flow.frame(id, frame),
        }
    }
}

/// An open chat: its flow, and the commands built from its verified transcript.
#[wasm_bindgen]
#[derive(Debug)]
pub struct WebChat {
    chat: Rc<RefCell<OpenChat>>,
    shared: Rc<RefCell<Shared>>,
}

#[wasm_bindgen]
impl WebChat {
    /// The `ChatRef` text of this chat.
    #[wasm_bindgen(js_name = chatId)]
    pub fn chat_id(&self) -> String {
        self.chat.borrow().chat().to_string()
    }
    pub fn next(&mut self, now_ms: f64) -> Result<FlowStep, JsError> {
        js(self.step(now_ms))
    }
    pub fn resolve(
        &mut self,
        id: u32,
        #[wasm_bindgen(unchecked_param_type = "EffectInput")] input: JsValue,
    ) -> Result<(), JsError> {
        js(from_js(input, "effect input").and_then(|input| self.resolve_input(id, input)))
    }
    pub fn frame(
        &mut self,
        id: u32,
        #[wasm_bindgen(unchecked_param_type = "StreamFrame")] frame: JsValue,
    ) -> Result<(), JsError> {
        let frame = js(from_js(frame, "stream frame"))?;
        self.frame_input(id, frame);
        Ok(())
    }
    /// The whole transcript as one reset delta, for a view that starts now.
    pub fn transcript(&self) -> WireDelta {
        WireDelta::from(&self.chat.borrow().transcript().full_delta())
    }
    pub fn freshness(&self) -> WireFreshness {
        WireFreshness::from(self.chat.borrow().freshness())
    }
    /// Probes the runner again and replays what is new (the Refresh button).
    pub fn refresh(&mut self) {
        self.chat.borrow_mut().refresh();
    }
    /// The device after a token refresh.
    #[wasm_bindgen(js_name = setDevice)]
    pub fn set_device(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "DeviceInput")] device: JsValue,
    ) -> Result<(), JsError> {
        let identity = js(from_js(device, "device").and_then(super::device::identity))?;
        self.chat.borrow_mut().set_device(identity);
        Ok(())
    }
    /// Starts delivering `action`; it shows as a pending command at once. `wake` names the
    /// managed agent whose seat serves this chat (its seat is started first).
    pub fn deliver(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ChatActionInput")] action: JsValue,
        wake: Option<String>,
        now_ms: f64,
    ) -> Result<WebFlow, JsError> {
        js(from_js(action, "chat action").and_then(|action| self.delivery(action, wake, now_ms)))
    }
}

impl WebChat {
    pub(super) fn new(chat: OpenChat, shared: Rc<RefCell<Shared>>) -> Self {
        Self {
            chat: Rc::new(RefCell::new(chat)),
            shared,
        }
    }
    pub(super) fn handle(&self) -> Weak<RefCell<OpenChat>> {
        Rc::downgrade(&self.chat)
    }
    pub(super) fn chat_ref(&self) -> nocterm_cloud_device::context::ChatRef {
        self.chat.borrow().chat()
    }
    pub(crate) fn step(&mut self, now_ms: f64) -> CloudResult<FlowStep> {
        let now = millis(now_ms, "time")?;
        let step = self.chat.borrow_mut().next(now);
        Ok(convert(step, |update| match update {
            ChatUpdate::Transcript(delta) => FlowOutput::Transcript {
                delta: WireDelta::from(&delta),
            },
            ChatUpdate::Freshness(freshness) => FlowOutput::Freshness {
                freshness: freshness.into(),
            },
            ChatUpdate::Checkpoint(checkpoint) => FlowOutput::Checkpoint {
                bytes: checkpoint.into_bytes(),
            },
            ChatUpdate::AllowRun { run } => FlowOutput::AllowRun {
                run: hex::encode(run.id),
            },
            ChatUpdate::Refused(error) => FlowOutput::Refused {
                error: WebCloudError::from(error).wire(),
            },
        }))
    }
    pub(crate) fn resolve_input(&mut self, id: u32, input: EffectInput) -> CloudResult<()> {
        let input = input_of(input)?;
        self.chat.borrow_mut().resolve(id, input);
        Ok(())
    }
    pub(crate) fn frame_input(&mut self, id: u32, frame: StreamFrame) {
        self.chat.borrow_mut().frame(id, frame_of(frame));
    }
    pub(crate) fn delivery(
        &mut self,
        action: ChatActionInput,
        wake: Option<String>,
        now_ms: f64,
    ) -> CloudResult<WebFlow> {
        let action = action_of(action)?;
        let now = millis(now_ms, "time")?;
        let deliver = self.chat.borrow_mut().deliver(&action, wake, now)?;
        Ok(WebFlow::new(
            Running::Deliver(deliver, self.handle()),
            self.shared.clone(),
        ))
    }
}

/// One core step as the page reads it.
fn convert<O>(step: Step<O>, output: impl FnOnce(O) -> FlowOutput) -> FlowStep {
    match step {
        Step::Effect(id, effect) => FlowStep::Effect {
            id,
            effect: wire_effect(effect),
        },
        Step::Output(value) => FlowStep::Output {
            output: output(value),
        },
        Step::Idle { until_ms } => FlowStep::Idle {
            until_ms: until_ms.map(ms),
        },
        Step::Done => FlowStep::Done,
        Step::Failed(error) => FlowStep::Failed {
            error: WebCloudError::from(error).wire(),
        },
    }
}

fn discovery(shared: &mut Shared, outcome: Discovery) -> FlowOutput {
    match outcome {
        Discovery::NotSetUp => FlowOutput::NotSetUp,
        Discovery::ChooseOrigin(origins) => FlowOutput::ChooseOrigin { origins },
        Discovery::Unsupported => FlowOutput::Unsupported,
        Discovery::Ready(session) => {
            let capabilities = session.capabilities();
            let output = FlowOutput::Ready {
                origin: session.hub().record().origin().to_owned(),
                can_command: capabilities.require_commands().is_ok(),
                can_create: capabilities.require_commands().is_ok()
                    && capabilities.chat_key_material(),
                runners: session.runners().iter().map(RunnerInfo::from).collect(),
            };
            shared.set_session(session);
            output
        }
    }
}

fn selector_out(selector: StreamSelector) -> WireSelector {
    let (chat_id, directory) = match selector.stream {
        StreamKind::Inbox => (None, false),
        StreamKind::Chat(id) => (Some(id.to_vec()), false),
        StreamKind::Directory => (None, true),
    };
    WireSelector {
        runner_id: selector.runner_id.to_vec(),
        runner_key_epoch: selector.runner_key_epoch,
        chat_id,
        directory,
    }
}

pub(crate) fn wire_effect(effect: Effect) -> WireEffect {
    match effect {
        Effect::Sign(request) => WireEffect::Sign {
            bytes: request.bytes().to_vec(),
            signing_key: request.signing_key().to_vec(),
        },
        Effect::ListCollections { kind } => WireEffect::ListCollections {
            collection_kind: kind,
        },
        Effect::GetCollectionKey { collection_id } => {
            WireEffect::GetCollectionKey { collection_id }
        }
        Effect::GetObject {
            collection_id,
            object_id,
        } => WireEffect::GetObject {
            collection_id,
            object_id,
        },
        Effect::PutObject {
            collection_id,
            object_id,
            kind,
            expected_version,
            ciphertext,
        } => WireEffect::PutObject {
            collection_id,
            object_id,
            object_kind: kind,
            expected_version,
            ciphertext,
        },
        Effect::CreateCollection {
            collection_id,
            kind,
            wrapped_key,
            sealed_name,
        } => WireEffect::CreateCollection {
            collection_id,
            collection_kind: kind,
            wrapped_key,
            sealed_name,
        },
        Effect::Capabilities { nonce } => WireEffect::Capabilities {
            nonce: nonce.to_vec(),
        },
        Effect::Probe(request) => WireEffect::Probe {
            scope: request.scope,
            probe_id: request.probe_id.to_vec(),
            ciphertext: request.ciphertext,
            expires_at_ms: ms(request.expires_at_ms),
        },
        Effect::Replay {
            selector,
            after_cursor,
            max_records,
            max_bytes,
        } => WireEffect::Replay {
            selector: selector_out(selector),
            after_cursor,
            max_records,
            max_bytes,
        },
        Effect::Watch {
            selector,
            after_cursor,
        } => WireEffect::Watch {
            selector: selector_out(selector),
            after_cursor,
        },
        Effect::Publish(publication) => WireEffect::Publish {
            publication: WirePublication {
                publication_id: publication.publication_id().to_vec(),
                binding: publication.binding().unwrap_or_default(),
                total_bytes: publication.total_bytes(),
                ciphertext_sha256: publication.ciphertext_sha256().to_vec(),
            },
            data: publication.ciphertext().to_vec(),
        },
        Effect::StartInstance { agent_id, chat_id } => {
            WireEffect::StartInstance { agent_id, chat_id }
        }
        Effect::ListInstances => WireEffect::ListInstances,
        Effect::RunnerStatus { runner_id } => WireEffect::RunnerStatus {
            runner_id: runner_id.to_vec(),
        },
    }
}

const STATES: [(&str, InstanceState); 7] = [
    ("provisioning", InstanceState::Provisioning),
    ("awaiting_enrolment", InstanceState::AwaitingEnrolment),
    ("ready", InstanceState::Ready),
    ("suspended", InstanceState::Suspended),
    ("deleting", InstanceState::Deleting),
    ("failed", InstanceState::Failed),
    ("unknown", InstanceState::Unknown),
];
const FAILURES: [(&str, EffectFailure); 7] = [
    ("not_found", EffectFailure::NotFound),
    ("already_exists", EffectFailure::AlreadyExists),
    ("conflict", EffectFailure::Conflict),
    ("unavailable", EffectFailure::Unavailable),
    ("unknown", EffectFailure::Unknown),
    ("refused", EffectFailure::Refused),
    ("ended", EffectFailure::Ended),
];

pub(super) fn instance_out(seat: &InstanceEntry) -> WireInstance {
    WireInstance {
        instance_id: seat.instance_id.clone(),
        agent_id: seat.agent_id.clone(),
        runner_id: seat.runner_id.map(hex::encode),
        state: STATES
            .iter()
            .find(|(_, state)| *state == seat.state)
            .map_or("unknown", |(name, _)| name)
            .to_owned(),
    }
}
fn instance_in(seat: WireInstance) -> CloudResult<InstanceEntry> {
    Ok(InstanceEntry {
        runner_id: seat
            .runner_id
            .map(|id| hex_id(&id, "runner id"))
            .transpose()?,
        state: STATES
            .iter()
            .find(|(name, _)| *name == seat.state)
            .map_or(InstanceState::Unknown, |(_, state)| *state),
        instance_id: seat.instance_id,
        agent_id: seat.agent_id,
    })
}

pub(crate) fn input_of(input: EffectInput) -> CloudResult<Input> {
    Ok(match input {
        EffectInput::Signature { signature } => Input::Signature(signature),
        EffectInput::Collections { collections } => Input::Collections(
            collections
                .into_iter()
                .map(|c| CollectionEntry {
                    collection_id: c.collection_id,
                    kind: c.kind,
                    personal: c.personal,
                    deleted: c.deleted,
                })
                .collect(),
        ),
        EffectInput::CollectionKey {
            wrapped_key,
            granted_by,
        } => Input::CollectionKey {
            wrapped_key,
            granted_by: granted_by.unwrap_or_default(),
        },
        EffectInput::Object { object } => Input::Object(ObjectEntry {
            collection_id: object.collection_id,
            object_id: object.object_id,
            kind: object.kind,
            version: object.version,
            deleted: object.deleted,
            ciphertext: object.ciphertext,
        }),
        EffectInput::Stored { version } => Input::Stored { version },
        EffectInput::Done => Input::Done,
        EffectInput::Capabilities { claim, signature } => Input::Capabilities { claim, signature },
        EffectInput::ProbeReply {
            scope,
            probe_id,
            ciphertext,
        } => Input::ProbeReply {
            scope,
            probe_id,
            ciphertext,
        },
        EffectInput::Receipt {
            publication_id,
            cursor,
            ciphertext_sha256,
        } => Input::Receipt {
            publication_id,
            cursor,
            ciphertext_sha256,
        },
        EffectInput::Instance { instance } => Input::Instance(instance_in(instance)?),
        EffectInput::Instances { instances } => Input::Instances(
            instances
                .into_iter()
                .map(instance_in)
                .collect::<CloudResult<_>>()?,
        ),
        EffectInput::RunnerStatus { signed_status } => Input::RunnerStatus { signed_status },
        EffectInput::Failed { failure } => Input::Failed(
            FAILURES
                .iter()
                .find(|(name, _)| *name == failure)
                .map(|(_, failure)| *failure)
                .ok_or(WebCloudError::Argument("failure"))?,
        ),
    })
}

pub(crate) fn frame_of(frame: StreamFrame) -> Frame {
    match frame {
        StreamFrame::Header {
            publication_id,
            binding,
            total_bytes,
            ciphertext_sha256,
            cursor,
            origin_account_id,
            origin_signing_key,
            origin_runner_id,
        } => Frame::Header(RecordHeader {
            publication_id,
            binding,
            total_bytes,
            ciphertext_sha256,
            cursor,
            origin_account_id,
            origin_signing_key,
            origin_runner_id,
        }),
        StreamFrame::Data { bytes } => Frame::Data(bytes),
        StreamFrame::End { publication_id } => Frame::End { publication_id },
        StreamFrame::PageEnd {
            through_cursor,
            has_more,
        } => Frame::PageEnd {
            through_cursor,
            has_more,
        },
        StreamFrame::Gap {
            retained_from,
            snapshot_publication_id,
        } => Frame::Gap {
            retained_from,
            snapshot_publication_id,
        },
        StreamFrame::Hint { head_cursor } => Frame::Hint { head_cursor },
    }
}

fn action_of(action: ChatActionInput) -> CloudResult<ChatAction> {
    Ok(match action {
        ChatActionInput::Prompt { text, model } => ChatAction::Prompt {
            text,
            model: model.map(|model| ModelChoice {
                provider: model.provider,
                model: model.model,
            }),
        },
        ChatActionInput::Stop { run } => ChatAction::Stop {
            run: run.map(|run| hex_id(&run, "run")).transpose()?,
        },
        ChatActionInput::Allow { run } => ChatAction::Allow {
            run: hex_id(&run, "run")?,
        },
        ChatActionInput::Answer { intent, approve } => ChatAction::Answer {
            intent: hex_id(&intent, "intent")?,
            approve,
        },
    })
}
