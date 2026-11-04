//! The `OpenChat` flow: one chat kept current while it is open (ADR 0007).
//!
//! It opens the chat's wrapped key from `cloud-chat-material`, restores a sealed checkpoint when
//! the caller has one (its transcript shows at once, `Unconfirmed`), probes the runner for a
//! fresh head and replays incrementally from the reader's cursor. It then watches the chat
//! stream: a hint above the cursor replays only the new records. A probe runs on open, on every
//! Watch reconnect, after a receipt of a command this device sent, and on [`OpenChat::refresh`];
//! never periodically. After every completed round it hands out the transcript delta, the
//! freshness when it changed, and a new sealed checkpoint for the client to store.
//!
//! Commands are built here from the verified transcript ([`OpenChat::deliver`]) and run as their
//! own [`Deliver`] flow; their outcomes come back through [`OpenChat::delivery`]. When the runner
//! accepted a prompt of this device that waits for its model grant, the flow asks for it once
//! ([`ChatUpdate::AllowRun`], ADR 0129 of the native client).
use crate::{
    CloudDeviceError, DeviceIdentity,
    command::{CommandAction, Deliver, DeliveryUpdate, UnsignedCommand},
    context::{ChatRef, CloudSession},
    flow::{
        Arrival, Driven, Effect, EffectId, Flow, Frame, Input, Io, Machine, StreamKind,
        StreamSelector, Wait,
    },
    policy::{MANAGED_PROVIDER, PromptPolicy},
    probe::{ProbeCall, ProbeTarget},
    reader::{ChatReader, DeliveredOrigin, DeliveredRecord, Freshness, RoundEnd, VerifiedChat},
    records::{ChatMaterialRecord, ChatSelector, StoredObject},
    transcript::{CommandState, PendingCommand, PendingKind, Transcript, TranscriptDelta},
};
use nocterm_hub_model::cloud::{
    RunCoordinate, events::CloudRunStatus, head::HeadValue, payload::ApprovalChoice,
};
use nocterm_keys::CollectionKey;
use std::sync::Arc;

/// Bytes one replay page may carry; a record may stream over several frames.
pub const REPLAY_PAGE_BYTES: u32 = 1024 * 1024;
/// The first and the longest wait before a watch reconnects or a failed replay is retried.
pub const RETRY_MIN_MS: i64 = 1_000;
pub const RETRY_MAX_MS: i64 = 30_000;
const MAX_ALLOWED: usize = 32;

/// What an open chat reports.
#[derive(Debug)]
pub enum ChatUpdate {
    Transcript(TranscriptDelta),
    Freshness(Freshness),
    /// A sealed checkpoint to store in place of the previous one.
    Checkpoint(VerifiedChat),
    /// A prompt this device sent was accepted and waits for its model grant: deliver
    /// [`ChatAction::Allow`] for this run.
    AllowRun {
        run: RunCoordinate,
    },
    /// A replay round was refused; the verified prefix stays and the next hint or refresh tries
    /// again.
    Refused(CloudDeviceError),
}

/// A model a prompt names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelChoice {
    pub provider: String,
    pub model: String,
}

/// What the person asks of an open chat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatAction {
    /// A prompt; without a model, the latest run's.
    Prompt {
        text: String,
        model: Option<ModelChoice>,
    },
    /// Stop a run; without one, the active run.
    Stop {
        run: Option<[u8; 16]>,
    },
    /// The model grant of a run this device prompted, with that run's model.
    Allow {
        run: [u8; 16],
    },
    Answer {
        intent: [u8; 16],
        approve: bool,
    },
}

/// The `OpenChat` flow.
#[derive(Debug)]
pub struct OpenChat(Driven<Reading>);
impl OpenChat {
    /// Opens `chat`, resuming at `checkpoint` when it is one of this chat (any other or an
    /// unusable checkpoint is ignored and the chat is read from the start).
    pub fn new(
        session: Arc<CloudSession>,
        device: DeviceIdentity,
        chat: &ChatRef,
        checkpoint: Option<&VerifiedChat>,
    ) -> Result<Self, CloudDeviceError> {
        let selector = session.selector(chat)?;
        let fresh = || ChatReader::new(&selector, session.capabilities());
        let reader = match checkpoint {
            Some(checkpoint) => ChatReader::restore(
                &selector,
                session.capabilities(),
                session.keys(),
                checkpoint,
            )
            .or_else(|_| fresh())?,
            None => fresh()?,
        };
        Ok(Self(Driven::new(Reading {
            session,
            device,
            selector,
            reader,
            material: None,
            probe: None,
            probe_wanted: true,
            replay: Replay {
                id: None,
                wanted: true,
                retry_at: None,
            },
            watch: Watching {
                id: None,
                retry_at: Some(i64::MIN),
                delay: RETRY_MIN_MS,
                hinted: 0,
                started: false,
            },
            reported: None,
            allowed: Vec::new(),
        })))
    }
    pub fn chat(&self) -> ChatRef {
        ChatRef::of(&self.0.machine().selector)
    }
    pub fn transcript(&self) -> &Transcript {
        self.0.machine().reader.transcript()
    }
    pub fn freshness(&self) -> Freshness {
        self.0.machine().reader.freshness()
    }
    /// Probes the runner again and replays what is new.
    pub fn refresh(&mut self) {
        self.0.with(|reading, _| {
            reading.probe_wanted = true;
            reading.replay.wanted = true;
        });
    }
    /// The device after a token refresh; later probes and commands name it.
    pub fn set_device(&mut self, device: DeviceIdentity) {
        self.0.with(|reading, _| reading.device = device);
    }
    /// Builds `action` against the verified transcript, tracks it as pending and returns its
    /// delivery. `wake` names the managed agent whose seat serves this chat.
    pub fn deliver(
        &mut self,
        action: &ChatAction,
        wake: Option<String>,
        now_ms: i64,
    ) -> Result<Deliver, CloudDeviceError> {
        self.0
            .with(|reading, _| reading.deliver(action, wake, now_ms))
    }
    /// Applies the outcome of a delivery of this chat; a receipt probes the runner again.
    pub fn delivery(&mut self, update: &DeliveryUpdate) {
        self.0.with(|reading, _| {
            reading
                .reader
                .transcript_mut()
                .set_command_state(&update.command_id, update.state);
            if matches!(
                update.state,
                CommandState::Delivered | CommandState::Accepted
            ) {
                reading.probe_wanted = true;
            }
        });
    }
}
impl Flow for OpenChat {
    type Output = ChatUpdate;
    fn next(&mut self, now_ms: i64) -> crate::flow::Step<ChatUpdate> {
        self.0.next(now_ms)
    }
    fn resolve(&mut self, id: EffectId, input: Input) {
        self.0.resolve(id, input);
    }
    fn frame(&mut self, id: EffectId, frame: Frame) {
        self.0.frame(id, frame);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    MaterialKey,
    MaterialObject(Vec<u8>),
    ProbeSign,
    Probe,
    Replay,
    Watch,
}

#[derive(Debug)]
struct Replay {
    id: Option<EffectId>,
    wanted: bool,
    retry_at: Option<i64>,
}

#[derive(Debug)]
struct Watching {
    id: Option<EffectId>,
    retry_at: Option<i64>,
    delay: i64,
    hinted: u64,
    started: bool,
}

#[derive(Debug)]
pub(crate) struct Reading {
    session: Arc<CloudSession>,
    device: DeviceIdentity,
    selector: ChatSelector,
    reader: ChatReader,
    material: Option<ChatMaterialRecord>,
    probe: Option<ProbeCall>,
    probe_wanted: bool,
    replay: Replay,
    watch: Watching,
    reported: Option<Freshness>,
    allowed: Vec<[u8; 16]>,
}

type ChatIo = Io<Purpose, ChatUpdate>;

impl Reading {
    fn deliver(
        &mut self,
        action: &ChatAction,
        wake: Option<String>,
        now_ms: i64,
    ) -> Result<Deliver, CloudDeviceError> {
        let transcript = self.reader.transcript();
        let run_state = |id: &[u8; 16]| transcript.run_by_id(id).ok_or(CloudDeviceError::NoRun);
        let policy;
        let (command_action, kind, text, run) = match action {
            ChatAction::Prompt { text, model } => {
                policy = prompt_policy(transcript, model.as_ref())?;
                (
                    CommandAction::Prompt {
                        policy: &policy,
                        text,
                    },
                    PendingKind::Prompt,
                    text.clone(),
                    None,
                )
            }
            ChatAction::Stop { run } => {
                let state = match run {
                    Some(id) => run_state(id)?,
                    None => transcript.active_run().ok_or(CloudDeviceError::NoRun)?,
                };
                let run = state.run;
                (
                    CommandAction::Stop { run },
                    PendingKind::Stop,
                    String::new(),
                    Some(run),
                )
            }
            ChatAction::Allow { run } => {
                let state = run_state(run)?;
                policy = PromptPolicy::runner_default(state.model.clone())?;
                (
                    CommandAction::Allow {
                        policy: &policy,
                        run: state.run,
                    },
                    PendingKind::Allow,
                    String::new(),
                    Some(state.run),
                )
            }
            ChatAction::Answer { intent, approve } => {
                let approval = transcript
                    .approval(intent)
                    .ok_or(CloudDeviceError::NoApproval)?;
                let choice = if *approve {
                    ApprovalChoice::Approve
                } else {
                    ApprovalChoice::Deny
                };
                (
                    CommandAction::Answer { approval, choice },
                    PendingKind::Answer,
                    String::new(),
                    Some(approval.run()),
                )
            }
        };
        let command = UnsignedCommand::prepare(
            &self.selector,
            self.session.keys().public_key(),
            &self.device,
            command_action,
            transcript.control_revision(),
            now_ms,
        )?;
        self.reader.transcript_mut().track(PendingCommand {
            command_id: command.command_id(),
            kind,
            text,
            run,
            state: CommandState::Sending,
            at_ms: now_ms,
        });
        Ok(Deliver::new(
            self.session.clone(),
            self.device.clone(),
            self.selector.clone(),
            command,
            wake,
        ))
    }

    fn selector(&self) -> StreamSelector {
        let runner = self.selector.runner();
        StreamSelector {
            runner_id: runner.id,
            runner_key_epoch: runner.key_epoch,
            stream: StreamKind::Chat(self.selector.chat_id()),
        }
    }
    fn material(
        &mut self,
        io: &mut ChatIo,
        purpose: Purpose,
        input: Input,
    ) -> Result<(), CloudDeviceError> {
        let collection = ChatMaterialRecord::collection_id(self.selector.scope())?;
        match (purpose, input) {
            (
                Purpose::MaterialKey,
                Input::CollectionKey {
                    wrapped_key,
                    granted_by,
                },
            ) => {
                if !granted_by.is_empty() {
                    return Err(CloudDeviceError::Binding);
                }
                io.issue(
                    Purpose::MaterialObject(wrapped_key),
                    Effect::GetObject {
                        collection_id: collection,
                        object_id: self.selector.object_id()?,
                    },
                );
                Ok(())
            }
            (Purpose::MaterialObject(wrapped), Input::Object(object)) => {
                let keys = self.session.keys();
                let key = CollectionKey::open(keys.account(), &collection, &wrapped)?;
                let view = StoredObject {
                    collection_id: &object.collection_id,
                    object_id: &object.object_id,
                    kind: &object.kind,
                    version: object.version,
                    deleted: object.deleted,
                    ciphertext: &object.ciphertext,
                };
                self.material = Some(ChatMaterialRecord::open(
                    &key,
                    self.selector.clone(),
                    &view,
                    keys.account(),
                )?);
                Ok(())
            }
            (_, Input::Failed(failure)) => Err(CloudDeviceError::Effect(failure)),
            _ => Err(CloudDeviceError::Protocol),
        }
    }
    fn probed(
        &mut self,
        input: Input,
        now_ms: i64,
    ) -> Result<Option<CloudDeviceError>, CloudDeviceError> {
        let mut probe = self.probe.take().ok_or(CloudDeviceError::Protocol)?;
        self.replay.wanted = true;
        match probe.answered(self.session.keys(), input, now_ms) {
            Ok(Some(HeadValue::Chat(head))) => {
                self.reader.witness(*head, now_ms)?;
                Ok(None)
            }
            Ok(Some(_)) => Err(CloudDeviceError::Protocol),
            Ok(None) => {
                self.reader.unanswered();
                Ok(None)
            }
            Err(error) => {
                self.reader.unanswered();
                Ok(Some(error))
            }
        }
    }
    /// One replay frame; a refusal ends the round and is reported.
    fn replayed(&mut self, io: &mut ChatIo, frame: Frame) -> Result<(), CloudDeviceError> {
        match frame {
            Frame::Header(header) => self.reader.record_header(&DeliveredRecord {
                publication_id: &header.publication_id,
                binding: &header.binding,
                total_bytes: header.total_bytes,
                ciphertext_sha256: &header.ciphertext_sha256,
                cursor: header.cursor,
                origin: DeliveredOrigin {
                    account_id: &header.origin_account_id,
                    signing_key: &header.origin_signing_key,
                    runner_id: header.origin_runner_id.as_deref(),
                },
            }),
            Frame::Data(bytes) => self.reader.record_data(&bytes),
            Frame::End { publication_id } => {
                let material = self.material.as_ref().ok_or(CloudDeviceError::Protocol)?;
                let key = material.open_key(self.session.keys().account())?;
                self.reader.record_end(&publication_id, &key).map(drop)
            }
            Frame::PageEnd {
                through_cursor,
                has_more,
            } => {
                self.replay.id = None;
                match self.reader.page_end(through_cursor, has_more)? {
                    RoundEnd::More => {
                        self.request_page(io, self.reader.cursor(), ChatReader::max_page_records());
                    }
                    RoundEnd::Complete(freshness) => self.round_done(io, freshness),
                }
                Ok(())
            }
            Frame::Gap {
                retained_from,
                snapshot_publication_id,
            } => {
                self.replay.id = None;
                let recovery = self.reader.gap(retained_from, &snapshot_publication_id)?;
                self.request_page(io, recovery.after_cursor, 1);
                Ok(())
            }
            Frame::Hint { .. } => Err(CloudDeviceError::Protocol),
        }
    }
    fn request_page(&mut self, io: &mut ChatIo, after_cursor: u64, max_records: u32) {
        let selector = self.selector();
        self.replay.id = Some(io.issue(
            Purpose::Replay,
            Effect::Replay {
                selector,
                after_cursor,
                max_records,
                max_bytes: REPLAY_PAGE_BYTES,
            },
        ));
    }
    fn round_done(&mut self, io: &mut ChatIo, freshness: Freshness) {
        self.report(io);
        if self.reported != Some(freshness) {
            self.reported = Some(freshness);
            io.output(ChatUpdate::Freshness(freshness));
        }
        if let Ok(checkpoint) = self.reader.checkpoint(&self.selector, self.session.keys()) {
            io.output(ChatUpdate::Checkpoint(checkpoint));
        }
        if self.watch.hinted > self.reader.cursor() {
            self.replay.wanted = true;
        }
    }
    fn refused(
        &mut self,
        io: &mut ChatIo,
        error: CloudDeviceError,
    ) -> Result<(), CloudDeviceError> {
        if matches!(
            error,
            CloudDeviceError::Rollback | CloudDeviceError::Protocol
        ) {
            return Err(error);
        }
        if let Some(id) = self.replay.id.take() {
            io.abandon(id);
        }
        self.reader.abandon();
        self.report(io);
        io.output(ChatUpdate::Refused(error));
        Ok(())
    }
    /// Hands out the transcript delta and any model grant a prompt of this device waits for.
    fn report(&mut self, io: &mut ChatIo) {
        let transcript = self.reader.transcript_mut();
        let Some(delta) = transcript.take_delta() else {
            return;
        };
        io.output(ChatUpdate::Transcript(delta));
        let transcript = self.reader.transcript();
        for pending in transcript.pending_commands() {
            if pending.kind != PendingKind::Prompt
                || pending.state != CommandState::Accepted
                || self.allowed.contains(&pending.command_id)
            {
                continue;
            }
            let Some(run) = transcript
                .runs()
                .iter()
                .find(|run| run.prompt_command == pending.command_id)
            else {
                continue;
            };
            if self.allowed.len() == MAX_ALLOWED {
                self.allowed.remove(0);
            }
            self.allowed.push(pending.command_id);
            if !run.finished()
                && matches!(
                    run.status,
                    CloudRunStatus::Queued | CloudRunStatus::NeedsGrant
                )
            {
                io.output(ChatUpdate::AllowRun { run: run.run });
            }
        }
    }
    fn watch_ended(&mut self, now_ms: i64) {
        self.watch.id = None;
        self.watch.retry_at = Some(now_ms.saturating_add(self.watch.delay));
        self.watch.delay = (self.watch.delay * 2).min(RETRY_MAX_MS);
    }
}

fn prompt_policy(
    transcript: &Transcript,
    model: Option<&ModelChoice>,
) -> Result<PromptPolicy, CloudDeviceError> {
    match model {
        Some(choice) if choice.provider == MANAGED_PROVIDER => PromptPolicy::managed(&choice.model),
        Some(choice) => PromptPolicy::own(&choice.provider, &choice.model),
        None => {
            let last = transcript.runs().last().ok_or(CloudDeviceError::NoModel)?;
            PromptPolicy::runner_default(last.model.clone())
        }
    }
}

impl Machine for Reading {
    type Purpose = Purpose;
    type Output = ChatUpdate;
    fn handle(
        &mut self,
        io: &mut ChatIo,
        purpose: Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError> {
        match (purpose, arrival) {
            (
                purpose @ (Purpose::MaterialKey | Purpose::MaterialObject(_)),
                Arrival::Input(input),
            ) => self.material(io, purpose, input),
            (Purpose::ProbeSign, Arrival::Input(input)) => {
                let probe = self.probe.as_mut().ok_or(CloudDeviceError::Protocol)?;
                match probe.signed(self.session.keys(), input) {
                    Ok(request) => {
                        io.issue(Purpose::Probe, Effect::Probe(request));
                        Ok(())
                    }
                    Err(error) => {
                        self.probe = None;
                        self.reader.unanswered();
                        self.replay.wanted = true;
                        self.refused(io, error)
                    }
                }
            }
            (Purpose::Probe, Arrival::Input(input)) => match self.probed(input, now_ms)? {
                Some(error) => self.refused(io, error),
                None => Ok(()),
            },
            (Purpose::Replay, Arrival::Frame(frame)) => match self.replayed(io, frame) {
                Ok(()) => Ok(()),
                Err(error) => self.refused(io, error),
            },
            (Purpose::Replay, Arrival::Input(input)) => {
                self.replay.id = None;
                self.reader.abandon();
                self.replay.wanted = true;
                self.replay.retry_at = Some(now_ms.saturating_add(RETRY_MIN_MS));
                match input {
                    Input::Failed(_) => Ok(()),
                    _ => Err(CloudDeviceError::Protocol),
                }
            }
            (Purpose::Watch, Arrival::Frame(Frame::Hint { head_cursor })) => {
                self.watch.delay = RETRY_MIN_MS;
                self.watch.hinted = self.watch.hinted.max(head_cursor);
                if head_cursor > self.reader.cursor() {
                    self.replay.wanted = true;
                }
                Ok(())
            }
            (Purpose::Watch, Arrival::Input(Input::Failed(_))) => {
                self.watch_ended(now_ms);
                Ok(())
            }
            _ => Err(CloudDeviceError::Protocol),
        }
    }
    fn tick(&mut self, io: &mut ChatIo, now_ms: i64) -> Result<Wait, CloudDeviceError> {
        self.report(io);
        let mut busy = false;
        if self.material.is_none()
            && !io.waiting(|p| matches!(p, Purpose::MaterialKey | Purpose::MaterialObject(_)))
        {
            let collection_id = ChatMaterialRecord::collection_id(self.selector.scope())?;
            io.issue(
                Purpose::MaterialKey,
                Effect::GetCollectionKey { collection_id },
            );
            busy = true;
        }
        if self.watch.id.is_none() && self.watch.retry_at.is_some_and(|at| now_ms >= at) {
            if std::mem::replace(&mut self.watch.started, true) {
                self.probe_wanted = true;
            }
            self.watch.retry_at = None;
            let selector = self.selector();
            self.watch.id = Some(io.issue(
                Purpose::Watch,
                Effect::Watch {
                    selector,
                    after_cursor: self.reader.cursor(),
                },
            ));
            busy = true;
        }
        if self.probe_wanted && self.probe.is_none() {
            self.probe_wanted = false;
            let runner = self.session.runner(&self.selector.runner().id)?;
            let target = ProbeTarget::Chat {
                chat_id: self.selector.chat_id(),
                key_epoch: self.selector.key_epoch(),
            };
            let (probe, request) =
                ProbeCall::start(&self.session, &self.device, runner, target, now_ms)?;
            self.probe = Some(probe);
            io.issue(Purpose::ProbeSign, Effect::Sign(request));
            busy = true;
        }
        let retry_due = self.replay.retry_at.is_none_or(|at| now_ms >= at);
        if self.replay.wanted
            && retry_due
            && self.replay.id.is_none()
            && self.material.is_some()
            && self.probe.is_none()
            && self.reader.idle()
        {
            self.replay.wanted = false;
            self.replay.retry_at = None;
            self.request_page(io, self.reader.cursor(), ChatReader::max_page_records());
            busy = true;
        }
        if busy {
            return Ok(Wait::Busy);
        }
        let until = [
            self.watch.retry_at,
            self.replay.retry_at.filter(|_| self.replay.wanted),
        ]
        .into_iter()
        .flatten()
        .min();
        Ok(Wait::Idle(until))
    }
}

#[cfg(test)]
mod tests;
