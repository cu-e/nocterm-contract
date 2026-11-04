//! The effect protocol between a device flow and the client that runs it (ADR 0007).
//!
//! A flow decides everything; the client only performs what it is asked and reports back:
//! 1. call [`Flow::next`] with the current time until it returns [`Step::Idle`], [`Step::Done`] or
//!    [`Step::Failed`]; start every [`Step::Effect`] it hands out (several may run at once) and
//!    handle every [`Step::Output`];
//! 2. answer each effect once with [`Flow::resolve`]; deliver the frames of a `Replay` or `Watch`
//!    effect with [`Flow::frame`] in arrival order (a replay's page end or gap frame completes
//!    it; a watch ends only with `resolve(id, Input::Failed(..))`);
//! 3. call `next` again after any answer, frame or once `Idle { until_ms }` has passed.
//!
//! Time and signatures come in as inputs; randomness is the operating system's, inside the
//! flows. A refused effect is reported as [`Input::Failed`] with an [`EffectFailure`], never as
//! text.
use crate::CloudDeviceError;
use crate::command::Publication;
use std::collections::VecDeque;

/// Identifies one effect of one flow.
pub type EffectId = u32;

/// Bytes the device key must sign (Ed25519, no prehash). Only this crate makes one, from the
/// canonical bytes of a head query or command header it built, so a client signing service that
/// accepts only these values ([`CloudSignable`]) is no generic signing oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    bytes: Vec<u8>,
    signer: [u8; 32],
}
impl SignRequest {
    pub(crate) fn new(bytes: Vec<u8>, signer: [u8; 32]) -> Self {
        Self { bytes, signer }
    }
    /// The exact bytes to sign.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The device key the bytes name; a signer with another key must refuse.
    pub fn signing_key(&self) -> [u8; 32] {
        self.signer
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::SignRequest {}
}
/// A value a device may sign. Implemented only by [`SignRequest`].
pub trait CloudSignable: sealed::Sealed {
    fn signing_message(&self) -> &[u8];
    fn signer(&self) -> [u8; 32];
}
impl CloudSignable for SignRequest {
    fn signing_message(&self) -> &[u8] {
        &self.bytes
    }
    fn signer(&self) -> [u8; 32] {
        self.signer
    }
}

/// `CloudSelector` of one stream of a runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSelector {
    pub runner_id: [u8; 16],
    pub runner_key_epoch: u64,
    pub stream: StreamKind,
}

/// `CloudSelector.stream`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    /// `inbox`: the runner's commands.
    Inbox,
    /// `chat_id`: the events and snapshots of one chat.
    Chat([u8; 16]),
    /// `directory` (capability bit 256): the runner's chat summaries.
    Directory,
}

/// `CloudService.ProbeHead` as plain fields. The client stops waiting at `expires_at_ms` and
/// answers `Failed(Unavailable)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeRequest {
    pub scope: Vec<u8>,
    pub probe_id: [u8; 16],
    pub ciphertext: Vec<u8>,
    pub expires_at_ms: i64,
}

/// What a flow asks the client to do.
#[derive(Clone, Debug)]
pub enum Effect {
    /// Sign with the device key; answer [`Input::Signature`].
    Sign(SignRequest),
    /// `StoreService.ListCollections { kind }` (all pages); answer [`Input::Collections`].
    ListCollections { kind: String },
    /// `StoreService.GetCollectionKey`; answer [`Input::CollectionKey`] or `Failed(NotFound)`.
    GetCollectionKey { collection_id: String },
    /// `StoreService.GetObject`; answer [`Input::Object`] or `Failed(NotFound)`.
    GetObject {
        collection_id: String,
        object_id: String,
    },
    /// `StoreService.PutObject` (compare-and-set); answer [`Input::Stored`] or
    /// `Failed(Conflict)` when the expected version is not the stored one.
    PutObject {
        collection_id: String,
        object_id: String,
        kind: String,
        expected_version: u64,
        ciphertext: Vec<u8>,
    },
    /// `StoreService.CreateCollection` of a personal collection with a client-chosen id;
    /// answer [`Input::Done`] or `Failed(AlreadyExists)`.
    CreateCollection {
        collection_id: String,
        kind: String,
        wrapped_key: Vec<u8>,
        sealed_name: Vec<u8>,
    },
    /// `CloudService.Capabilities { nonce }`; answer [`Input::Capabilities`].
    Capabilities { nonce: [u8; 16] },
    /// `CloudService.ProbeHead`; answer [`Input::ProbeReply`].
    Probe(ProbeRequest),
    /// `CloudService.Replay`; frames through [`Flow::frame`].
    Replay {
        selector: StreamSelector,
        after_cursor: u64,
        max_records: u32,
        max_bytes: u32,
    },
    /// `CloudService.Watch`; [`Frame::Hint`] frames until it ends.
    Watch {
        selector: StreamSelector,
        after_cursor: u64,
    },
    /// `CloudService.PublishOne` with exactly these bytes; answer [`Input::Receipt`].
    Publish(Publication),
    /// `AgentService.StartInstance { agent_id, pool_id, chat_id }`; answer [`Input::Instance`].
    /// The core asks only for a seat the agent already has: `pool_id` is the pool of an
    /// enrolled seat it found with [`Effect::ListInstances`] ([`crate::seat`]), never empty, so
    /// the call wakes that seat and never provisions one. Send the fields as they are.
    StartInstance {
        agent_id: String,
        pool_id: String,
        /// The chat id in lowercase hex.
        chat_id: Option<String>,
    },
    /// `AgentService.ListInstances` of the caller (all pages); answer [`Input::Instances`].
    ListInstances,
    /// `CloudService.RunnerStatus`; answer [`Input::RunnerStatus`].
    RunnerStatus { runner_id: [u8; 16] },
}

/// One listed collection (`StoreService.ListCollections`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionEntry {
    pub collection_id: String,
    pub kind: String,
    /// True for the account's own collection (no organization).
    pub personal: bool,
    pub deleted: bool,
}

/// One stored object (`StoreService.GetObject`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectEntry {
    pub collection_id: String,
    pub object_id: String,
    pub kind: String,
    pub version: u64,
    pub deleted: bool,
    pub ciphertext: Vec<u8>,
}

/// `Instance.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceState {
    Provisioning,
    AwaitingEnrolment,
    Ready,
    Suspended,
    Deleting,
    Failed,
    Unknown,
}

/// One seat (`AgentService` `Instance`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceEntry {
    pub instance_id: String,
    pub agent_id: String,
    /// `Instance.pool_id`: the pool the seat runs in.
    pub pool_id: String,
    /// The Cloud runner id, once the host created it.
    pub runner_id: Option<[u8; 16]>,
    pub state: InstanceState,
}

/// How an effect failed, as the client classifies the transport's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectFailure {
    /// `NOT_FOUND`.
    NotFound,
    /// `ALREADY_EXISTS`.
    AlreadyExists,
    /// A compare-and-set lost (`FAILED_PRECONDITION`, `ABORTED`).
    Conflict,
    /// Nothing was sent or the answer did not come in time (`UNAVAILABLE`, a deadline, a probe
    /// nobody answered).
    Unavailable,
    /// The request may have reached the hub, but no answer came (a broken connection after
    /// sending).
    Unknown,
    /// The hub refused it (`PERMISSION_DENIED`, `INVALID_ARGUMENT`, `RESOURCE_EXHAUSTED`,
    /// `UNIMPLEMENTED`, any other definitive refusal).
    Refused,
    /// A stream ended without an error (a watch the hub closed).
    Ended,
}

/// The answer to an effect.
#[derive(Clone, Debug)]
pub enum Input {
    Signature(Vec<u8>),
    Collections(Vec<CollectionEntry>),
    /// `GetCollectionKeyResponse`: the wrapped key and the granter (empty when personal).
    CollectionKey {
        wrapped_key: Vec<u8>,
        granted_by: String,
    },
    Object(ObjectEntry),
    Stored {
        version: u64,
    },
    Done,
    Capabilities {
        claim: Vec<u8>,
        signature: Vec<u8>,
    },
    ProbeReply {
        scope: Vec<u8>,
        probe_id: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    /// `CloudDeliveryReceipt`.
    Receipt {
        publication_id: Vec<u8>,
        cursor: u64,
        ciphertext_sha256: Vec<u8>,
    },
    Instance(InstanceEntry),
    Instances(Vec<InstanceEntry>),
    RunnerStatus {
        signed_status: Vec<u8>,
    },
    Failed(EffectFailure),
}

/// `CloudDeliveredRecord` as owned plain fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    pub publication_id: Vec<u8>,
    pub binding: Vec<u8>,
    pub total_bytes: u32,
    pub ciphertext_sha256: Vec<u8>,
    pub cursor: u64,
    pub origin_account_id: String,
    pub origin_signing_key: Vec<u8>,
    /// `issuer.runner_id`; `None` when the origin names a device.
    pub origin_runner_id: Option<Vec<u8>>,
}

/// One frame of a `Replay` (`CloudReplayFrame`) or `Watch` (`CloudHint`) stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Header(RecordHeader),
    Data(Vec<u8>),
    End {
        publication_id: Vec<u8>,
    },
    PageEnd {
        through_cursor: u64,
        has_more: bool,
    },
    Gap {
        retained_from: u64,
        snapshot_publication_id: Vec<u8>,
    },
    Hint {
        head_cursor: u64,
    },
}
impl Frame {
    fn ends_stream(&self) -> bool {
        matches!(self, Self::PageEnd { .. } | Self::Gap { .. })
    }
}

/// What a flow wants next.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "a step is moved to the client once; boxing every effect would buy nothing"
)]
pub enum Step<O> {
    Effect(EffectId, Effect),
    Output(O),
    /// Nothing to do until an answer or frame arrives, or until `until_ms` when set.
    Idle {
        until_ms: Option<i64>,
    },
    Done,
    Failed(CloudDeviceError),
}

/// A device flow.
pub trait Flow {
    type Output;
    fn next(&mut self, now_ms: i64) -> Step<Self::Output>;
    fn resolve(&mut self, id: EffectId, input: Input);
    fn frame(&mut self, id: EffectId, frame: Frame);
}

/// An answer or frame waiting to be handled.
#[derive(Debug)]
pub(crate) enum Arrival {
    Input(Input),
    Frame(Frame),
}

/// The effects, answers and outputs of one flow. `P` says what an effect was for.
#[derive(Debug)]
pub(crate) struct Io<P, O> {
    next_id: EffectId,
    queued: VecDeque<(EffectId, Effect)>,
    waiting: Vec<(EffectId, P)>,
    abandoned: Vec<EffectId>,
    arrived: VecDeque<(P, Arrival)>,
    outputs: VecDeque<O>,
    protocol: bool,
}
impl<P: Clone, O> Io<P, O> {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            queued: VecDeque::new(),
            waiting: Vec::new(),
            abandoned: Vec::new(),
            arrived: VecDeque::new(),
            outputs: VecDeque::new(),
            protocol: false,
        }
    }
    pub(crate) fn issue(&mut self, purpose: P, effect: Effect) -> EffectId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.queued.push_back((id, effect));
        self.waiting.push((id, purpose));
        id
    }
    pub(crate) fn output(&mut self, output: O) {
        self.outputs.push_back(output);
    }
    /// Forgets an effect whose answer no longer matters; its late answer and frames are ignored.
    pub(crate) fn abandon(&mut self, id: EffectId) {
        if let Some(index) = self.waiting.iter().position(|(known, _)| *known == id) {
            self.waiting.remove(index);
            self.abandoned.push(id);
        }
    }
    pub(crate) fn waiting(&self, matches: impl Fn(&P) -> bool) -> bool {
        self.waiting.iter().any(|(_, purpose)| matches(purpose))
    }
    pub(crate) fn resolve(&mut self, id: EffectId, input: Input) {
        if let Some(index) = self.waiting.iter().position(|(known, _)| *known == id) {
            let (_, purpose) = self.waiting.remove(index);
            self.arrived.push_back((purpose, Arrival::Input(input)));
        } else if let Some(index) = self.abandoned.iter().position(|known| *known == id) {
            self.abandoned.remove(index);
        } else {
            self.protocol = true;
        }
    }
    pub(crate) fn frame(&mut self, id: EffectId, frame: Frame) {
        if let Some(index) = self.waiting.iter().position(|(known, _)| *known == id) {
            let purpose = if frame.ends_stream() {
                self.waiting.remove(index).1
            } else {
                self.waiting[index].1.clone()
            };
            self.arrived.push_back((purpose, Arrival::Frame(frame)));
        } else if let Some(index) = self.abandoned.iter().position(|known| *known == id) {
            if frame.ends_stream() {
                self.abandoned.remove(index);
            }
        } else {
            self.protocol = true;
        }
    }
}

/// The decisions of one flow, driven by [`Driven`].
pub(crate) trait Machine {
    type Purpose: Clone;
    type Output;
    /// Handles one answer or frame of an effect issued for `purpose`.
    fn handle(
        &mut self,
        io: &mut Io<Self::Purpose, Self::Output>,
        purpose: Self::Purpose,
        arrival: Arrival,
        now_ms: i64,
    ) -> Result<(), CloudDeviceError>;
    /// Called when nothing waits to be handled: start work that is due, or say how long to wait.
    fn tick(
        &mut self,
        io: &mut Io<Self::Purpose, Self::Output>,
        now_ms: i64,
    ) -> Result<Wait, CloudDeviceError>;
}

/// What a machine's tick decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wait {
    /// Work was started; look again.
    Busy,
    Idle(Option<i64>),
    Done,
}

#[derive(Debug)]
enum Run {
    Running,
    Failed(Option<CloudDeviceError>),
    Done,
}

/// A machine with its effect bookkeeping: the [`Flow`] every public flow wraps.
#[derive(Debug)]
pub(crate) struct Driven<M: Machine> {
    machine: M,
    io: Io<M::Purpose, M::Output>,
    run: Run,
}
impl<M: Machine> Driven<M> {
    pub(crate) fn new(machine: M) -> Self {
        Self {
            machine,
            io: Io::new(),
            run: Run::Running,
        }
    }
    /// Runs `change` on the machine with its bookkeeping, as a client call outside `next`.
    pub(crate) fn with<T>(
        &mut self,
        change: impl FnOnce(&mut M, &mut Io<M::Purpose, M::Output>) -> T,
    ) -> T {
        change(&mut self.machine, &mut self.io)
    }
    pub(crate) fn machine(&self) -> &M {
        &self.machine
    }
    fn fail(&mut self, error: CloudDeviceError) -> Step<M::Output> {
        self.run = Run::Failed(None);
        Step::Failed(error)
    }
}
impl<M: Machine> Flow for Driven<M> {
    type Output = M::Output;
    fn next(&mut self, now_ms: i64) -> Step<M::Output> {
        loop {
            match &mut self.run {
                Run::Running => {}
                Run::Failed(error) => {
                    return error
                        .take()
                        .map_or(Step::Failed(CloudDeviceError::Ended), Step::Failed);
                }
                Run::Done => return Step::Done,
            }
            if std::mem::take(&mut self.io.protocol) {
                return self.fail(CloudDeviceError::Protocol);
            }
            if let Some((id, effect)) = self.io.queued.pop_front() {
                return Step::Effect(id, effect);
            }
            if let Some(output) = self.io.outputs.pop_front() {
                return Step::Output(output);
            }
            if let Some((purpose, arrival)) = self.io.arrived.pop_front() {
                if let Err(error) = self.machine.handle(&mut self.io, purpose, arrival, now_ms) {
                    return self.fail(error);
                }
                continue;
            }
            match self.machine.tick(&mut self.io, now_ms) {
                Ok(Wait::Busy) => {}
                Ok(Wait::Idle(until_ms)) => return Step::Idle { until_ms },
                Ok(Wait::Done) => {
                    if self.io.outputs.is_empty() && self.io.queued.is_empty() {
                        self.run = Run::Done;
                    }
                }
                Err(error) => return self.fail(error),
            }
        }
    }
    fn resolve(&mut self, id: EffectId, input: Input) {
        self.io.resolve(id, input);
    }
    fn frame(&mut self, id: EffectId, frame: Frame) {
        self.io.frame(id, frame);
    }
}
