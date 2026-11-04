//! A scripted client for the flow tests: it answers every effect from in-memory Store objects,
//! a runner that witnesses heads with the world's real keys, a chat stream and a publish log.
use super::{ACCOUNT, NOW, World};
use crate::{
    CloudDeviceError,
    command::Publication,
    flow::{
        CollectionEntry, Effect, EffectFailure, EffectId, Flow, Frame, Input, InstanceEntry,
        ObjectEntry, RecordHeader, Step, StreamKind,
    },
    records::ChatSelector,
};
use nocterm_hub_model::cloud::{
    RecordContext, RecordKind, RecordPosition, RunCoordinate,
    events::CloudEvent,
    head::{
        CatalogHeadPage, ChatHead, HeadProbeScope, HeadRecordAnchor, HeadTarget, HeadValue,
        HeadWitness, ReceiptOutcome,
    },
    relay::RelayBinding,
    summary::{ChatSummary, SummaryContext},
};
use nocterm_keys::{
    CollectionKey,
    cloud::{ChatKey, open_head_query, seal_event, seal_head_witness, seal_summary},
};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

/// How a run of the scripted client ended.
#[derive(Debug)]
pub(crate) enum Ended {
    Idle(Option<i64>),
    Done,
    Failed(CloudDeviceError),
}

/// One record of the chat stream.
pub(crate) struct Stored {
    pub(crate) header: RecordHeader,
    pub(crate) data: Vec<u8>,
    pub(crate) anchor: HeadRecordAnchor,
}

pub(crate) struct FakeHub {
    pub(crate) world: World,
    pub(crate) collections: Vec<(CollectionEntry, Vec<u8>)>,
    pub(crate) objects: Vec<ObjectEntry>,
    pub(crate) chat: Vec<Stored>,
    /// What the runner witnesses for a chat probe; `None` is a sleeping runner.
    pub(crate) awake: bool,
    pub(crate) receipt: ReceiptOutcome,
    pub(crate) publish: VecDeque<Input>,
    pub(crate) published: Vec<Publication>,
    pub(crate) instances: Vec<InstanceEntry>,
    pub(crate) status: Option<Vec<u8>>,
    pub(crate) watches: Vec<EffectId>,
    pub(crate) effects: Vec<&'static str>,
    /// Trailing records the hub hides from replay (a withholding hub).
    pub(crate) hidden: usize,
    /// The `after_cursor` of every replay request.
    pub(crate) replayed_from: Vec<u64>,
    /// The runner directory stream: sealed summaries at their (holed) cursors.
    pub(crate) directory: Vec<(RecordHeader, Vec<u8>)>,
    /// The `after_cursor` of every directory replay request.
    pub(crate) directory_from: Vec<u64>,
    /// What a catalog probe witnesses instead of the world chat's head.
    pub(crate) catalog: Option<Vec<ChatHead>>,
}
impl FakeHub {
    pub(crate) fn new(world: World) -> Self {
        Self {
            world,
            collections: Vec::new(),
            objects: Vec::new(),
            chat: Vec::new(),
            awake: true,
            receipt: ReceiptOutcome::NotFound,
            publish: VecDeque::new(),
            published: Vec::new(),
            instances: Vec::new(),
            status: None,
            watches: Vec::new(),
            effects: Vec::new(),
            hidden: 0,
            replayed_from: Vec::new(),
            directory: Vec::new(),
            directory_from: Vec::new(),
            catalog: None,
        }
    }
    /// Publishes `summary` of `chat_id` (the world chat's runner and key epoch) at `revision`
    /// to the directory at `cursor`, signed and sealed with the world's runner keys.
    pub(crate) fn summary(
        &mut self,
        cursor: u64,
        chat_id: [u8; 16],
        revision: u64,
        summary: &ChatSummary,
    ) {
        let chat = self.world.selector.coordinate().unwrap();
        let chat = nocterm_hub_model::cloud::ChatCoordinate::new(
            chat.namespace().clone(),
            chat.runner(),
            chat_id,
            chat.key_epoch(),
        )
        .unwrap();
        let context = SummaryContext::new(chat, revision).unwrap();
        let signed = self
            .world
            .runner_signer
            .attest_summary(context.clone(), summary.clone())
            .unwrap();
        let sealed = seal_summary(
            &self.world.runner_key,
            &self.world.account_pair.public_key(),
            &signed,
        )
        .unwrap();
        self.directory_record(cursor, &context, sealed);
    }
    /// Stores `sealed` as the directory record at `cursor`, routed under `context`.
    pub(crate) fn directory_record(
        &mut self,
        cursor: u64,
        context: &SummaryContext,
        sealed: Vec<u8>,
    ) {
        let header = RecordHeader {
            publication_id: context.publication_id().unwrap().to_vec(),
            binding: RelayBinding::summary(context.clone())
                .canonical_bytes()
                .unwrap(),
            total_bytes: u32::try_from(sealed.len()).unwrap(),
            ciphertext_sha256: Sha256::digest(&sealed).to_vec(),
            cursor,
            origin_account_id: ACCOUNT.to_owned(),
            origin_signing_key: self.world.runner.pins().proof.to_vec(),
            origin_runner_id: Some(self.world.runner.runner().id.to_vec()),
        };
        self.directory.retain(|(held, _)| held.cursor != cursor);
        self.directory.push((header, sealed));
        self.directory.sort_by_key(|(header, _)| header.cursor);
    }
    /// A personal collection of `kind` whose key is wrapped for the world's account.
    pub(crate) fn collection(&mut self, id: &str, kind: &str) -> CollectionKey {
        let key = CollectionKey::generate().unwrap();
        let wrapped = key.seal_for(&self.world.account, id).unwrap();
        self.collections.push((
            CollectionEntry {
                collection_id: id.to_owned(),
                kind: kind.to_owned(),
                personal: true,
                deleted: false,
            },
            wrapped,
        ));
        key
    }
    pub(crate) fn object(
        &mut self,
        collection: &str,
        object: &str,
        kind: &str,
        ciphertext: Vec<u8>,
    ) {
        self.objects.push(ObjectEntry {
            collection_id: collection.to_owned(),
            object_id: object.to_owned(),
            kind: kind.to_owned(),
            version: 1,
            deleted: false,
            ciphertext,
        });
    }
    /// Appends one runner event of `selector` at the next sequence.
    pub(crate) fn event(
        &mut self,
        selector: &ChatSelector,
        key: &ChatKey,
        event: &CloudEvent<'_>,
        run: Option<RunCoordinate>,
    ) {
        let sequence = self.chat.len() as u64 + 1;
        let context = RecordContext::new(
            selector.coordinate().unwrap(),
            RecordPosition {
                writer_epoch: 1,
                sequence,
                journal_sequence: sequence,
                revision: sequence,
            },
            [u8::try_from(sequence).unwrap(); 16],
            run,
        )
        .unwrap();
        let body = event.canonical_bytes().unwrap();
        let sealed = seal_event(key, &self.world.runner_signer, context.clone(), &body).unwrap();
        let digest: [u8; 32] = Sha256::digest(&sealed).into();
        self.chat.push(Stored {
            header: RecordHeader {
                publication_id: vec![0xa0 + u8::try_from(sequence).unwrap(); 16],
                binding: RelayBinding::event(context.clone())
                    .canonical_bytes()
                    .unwrap(),
                total_bytes: u32::try_from(sealed.len()).unwrap(),
                ciphertext_sha256: digest.to_vec(),
                cursor: sequence,
                origin_account_id: ACCOUNT.to_owned(),
                origin_signing_key: self.world.runner.pins().proof.to_vec(),
                origin_runner_id: Some(self.world.runner.runner().id.to_vec()),
            },
            data: sealed,
            anchor: HeadRecordAnchor {
                kind: RecordKind::Event,
                position: context.position(),
                id: context.id(),
                run: context.run(),
                ciphertext_digest: digest,
            },
        });
    }
    pub(crate) fn head(&self) -> ChatHead {
        ChatHead {
            chat_id: self.world.selector.chat_id(),
            chat_key_epoch: self.world.selector.key_epoch(),
            current_writer: Some(1),
            control_revision: self.chat.len() as u64,
            deleted: false,
            head: self.chat.last().map(|record| record.anchor.clone()),
            retained_from: u64::from(!self.chat.is_empty()),
            snapshot: None,
        }
    }

    /// Drives `flow` at `now` until it waits, ends or fails; returns its outputs.
    pub(crate) fn run<F: Flow>(&mut self, flow: &mut F, now: i64) -> (Vec<F::Output>, Ended) {
        let mut outputs = Vec::new();
        loop {
            match flow.next(now) {
                Step::Effect(id, effect) => self.answer(flow, id, effect, now),
                Step::Output(output) => outputs.push(output),
                Step::Idle { until_ms } => return (outputs, Ended::Idle(until_ms)),
                Step::Done => return (outputs, Ended::Done),
                Step::Failed(error) => return (outputs, Ended::Failed(error)),
            }
        }
    }
    /// Sends a Watch hint for the stream's current head to every open watch.
    pub(crate) fn hint<F: Flow>(&mut self, flow: &mut F) {
        for id in self.watches.clone() {
            flow.frame(
                id,
                Frame::Hint {
                    head_cursor: self.chat.len() as u64,
                },
            );
        }
    }

    /// Sends a Watch hint for the directory's newest cursor to every open watch.
    pub(crate) fn hint_directory<F: Flow>(&mut self, flow: &mut F) {
        let head_cursor = self.directory.last().map_or(0, |(header, _)| header.cursor);
        for id in self.watches.clone() {
            flow.frame(id, Frame::Hint { head_cursor });
        }
    }

    fn answer<F: Flow>(&mut self, flow: &mut F, id: EffectId, effect: Effect, now: i64) {
        let input = match effect {
            Effect::Replay {
                selector,
                after_cursor,
                max_records,
                ..
            } if selector.stream == StreamKind::Directory => {
                self.effects.push("directory_replay");
                self.directory_replay(flow, id, after_cursor, max_records);
                return;
            }
            Effect::Replay {
                after_cursor,
                max_records,
                ..
            } => {
                self.effects.push("replay");
                self.replay(flow, id, after_cursor, max_records);
                return;
            }
            Effect::Watch { .. } => {
                self.effects.push("watch");
                self.watches.push(id);
                return;
            }
            Effect::ListCollections { .. }
            | Effect::GetCollectionKey { .. }
            | Effect::GetObject { .. }
            | Effect::PutObject { .. }
            | Effect::CreateCollection { .. } => self.store(effect),
            effect => self.cloud(effect, now),
        };
        flow.resolve(id, input);
    }
    fn store(&mut self, effect: Effect) -> Input {
        match effect {
            Effect::ListCollections { kind } => {
                self.effects.push("list_collections");
                Input::Collections(
                    self.collections
                        .iter()
                        .filter(|(entry, _)| entry.kind == kind)
                        .map(|(entry, _)| entry.clone())
                        .collect(),
                )
            }
            Effect::GetCollectionKey { collection_id } => {
                self.effects.push("get_collection_key");
                self.collections
                    .iter()
                    .find(|(entry, _)| entry.collection_id == collection_id)
                    .map_or(Input::Failed(EffectFailure::NotFound), |(_, wrapped)| {
                        Input::CollectionKey {
                            wrapped_key: wrapped.clone(),
                            granted_by: String::new(),
                        }
                    })
            }
            Effect::GetObject {
                collection_id,
                object_id,
            } => {
                self.effects.push("get_object");
                self.objects
                    .iter()
                    .find(|o| o.collection_id == collection_id && o.object_id == object_id)
                    .map_or(Input::Failed(EffectFailure::NotFound), |o| {
                        Input::Object(o.clone())
                    })
            }
            Effect::PutObject {
                collection_id,
                object_id,
                kind,
                expected_version,
                ciphertext,
            } => {
                self.effects.push("put_object");
                let current = self
                    .objects
                    .iter()
                    .find(|o| o.collection_id == collection_id && o.object_id == object_id)
                    .map_or(0, |o| o.version);
                if current == expected_version {
                    self.objects.retain(|o| {
                        !(o.collection_id == collection_id && o.object_id == object_id)
                    });
                    self.objects.push(ObjectEntry {
                        collection_id,
                        object_id,
                        kind,
                        version: current + 1,
                        deleted: false,
                        ciphertext,
                    });
                    Input::Stored {
                        version: current + 1,
                    }
                } else {
                    Input::Failed(EffectFailure::Conflict)
                }
            }
            Effect::CreateCollection {
                collection_id,
                kind,
                wrapped_key,
                ..
            } => {
                self.effects.push("create_collection");
                if self
                    .collections
                    .iter()
                    .any(|(e, _)| e.collection_id == collection_id)
                {
                    Input::Failed(EffectFailure::AlreadyExists)
                } else {
                    self.collections.push((
                        CollectionEntry {
                            collection_id,
                            kind,
                            personal: true,
                            deleted: false,
                        },
                        wrapped_key,
                    ));
                    Input::Done
                }
            }
            _ => unreachable!("a Store effect"),
        }
    }
    fn cloud(&mut self, effect: Effect, now: i64) -> Input {
        match effect {
            Effect::Sign(request) => {
                self.effects.push("sign");
                assert_eq!(request.signing_key(), self.world.device_key.public_key());
                Input::Signature(self.world.device_key.sign(request.bytes()).to_vec())
            }
            Effect::Capabilities { nonce } => {
                self.effects.push("capabilities");
                let (claim, signature) =
                    super::capability_proof(&self.world.authority, super::ALL_FEATURES, nonce, NOW);
                Input::Capabilities { claim, signature }
            }
            Effect::Probe(request) => {
                self.effects.push("probe");
                self.probe(&request.scope, request.probe_id, &request.ciphertext, now)
            }
            Effect::Publish(publication) => {
                self.effects.push("publish");
                self.published.push(publication.clone());
                self.publish.pop_front().unwrap_or_else(|| Input::Receipt {
                    publication_id: publication.publication_id().to_vec(),
                    cursor: self.published.len() as u64,
                    ciphertext_sha256: publication.ciphertext_sha256().to_vec(),
                })
            }
            Effect::StartInstance { agent_id, .. } => {
                self.effects.push("start_instance");
                self.instances
                    .iter()
                    .find(|seat| seat.agent_id == agent_id)
                    .map_or(Input::Failed(EffectFailure::NotFound), |seat| {
                        Input::Instance(seat.clone())
                    })
            }
            Effect::ListInstances => {
                self.effects.push("list_instances");
                Input::Instances(self.instances.clone())
            }
            Effect::RunnerStatus { .. } => {
                self.effects.push("runner_status");
                self.status
                    .clone()
                    .map_or(Input::Failed(EffectFailure::NotFound), |signed_status| {
                        Input::RunnerStatus { signed_status }
                    })
            }
            _ => unreachable!("a Cloud or Agent effect"),
        }
    }
    fn probe(&self, scope: &[u8], probe_id: [u8; 16], ciphertext: &[u8], now: i64) -> Input {
        if !self.awake {
            return Input::Failed(EffectFailure::Unavailable);
        }
        let parsed = HeadProbeScope::from_canonical_bytes(scope).unwrap();
        let query = open_head_query(&self.world.runner_key, &parsed, probe_id, ciphertext, now)
            .unwrap()
            .query()
            .clone();
        let value = match &query.target {
            HeadTarget::Catalog { after } => HeadValue::Catalog(Box::new(CatalogHeadPage {
                revision: 1,
                digest: [0x77; 32],
                total_chats: u32::try_from(self.catalog.as_ref().map_or(1, Vec::len)).unwrap(),
                after: after.clone(),
                chats: self.catalog.clone().unwrap_or_else(|| vec![self.head()]),
                has_more: false,
            })),
            HeadTarget::Chat {
                chat_id,
                chat_key_epoch,
            } if (*chat_id, *chat_key_epoch)
                != (
                    self.world.selector.chat_id(),
                    self.world.selector.key_epoch(),
                ) =>
            {
                HeadValue::Chat(Box::new(ChatHead {
                    chat_id: *chat_id,
                    chat_key_epoch: *chat_key_epoch,
                    current_writer: Some(1),
                    control_revision: 0,
                    deleted: false,
                    head: None,
                    retained_from: 0,
                    snapshot: None,
                }))
            }
            HeadTarget::Chat { .. } => HeadValue::Chat(Box::new(self.head())),
            HeadTarget::CommandReceipt { .. } => HeadValue::CommandReceipt(self.receipt),
        };
        let witness = self
            .world
            .runner_signer
            .attest_head(HeadWitness {
                query,
                observed_at_ms: now,
                value,
            })
            .unwrap();
        Input::ProbeReply {
            scope: scope.to_vec(),
            probe_id: probe_id.to_vec(),
            ciphertext: seal_head_witness(&self.world.runner_key, &witness).unwrap(),
        }
    }
    fn directory_replay<F: Flow>(&mut self, flow: &mut F, id: EffectId, after: u64, max: u32) {
        self.directory_from.push(after);
        let mut through = after;
        let page: Vec<_> = self
            .directory
            .iter()
            .filter(|(header, _)| header.cursor > after)
            .take(max as usize)
            .cloned()
            .collect();
        for (header, data) in page {
            flow.frame(id, Frame::Header(header.clone()));
            flow.frame(id, Frame::Data(data));
            flow.frame(
                id,
                Frame::End {
                    publication_id: header.publication_id.clone(),
                },
            );
            through = header.cursor;
        }
        let has_more = self
            .directory
            .iter()
            .any(|(header, _)| header.cursor > through);
        flow.frame(
            id,
            Frame::PageEnd {
                through_cursor: through,
                has_more,
            },
        );
    }
    fn replay<F: Flow>(&mut self, flow: &mut F, id: EffectId, after: u64, max: u32) {
        self.replayed_from.push(after);
        let mut through = after;
        let visible = self.chat.len() - self.hidden;
        let page: Vec<&Stored> = self.chat[..visible]
            .iter()
            .filter(|record| record.header.cursor > after)
            .take(max as usize)
            .collect();
        for record in &page {
            flow.frame(id, Frame::Header(record.header.clone()));
            flow.frame(id, Frame::Data(record.data.clone()));
            flow.frame(
                id,
                Frame::End {
                    publication_id: record.header.publication_id.clone(),
                },
            );
            through = record.header.cursor;
        }
        let has_more = self.chat[..visible]
            .iter()
            .any(|record| record.header.cursor > through);
        flow.frame(
            id,
            Frame::PageEnd {
                through_cursor: through,
                has_more,
            },
        );
    }
}
