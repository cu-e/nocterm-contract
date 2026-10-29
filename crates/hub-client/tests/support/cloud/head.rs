//! Bounded rendezvous in the existing scripted peer. This is not production
//! account authentication, journal heads or private server storage.
use super::super::lock;
use nocterm_hub_model::cloud::head::{
    HeadProbeScope, MAX_HEAD_PROBE_LIFETIME_MS, MAX_HEAD_PROBES_GLOBAL,
    MAX_HEAD_PROBES_PER_ACCOUNT, MAX_HEAD_QUERY_BYTES, MAX_HEAD_QUERY_ENVELOPE_BYTES,
    MAX_HEAD_REPLY_ENVELOPE_BYTES,
};
use nocterm_hub_proto::v1;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    sync::{Notify, oneshot},
    time::{Instant, timeout_at},
};
use tonic::Status;
type Key = (Vec<u8>, [u8; 16]);
struct Pending {
    scope: HeadProbeScope,
    wire: v1::CloudHeadProbe,
    assigned: bool,
    reply: Option<oneshot::Sender<v1::CloudHeadProbeReply>>,
    token: Arc<()>,
    deadline: Instant,
}
#[derive(Default)]
struct State {
    pending: BTreeMap<Key, Pending>,
    pollers: BTreeSet<Vec<u8>>,
}
#[derive(Clone, Default)]
pub(super) struct HeadLane {
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
}
impl HeadLane {
    pub(super) async fn wait_count(&self, count: usize) {
        loop {
            let changed = self.changed.notified();
            if lock(&self.state).pending.len() == count {
                return;
            }
            changed.await;
        }
    }
    pub(super) async fn submit(
        &self,
        wire: v1::CloudHeadProbe,
    ) -> Result<v1::CloudHeadProbeReply, Status> {
        check(
            &wire.scope,
            &wire.probe_id,
            &wire.ciphertext,
            MAX_HEAD_QUERY_ENVELOPE_BYTES,
        )?;
        let scope = HeadProbeScope::from_canonical_bytes(&wire.scope)
            .map_err(|_| Status::invalid_argument("scope"))?;
        let left = wire
            .expires_at_ms
            .checked_sub(nocterm_hub_client::now_ms())
            .filter(|n| *n > 0)
            .ok_or_else(|| Status::deadline_exceeded("probe"))?;
        let duration = u64::try_from(left.min(MAX_HEAD_PROBE_LIFETIME_MS))
            .map_err(|_| Status::invalid_argument("time"))?;
        let deadline = Instant::now() + Duration::from_millis(duration);
        let id = wire
            .probe_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("id"))?;
        let key = (wire.scope.clone(), id);
        let token = Arc::new(());
        let (tx, rx) = oneshot::channel();
        {
            let mut state = lock(&self.state);
            if state.pending.contains_key(&key) {
                return Err(Status::already_exists("pending probe"));
            }
            let account = state
                .pending
                .values()
                .filter(|entry| entry.scope.namespace == scope.namespace)
                .count();
            if state.pending.len() >= MAX_HEAD_PROBES_GLOBAL
                || account >= MAX_HEAD_PROBES_PER_ACCOUNT
            {
                return Err(Status::resource_exhausted("probe slots"));
            }
            state.pending.insert(
                key.clone(),
                Pending {
                    scope,
                    wire,
                    assigned: false,
                    reply: Some(tx),
                    token: token.clone(),
                    deadline,
                },
            );
        }
        let _lease = ProbeLease {
            state: Arc::downgrade(&self.state),
            changed: self.changed.clone(),
            key,
            token,
        };
        self.changed.notify_waiters();
        timeout_at(deadline, rx)
            .await
            .map_err(|_| Status::deadline_exceeded("probe"))?
            .map_err(|_| Status::cancelled("probe"))
    }
    pub(super) async fn next(
        &self,
        request: v1::CloudNextHeadProbe,
    ) -> Result<v1::CloudHeadProbeDelivery, Status> {
        if request.wait_millis > 10_000 || request.scope.len() > MAX_HEAD_QUERY_BYTES {
            return Err(Status::invalid_argument("poll"));
        }
        HeadProbeScope::from_canonical_bytes(&request.scope)
            .map_err(|_| Status::invalid_argument("scope"))?;
        {
            let mut state = lock(&self.state);
            if state.pollers.len() >= MAX_HEAD_PROBES_GLOBAL
                || !state.pollers.insert(request.scope.clone())
            {
                return Err(Status::resource_exhausted("poll slots"));
            }
        }
        let _poll = PollLease {
            state: Arc::downgrade(&self.state),
            scope: request.scope.clone(),
        };
        let deadline = Instant::now() + Duration::from_millis(u64::from(request.wait_millis));
        loop {
            let changed = self.changed.notified();
            {
                let mut state = lock(&self.state);
                if let Some(entry) = state.pending.values_mut().find(|entry| {
                    entry.wire.scope == request.scope
                        && !entry.assigned
                        && entry.deadline > Instant::now()
                }) {
                    entry.assigned = true;
                    return Ok(v1::CloudHeadProbeDelivery {
                        probe: Some(entry.wire.clone()),
                    });
                }
            }
            if timeout_at(deadline, changed).await.is_err() {
                return Ok(v1::CloudHeadProbeDelivery { probe: None });
            }
        }
    }
    pub(super) fn reply(
        &self,
        wire: v1::CloudHeadProbeReply,
    ) -> Result<v1::CloudHeadProbeReplied, Status> {
        check(
            &wire.scope,
            &wire.probe_id,
            &wire.ciphertext,
            MAX_HEAD_REPLY_ENVELOPE_BYTES,
        )?;
        let id = wire
            .probe_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("id"))?;
        let mut state = lock(&self.state);
        let entry = state
            .pending
            .get_mut(&(wire.scope.clone(), id))
            .ok_or_else(|| Status::not_found("probe"))?;
        if !entry.assigned || entry.deadline <= Instant::now() {
            return Err(Status::failed_precondition("inactive probe"));
        }
        let sender = entry
            .reply
            .take()
            .ok_or_else(|| Status::already_exists("answered probe"))?;
        Ok(v1::CloudHeadProbeReplied {
            delivered: sender.send(wire).is_ok(),
        })
    }
}
fn check(scope: &[u8], id: &[u8], ciphertext: &[u8], maximum: usize) -> Result<(), Status> {
    if scope.len() > MAX_HEAD_QUERY_BYTES
        || id.len() != 16
        || ciphertext.is_empty()
        || scope
            .len()
            .saturating_add(ciphertext.len())
            .saturating_add(128)
            > maximum
    {
        return Err(Status::invalid_argument("probe framing"));
    }
    Ok(())
}
struct ProbeLease {
    state: Weak<Mutex<State>>,
    changed: Arc<Notify>,
    key: Key,
    token: Arc<()>,
}
impl Drop for ProbeLease {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            let mut state = lock(&state);
            if state
                .pending
                .get(&self.key)
                .is_some_and(|entry| Arc::ptr_eq(&entry.token, &self.token))
            {
                state.pending.remove(&self.key);
            }
        }
        self.changed.notify_waiters();
    }
}
struct PollLease {
    state: Weak<Mutex<State>>,
    scope: Vec<u8>,
}
impl Drop for PollLease {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            lock(&state).pollers.remove(&self.scope);
        }
    }
}
