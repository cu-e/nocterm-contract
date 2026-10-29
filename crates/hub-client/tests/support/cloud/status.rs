//! Status reply controls on the existing actual h2c peer, not another server.
use super::{super::lock, CloudHarness};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, watch};
use tonic::Status;

pub(super) struct StatusLane {
    signed: Mutex<Vec<u8>>,
    held: watch::Sender<bool>,
    calls: AtomicUsize,
    entered: Notify,
}
impl Default for StatusLane {
    fn default() -> Self {
        Self {
            signed: Mutex::default(),
            held: watch::channel(false).0,
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
        }
    }
}
impl StatusLane {
    pub(super) async fn heartbeat(&self, signed: Vec<u8>) -> Result<(), Status> {
        *lock(&self.signed) = signed;
        self.pass().await
    }
    pub(super) async fn read(&self) -> Result<Vec<u8>, Status> {
        self.pass().await?;
        Ok(lock(&self.signed).clone())
    }
    async fn pass(&self) -> Result<(), Status> {
        let mut held = self.held.subscribe();
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.entered.notify_one();
        loop {
            let waiting = *held.borrow_and_update();
            if !waiting {
                break;
            }
            held.changed()
                .await
                .map_err(|_| Status::cancelled("fixture closed"))?;
        }
        Ok(())
    }
}
impl CloudHarness {
    pub fn hold_status_reply(&self) {
        self.status.held.send_replace(true);
    }
    pub fn release_status_reply(&self) {
        self.status.held.send_replace(false);
    }
    pub fn status_calls(&self) -> usize {
        self.status.calls.load(Ordering::Acquire)
    }
    pub async fn wait_status_after(&self, before: usize) {
        loop {
            let entered = self.status.entered.notified();
            if self.status_calls() > before {
                return;
            }
            entered.await;
        }
    }
    pub fn status_bytes(&self, bytes: Vec<u8>) {
        *lock(&self.status.signed) = bytes;
    }
}
