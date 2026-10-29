//! Reuses Cloud's scripted peer; validates real SDK runner proofs on the wire.
use super::{
    super::{HUB_ID, lock},
    CloudHarness,
};
use nocterm_hub_client::now_ms;
use nocterm_hub_model::cloud::{
    runner_auth::{RunnerProofClaim, RunnerProofKind, RunnerProofSubject},
    runner_request::{RunnerMethod, RunnerRequestClaim},
};
use nocterm_hub_proto::v1;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Notify;
use tonic::{Request, Status};

struct BoundRunner {
    subject: RunnerProofSubject,
    refresh: String,
    nonces: HashSet<[u8; 16]>,
    generation: u64,
}
#[derive(Default)]
pub(super) struct RunnerPeer {
    state: Mutex<Option<BoundRunner>>,
    hold: AtomicBool,
    started: Notify,
    release: Notify,
}
impl RunnerPeer {
    pub(super) fn head_scope(&self, bytes: &[u8]) -> Result<(), Status> {
        let scope = nocterm_hub_model::cloud::head::HeadProbeScope::from_canonical_bytes(bytes)
            .map_err(|_| Status::invalid_argument("scope"))?;
        let state = lock(&self.state);
        let runner = state
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("runner"))?;
        if scope.namespace != runner.subject.namespace
            || scope.runner.id != runner.subject.runner_id
        {
            return Err(Status::permission_denied("runner scope"));
        }
        Ok(())
    }
    pub(super) fn redeem(
        &self,
        wire: &v1::CloudRedeemRunnerGrant,
    ) -> Result<v1::CloudRunnerTokens, Status> {
        let claim = RunnerProofClaim::from_canonical_bytes(&wire.claim)
            .map_err(|_| Status::invalid_argument("claim"))?;
        let signature = wire
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("signature"))?;
        claim
            .verify(
                RunnerProofKind::Redeem,
                claim.subject(),
                &signature,
                now_ms(),
            )
            .map_err(|_| Status::unauthenticated("proof"))?;
        if claim.subject().raw_hub_id.as_str() != HUB_ID || claim.token() != "fixture-ticket" {
            return Err(Status::unauthenticated("ticket"));
        }
        let mut state = lock(&self.state);
        if state.is_some() {
            return Err(Status::already_exists("redeemed"));
        }
        let tokens = tokens(claim.subject(), 1);
        *state = Some(BoundRunner {
            subject: claim.subject().clone(),
            refresh: tokens.refresh_token.clone(),
            nonces: HashSet::new(),
            generation: 1,
        });
        Ok(tokens)
    }
    pub(super) async fn refresh(
        &self,
        wire: v1::CloudRefreshRunner,
    ) -> Result<v1::CloudRunnerTokens, Status> {
        let claim = RunnerProofClaim::from_canonical_bytes(&wire.claim)
            .map_err(|_| Status::invalid_argument("claim"))?;
        let signature = wire
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("signature"))?;
        let result = {
            let mut state = lock(&self.state);
            let state = state
                .as_mut()
                .ok_or_else(|| Status::unauthenticated("runner"))?;
            claim
                .verify(
                    RunnerProofKind::Refresh,
                    &state.subject,
                    &signature,
                    now_ms(),
                )
                .map_err(|_| Status::unauthenticated("proof"))?;
            if claim.token() != state.refresh || !state.nonces.insert(claim.nonce()) {
                return Err(Status::unauthenticated("rotation"));
            }
            state.generation += 1;
            let tokens = tokens(&state.subject, state.generation);
            state.refresh.clone_from(&tokens.refresh_token);
            tokens
        };
        self.started.notify_one();
        if self.hold.load(Ordering::Acquire) {
            self.release.notified().await;
        }
        Ok(result)
    }
    pub(super) fn authenticate<T>(
        &self,
        request: &Request<T>,
        method: RunnerMethod,
    ) -> Result<(), Status> {
        let header = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("token"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| Status::unauthenticated("token"))?;
        let bytes = request
            .metadata()
            .get_bin("x-nocterm-runner-claim-bin")
            .ok_or_else(|| Status::unauthenticated("claim"))?
            .to_bytes()
            .map_err(|_| Status::unauthenticated("claim"))?;
        let signature = request
            .metadata()
            .get_bin("x-nocterm-runner-proof-bin")
            .ok_or_else(|| Status::unauthenticated("proof"))?
            .to_bytes()
            .map_err(|_| Status::unauthenticated("proof"))?;
        let signature = signature
            .as_ref()
            .try_into()
            .map_err(|_| Status::unauthenticated("proof"))?;
        let claim = RunnerRequestClaim::from_canonical_bytes(&bytes)
            .map_err(|_| Status::unauthenticated("claim"))?;
        let mut state = lock(&self.state);
        let state = state
            .as_mut()
            .ok_or_else(|| Status::unauthenticated("runner"))?;
        if token != format!("runner-access-{}", state.generation) {
            return Err(Status::unauthenticated("token"));
        }
        let digest = Sha256::digest(token.as_bytes()).into();
        claim
            .verify(&state.subject, method, &digest, &signature, now_ms())
            .map_err(|_| Status::unauthenticated("proof"))?;
        if !state.nonces.insert(claim.nonce()) {
            return Err(Status::unauthenticated("replay"));
        }
        Ok(())
    }
    pub(super) fn hold(&self) {
        self.hold.store(true, Ordering::Release);
    }
    pub(super) async fn wait(&self) {
        self.started.notified().await;
    }
    pub(super) fn release(&self) {
        self.release.notify_one();
    }
}
fn tokens(subject: &RunnerProofSubject, generation: u64) -> v1::CloudRunnerTokens {
    v1::CloudRunnerTokens {
        account_id: subject.namespace.account_id.as_str().into(),
        runner_id: subject.runner_id.to_vec(),
        access_token: format!("runner-access-{generation}"),
        access_expires_at_ms: now_ms() + 300_000,
        refresh_token: format!("runner-refresh-{generation}"),
        refresh_expires_at_ms: now_ms() + 900_000,
        capability_version: 1,
    }
}
impl CloudHarness {
    pub fn hold_runner_refresh(&self) {
        self.runner.hold();
    }
    pub async fn wait_runner_refresh(&self) {
        self.runner.wait().await;
    }
    pub fn release_runner_refresh(&self) {
        self.runner.release();
    }
}
