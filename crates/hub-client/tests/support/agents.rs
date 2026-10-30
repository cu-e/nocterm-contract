//! A fake `AgentService`: a paged listing, compare-and-swap writes and a refusing seat.

#![allow(clippy::expect_used, dead_code)]

use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use nocterm_hub_grpc::agent_service_server::{AgentService, AgentServiceServer};
use nocterm_hub_grpc::metadata;
use nocterm_hub_model::agents::RefusalReason;
use nocterm_hub_proto::v1::{self, ErrorCode};
use prost::Message;
use tokio_stream::Stream;
use tonic::metadata::MetadataValue;
use tonic::{Request, Response, Status};

type Reply<T> = Result<Response<T>, Status>;
type Hints<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// What the fake agent service stores and what it refuses with.
#[derive(Default)]
pub struct AgentState {
    pub stored_version: Mutex<u64>,
    pub puts: Mutex<Vec<v1::PutAgentRequest>>,
    pub refusal: Mutex<Option<RefusalReason>>,
    pub listing: Mutex<Vec<v1::AgentListing>>,
}

pub struct AgentPeer(pub Arc<AgentState>);

pub fn service(state: Arc<AgentState>) -> AgentServiceServer<AgentPeer> {
    AgentServiceServer::new(AgentPeer(state))
}

fn unsupported<T>() -> Reply<T> {
    Err(Status::unimplemented("not part of this fake"))
}

#[tonic::async_trait]
impl AgentService for AgentPeer {
    async fn list_agents(&self, request: Request<v1::ListAgentsRequest>) -> Reply<v1::AgentList> {
        let all = self
            .0
            .listing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let after: usize = request.get_ref().after.parse().unwrap_or(0);
        let page: Vec<_> = all.iter().skip(after).take(2).cloned().collect();
        let next = if after + 2 < all.len() {
            (after + 2).to_string()
        } else {
            String::new()
        };
        Ok(Response::new(v1::AgentList { agents: page, next }))
    }
    type WatchAgentsStream = Hints<v1::AgentHint>;
    async fn watch_agents(
        &self,
        _: Request<v1::WatchAgentsRequest>,
    ) -> Reply<Self::WatchAgentsStream> {
        let hints = tokio_stream::iter([Ok(v1::AgentHint { revision: 7 })]);
        Ok(Response::new(Box::pin(hints)))
    }
    async fn get_agent(&self, _: Request<v1::AgentRef>) -> Reply<v1::AgentDetail> {
        unsupported()
    }
    async fn put_agent(&self, request: Request<v1::PutAgentRequest>) -> Reply<v1::AgentDetail> {
        let request = request.into_inner();
        let current = *self
            .0
            .stored_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if request.expected_version != current {
            let mut status = Status::aborted("version moved");
            status.metadata_mut().insert(
                metadata::ERROR_CODE,
                ErrorCode::Conflict.as_str_name().parse().expect("ascii"),
            );
            status.metadata_mut().insert(
                metadata::CURRENT_VERSION,
                current.to_string().parse().expect("ascii"),
            );
            return Err(status);
        }
        *self
            .0
            .stored_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = current + 1;
        let mut listing = request.listing.clone().unwrap_or_default();
        listing.version = current + 1;
        self.0
            .puts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request);
        Ok(Response::new(v1::AgentDetail {
            listing: Some(listing),
            ..Default::default()
        }))
    }
    async fn delete_agent(&self, _: Request<v1::DeleteAgentRequest>) -> Reply<v1::Empty> {
        unsupported()
    }
    async fn list_pools(&self, _: Request<v1::ListPoolsRequest>) -> Reply<v1::PoolList> {
        unsupported()
    }
    async fn get_pool_key(&self, _: Request<v1::PoolRef>) -> Reply<v1::PoolKeys> {
        Ok(Response::new(v1::PoolKeys {
            encryption_public_key: vec![1; 32],
            signing_public_key: vec![2; 32],
        }))
    }
    async fn start_instance(&self, _: Request<v1::StartInstanceRequest>) -> Reply<v1::Instance> {
        let reason = *self
            .0
            .refusal
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(reason) = reason else {
            return unsupported();
        };
        let mut status = Status::resource_exhausted("no seat");
        status.metadata_mut().insert_bin(
            metadata::REFUSAL,
            MetadataValue::from_bytes(&v1::Refusal::from(reason).encode_to_vec()),
        );
        Err(status)
    }
    async fn get_instance(&self, _: Request<v1::InstanceRef>) -> Reply<v1::Instance> {
        unsupported()
    }
    type WatchInstancesStream = Hints<v1::InstanceHint>;
    async fn watch_instances(
        &self,
        _: Request<v1::WatchInstancesRequest>,
    ) -> Reply<Self::WatchInstancesStream> {
        Err(Status::unimplemented("not part of this fake"))
    }
    async fn complete_enrolment(
        &self,
        _: Request<v1::CompleteEnrolmentRequest>,
    ) -> Reply<v1::Instance> {
        unsupported()
    }
    async fn suspend_instance(&self, _: Request<v1::InstanceRef>) -> Reply<v1::Instance> {
        unsupported()
    }
    async fn delete_instance(&self, _: Request<v1::InstanceRef>) -> Reply<v1::Empty> {
        unsupported()
    }
    async fn get_usage(&self, _: Request<v1::GetUsageRequest>) -> Reply<v1::UsageReport> {
        unsupported()
    }
    async fn list_access_grants(
        &self,
        _: Request<v1::ListAccessGrantsRequest>,
    ) -> Reply<v1::AccessGrantList> {
        unsupported()
    }
    async fn revoke_access_grant(
        &self,
        _: Request<v1::RevokeAccessGrantRequest>,
    ) -> Reply<v1::Empty> {
        unsupported()
    }
}
