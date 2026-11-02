//! Typed client of `AgentService`: agent listings and sealed definitions, pools, instances,
//! usage and access grants.
//!
//! A hub that lacks the service answers `UNIMPLEMENTED`, which every call reports as
//! [`AgentError::Unsupported`] so a client hides its Cloud agents tab instead of failing.

mod error;
mod setup;
mod versions;

use nocterm_hub_grpc::agent_service_client::AgentServiceClient;
use nocterm_hub_model::agents::{
    AgentListing, AgentScope, CHAT_ID_BYTES, PoolKeys, ProviderProbe, chat_id_to_wire, limits,
};
use nocterm_hub_model::{AgentId, InstanceId, PoolId};
use nocterm_hub_proto::{org_name_from_wire, v1};
use tonic::Streaming;

pub use error::AgentError;
pub use setup::{SetupError, VerifiedSetup, verify_instance_setup};
pub use versions::{AgentVersion, AgentVersionPage};

use crate::{HubClient, Signed};

/// Pages a full listing may span before the client gives up on a runaway hub.
const MAX_PAGES: usize = 64;
/// Largest message the client accepts (a page of detailed listings).
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// A definition sealed for one pool, as sent in [`AgentClient::put_agent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolEnvelope {
    /// The pool whose encryption key the envelope was sealed to.
    pub pool: PoolId,
    /// Output of `nocterm_keys::agents::seal_definition`.
    pub envelope: Vec<u8>,
}

/// A listing with the display name of its organization, as the hub sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedAgent {
    /// The listing.
    pub listing: AgentListing,
    /// Display name of the owning organization; `None` outside an organization scope, from a
    /// hub that does not send names, or when the name exceeds
    /// [`limits::MAX_ORG_NAME_BYTES`].
    pub org_name: Option<String>,
}

/// Lossy change hints of the agent list or of instances. A hint means "list again".
#[derive(Debug)]
pub struct AgentHints {
    stream: Streaming<v1::AgentHint>,
}

impl AgentHints {
    /// Waits for the next revision; `None` when the hub ended the stream (resubscribe).
    pub async fn next(&mut self) -> Result<Option<u64>, AgentError> {
        Ok(self.stream.message().await?.map(|hint| hint.revision))
    }
}

/// Lossy change hints of the caller's instances.
#[derive(Debug)]
pub struct InstanceHints {
    stream: Streaming<v1::InstanceHint>,
}

impl InstanceHints {
    /// Waits for the next hint; `None` when the hub ended the stream.
    pub async fn next(&mut self) -> Result<Option<v1::InstanceHint>, AgentError> {
        Ok(self.stream.message().await?)
    }
}

/// The agents API of one signed-in hub connection.
#[derive(Debug, Clone)]
pub struct AgentClient {
    client: HubClient,
}

impl HubClient {
    /// The agents API; every call is signed like any other authenticated call.
    pub fn agents(&self) -> AgentClient {
        AgentClient {
            client: self.clone(),
        }
    }
}

impl AgentClient {
    fn rpc(&self) -> AgentServiceClient<Signed> {
        AgentServiceClient::new(self.client.signed()).max_decoding_message_size(MAX_MESSAGE_BYTES)
    }

    /// Every agent the account may see, optionally in one scope, with its availability.
    pub async fn list_agents(
        &self,
        scope: Option<AgentScope>,
    ) -> Result<Vec<AgentListing>, AgentError> {
        Ok(self
            .list_agents_with_org_names(scope)
            .await?
            .into_iter()
            .map(|agent| agent.listing)
            .collect())
    }

    /// Like [`AgentClient::list_agents`], with the display name of each listing's
    /// organization when the hub sends one.
    pub async fn list_agents_with_org_names(
        &self,
        scope: Option<AgentScope>,
    ) -> Result<Vec<ListedAgent>, AgentError> {
        let mut agents = Vec::new();
        let mut after = String::new();
        for _ in 0..MAX_PAGES {
            let page = self
                .rpc()
                .list_agents(v1::ListAgentsRequest {
                    scope: scope.map(Into::into),
                    after: after.clone(),
                    limit: 0,
                })
                .await?
                .into_inner();
            for wire in &page.agents {
                agents.push(ListedAgent {
                    listing: AgentListing::try_from(wire)?,
                    org_name: org_name_from_wire(wire),
                });
            }
            if page.next.is_empty() {
                return Ok(agents);
            }
            after = page.next;
        }
        Err(AgentError::TooManyPages)
    }

    /// Subscribes to lossy change hints; list again on each one.
    pub async fn watch_agents(&self) -> Result<AgentHints, AgentError> {
        let stream = self
            .rpc()
            .watch_agents(v1::WatchAgentsRequest {})
            .await?
            .into_inner();
        Ok(AgentHints { stream })
    }

    /// One agent with the sealed envelopes the caller may see.
    pub async fn get_agent(&self, agent: AgentId) -> Result<v1::AgentDetail, AgentError> {
        Ok(self
            .rpc()
            .get_agent(v1::AgentRef {
                agent_id: agent.to_string(),
            })
            .await?
            .into_inner())
    }

    /// Creates (`expected_version == 0`) or replaces an agent with one sealed envelope per pool.
    ///
    /// Checks the listing and envelope bounds locally first. A stale `expected_version` is
    /// [`AgentError::Conflict`] with the current version.
    pub async fn put_agent(
        &self,
        listing: &AgentListing,
        envelopes: Vec<PoolEnvelope>,
        expected_version: u64,
    ) -> Result<v1::AgentDetail, AgentError> {
        listing.validate()?;
        if envelopes.len() > limits::MAX_ENVELOPES_PER_AGENT {
            return Err(AgentError::EnvelopeLimit);
        }
        if envelopes
            .iter()
            .any(|e| e.envelope.is_empty() || e.envelope.len() > limits::MAX_ENVELOPE_BYTES)
        {
            return Err(AgentError::EnvelopeLimit);
        }
        let envelopes = envelopes
            .into_iter()
            .map(|e| v1::SealedDefinition {
                pool_id: e.pool.to_string(),
                envelope: e.envelope,
                ..v1::SealedDefinition::default()
            })
            .collect();
        Ok(self
            .rpc()
            .put_agent(v1::PutAgentRequest {
                listing: Some(listing.into()),
                envelopes,
                expected_version,
            })
            .await?
            .into_inner())
    }

    /// Deletes an agent whose current version is `expected_version`.
    pub async fn delete_agent(
        &self,
        agent: AgentId,
        expected_version: u64,
    ) -> Result<(), AgentError> {
        self.rpc()
            .delete_agent(v1::DeleteAgentRequest {
                agent_id: agent.to_string(),
                expected_version,
            })
            .await?;
        Ok(())
    }

    /// One page of the versions of an agent's public listing, newest first. Pass `after` as
    /// the previous page's [`AgentVersionPage::next`]; `limit` is clamped to
    /// [`limits::MAX_PAGE_ENTRIES`] and zero asks for the hub's default. A hub that keeps no
    /// history returns the current version only.
    pub async fn list_agent_versions(
        &self,
        agent: AgentId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<AgentVersionPage, AgentError> {
        let after = after.unwrap_or_default();
        if after.len() > versions::MAX_CURSOR_BYTES {
            return Err(AgentError::EnvelopeLimit);
        }
        let max = u32::try_from(limits::MAX_PAGE_ENTRIES).unwrap_or(u32::MAX);
        let page = self
            .rpc()
            .list_agent_versions(v1::ListAgentVersionsRequest {
                agent_id: agent.to_string(),
                after: after.to_owned(),
                limit: limit.min(max),
            })
            .await?
            .into_inner();
        Ok(AgentVersionPage::try_from(&page)?)
    }

    /// Pools visible to the caller, optionally in one scope.
    pub async fn list_pools(
        &self,
        scope: Option<AgentScope>,
    ) -> Result<Vec<v1::PoolInfo>, AgentError> {
        Ok(self
            .rpc()
            .list_pools(v1::ListPoolsRequest {
                scope: scope.map(Into::into),
            })
            .await?
            .into_inner()
            .pools)
    }

    /// The keys a pool is pinned by. Compare them with the device's pin
    /// (`nocterm_hub_model::agents::check_pool_keys`) before sealing to or trusting the pool.
    pub async fn pool_keys(&self, pool: PoolId) -> Result<PoolKeys, AgentError> {
        let keys = self
            .rpc()
            .get_pool_key(v1::PoolRef {
                pool_id: pool.to_string(),
            })
            .await?
            .into_inner();
        Ok(PoolKeys::try_from(&keys)?)
    }

    /// Reserves (or returns) the caller's seat for an agent. A refusal is
    /// [`AgentError::Refused`] with its typed reason.
    pub async fn start_instance(
        &self,
        agent: AgentId,
        pool: Option<PoolId>,
    ) -> Result<v1::Instance, AgentError> {
        self.start(agent, pool, None).await
    }

    /// Like [`AgentClient::start_instance`], for one chat: the lease serves `chat` with a
    /// broker token of its own, or, when the instance already runs, the chat gets a token in
    /// that lease. A hub that does not know chat-bound starts ignores the chat and behaves
    /// like [`AgentClient::start_instance`].
    pub async fn start_instance_for_chat(
        &self,
        agent: AgentId,
        pool: Option<PoolId>,
        chat: [u8; CHAT_ID_BYTES],
    ) -> Result<v1::Instance, AgentError> {
        self.start(agent, pool, Some(chat)).await
    }

    async fn start(
        &self,
        agent: AgentId,
        pool: Option<PoolId>,
        chat: Option<[u8; CHAT_ID_BYTES]>,
    ) -> Result<v1::Instance, AgentError> {
        Ok(self
            .rpc()
            .start_instance(v1::StartInstanceRequest {
                agent_id: agent.to_string(),
                pool_id: pool.map(|p| p.to_string()).unwrap_or_default(),
                chat_id: chat.as_ref().map(chat_id_to_wire),
            })
            .await?
            .into_inner())
    }

    /// Current state of a seat.
    pub async fn get_instance(&self, instance: InstanceId) -> Result<v1::Instance, AgentError> {
        Ok(self
            .rpc()
            .get_instance(v1::InstanceRef {
                instance_id: instance.to_string(),
            })
            .await?
            .into_inner())
    }

    /// The caller's own instances, optionally of one agent (no administrator right needed).
    /// A listed instance may lack its setup document and attestation; read those with
    /// [`AgentClient::get_instance`].
    pub async fn list_instances(
        &self,
        agent: Option<AgentId>,
    ) -> Result<Vec<v1::Instance>, AgentError> {
        let agent_id = agent.map(|a| a.to_string()).unwrap_or_default();
        let mut instances = Vec::new();
        let mut after = String::new();
        for _ in 0..MAX_PAGES {
            let page = self
                .rpc()
                .list_instances(v1::ListInstancesRequest {
                    agent_id: agent_id.clone(),
                    after: after.clone(),
                    limit: 0,
                })
                .await?
                .into_inner();
            instances.extend(page.instances);
            if page.next.is_empty() {
                return Ok(instances);
            }
            after = page.next;
        }
        Err(AgentError::TooManyPages)
    }

    /// Hints about the caller's instances, optionally of one agent.
    pub async fn watch_instances(
        &self,
        agent: Option<AgentId>,
    ) -> Result<InstanceHints, AgentError> {
        let stream = self
            .rpc()
            .watch_instances(v1::WatchInstancesRequest {
                agent_id: agent.map(|a| a.to_string()).unwrap_or_default(),
            })
            .await?
            .into_inner();
        Ok(InstanceHints { stream })
    }

    /// Hands the runner grant ticket to the host through the hub, after the device verified the
    /// host attestation ([`verify_instance_setup`]) and imported the setup document.
    pub async fn complete_enrolment(
        &self,
        instance: InstanceId,
        ticket: &str,
    ) -> Result<v1::Instance, AgentError> {
        if ticket.is_empty() || ticket.len() > limits::MAX_TICKET_BYTES {
            return Err(AgentError::EnvelopeLimit);
        }
        Ok(self
            .rpc()
            .complete_enrolment(v1::CompleteEnrolmentRequest {
                instance_id: instance.to_string(),
                ticket: ticket.to_owned(),
            })
            .await?
            .into_inner())
    }

    /// Stops the instance's compute; the volume stays.
    pub async fn suspend_instance(&self, instance: InstanceId) -> Result<v1::Instance, AgentError> {
        Ok(self
            .rpc()
            .suspend_instance(v1::InstanceRef {
                instance_id: instance.to_string(),
            })
            .await?
            .into_inner())
    }

    /// Removes the instance, its volume and its runner.
    pub async fn delete_instance(&self, instance: InstanceId) -> Result<(), AgentError> {
        self.rpc()
            .delete_instance(v1::InstanceRef {
                instance_id: instance.to_string(),
            })
            .await?;
        Ok(())
    }

    /// Usage rows and quota of a scope between two UTC days (days since the Unix epoch).
    pub async fn usage(&self, request: v1::GetUsageRequest) -> Result<v1::UsageReport, AgentError> {
        Ok(self.rpc().get_usage(request).await?.into_inner())
    }

    /// Active accesses of agents' chats (broker tokens, SSH certificates).
    pub async fn list_access_grants(&self) -> Result<Vec<v1::AccessGrant>, AgentError> {
        let mut grants = Vec::new();
        let mut after = String::new();
        for _ in 0..MAX_PAGES {
            let page = self
                .rpc()
                .list_access_grants(v1::ListAccessGrantsRequest {
                    after: after.clone(),
                    limit: 0,
                })
                .await?
                .into_inner();
            grants.extend(page.grants);
            if page.next.is_empty() {
                return Ok(grants);
            }
            after = page.next;
        }
        Err(AgentError::TooManyPages)
    }

    /// Asks a host of the agent's pool (`pool`, or one the hub chooses) to check that the
    /// agent's provider accepts its key. A failed probe is an `Ok` result with
    /// [`nocterm_hub_model::agents::ProbeOutcome::Failed`]; errors are reserved for the call
    /// itself. The result never carries a secret or provider text.
    pub async fn probe_provider(
        &self,
        agent: AgentId,
        pool: Option<PoolId>,
    ) -> Result<ProviderProbe, AgentError> {
        let result = self
            .rpc()
            .probe_provider(v1::ProbeProviderRequest {
                agent_id: agent.to_string(),
                pool_id: pool.map(|p| p.to_string()),
                draft: None,
            })
            .await?
            .into_inner();
        Ok(ProviderProbe::try_from(&result)?)
    }

    /// Probes a definition that is not saved: `envelope` is sealed to `pool`'s key with the
    /// context `agent`, `scope`, `pool` and `version` (the listing's next version, 1 for a new
    /// agent), as for `PutAgent`. Results and errors as [`Self::probe_provider`].
    pub async fn probe_draft(
        &self,
        agent: AgentId,
        pool: PoolId,
        scope: AgentScope,
        version: u64,
        envelope: Vec<u8>,
    ) -> Result<ProviderProbe, AgentError> {
        let result = self
            .rpc()
            .probe_provider(v1::ProbeProviderRequest {
                agent_id: agent.to_string(),
                pool_id: Some(pool.to_string()),
                draft: Some(v1::ProbeDraft {
                    scope: Some(v1::AgentScope::from(scope)),
                    version,
                    envelope,
                }),
            })
            .await?
            .into_inner();
        Ok(ProviderProbe::try_from(&result)?)
    }

    /// Revokes one access at once; the broker stops honouring it and renewal stops.
    pub async fn revoke_access_grant(&self, grant_id: &str) -> Result<(), AgentError> {
        self.rpc()
            .revoke_access_grant(v1::RevokeAccessGrantRequest {
                grant_id: grant_id.to_owned(),
            })
            .await?;
        Ok(())
    }
}
