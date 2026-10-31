#![allow(clippy::expect_used)]

//! The agents client against a fake hub.

mod support;

use nocterm_hub_client::agents::{AgentError, PoolEnvelope};
use nocterm_hub_model::agents::{
    AgentAccess, AgentListing, AgentScope, Availability, PoolKeys, RefusalReason, ResourceRequest,
};
use nocterm_hub_model::{AgentId, OrgId, PoolId};
use nocterm_hub_proto::v1;
use support::FakeHub;

fn listing(version: u64) -> AgentListing {
    AgentListing {
        id: AgentId::new(),
        scope: AgentScope::Org(OrgId::new()),
        version,
        name: "Helper".into(),
        description: String::new(),
        icon: String::new(),
        color: String::new(),
        provider_kind: "openai_chat".into(),
        models: vec!["m".into()],
        resources: ResourceRequest {
            cpu_milli: 500,
            mem_mib: 256,
            disk_mib: 512,
            max_parallel_runs: 1,
        },
        idle_ttl_s: 60,
        access: AgentAccess::All,
        allow_personal_on_pool: false,
        enabled: true,
        pools: vec![],
        availability: Availability::Ready,
    }
}

#[tokio::test]
async fn a_hub_without_the_service_reports_unsupported() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;

    let err = client.agents().list_agents(None).await.unwrap_err();

    assert!(matches!(err, AgentError::Unsupported));
}

#[tokio::test]
async fn listing_follows_pages_and_converts_to_model_types() {
    let hub = FakeHub::start_agents().await;
    for n in 0..5 {
        hub.agents
            .listing
            .lock()
            .expect("lock")
            .push(v1::AgentListing::from(&listing(n)));
    }
    let client = hub.signed_in_client().await;

    let agents = client.agents().list_agents(None).await.unwrap();

    assert_eq!(agents.len(), 5);
    assert_eq!(agents[3].version, 3);
}

#[tokio::test]
async fn a_stale_version_is_a_conflict_with_the_current_version() {
    let hub = FakeHub::start_agents().await;
    *hub.agents.stored_version.lock().expect("lock") = 4;
    let client = hub.signed_in_client().await;
    let pool = PoolId::new();
    let envelope = PoolEnvelope {
        pool,
        envelope: vec![1; 40],
    };

    let err = client
        .agents()
        .put_agent(&listing(3), vec![envelope.clone()], 3)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        AgentError::Conflict {
            current_version: Some(4)
        }
    ));

    let detail = client
        .agents()
        .put_agent(&listing(4), vec![envelope], 4)
        .await
        .unwrap();
    assert_eq!(detail.listing.expect("listing").version, 5);
    let puts = hub.agents.puts.lock().expect("lock");
    assert_eq!(puts[0].envelopes[0].pool_id, pool.to_string());
}

#[tokio::test]
async fn oversized_input_is_refused_before_anything_is_sent() {
    let hub = FakeHub::start_agents().await;
    let client = hub.signed_in_client().await;
    let mut broken = listing(1);
    broken.name.clear();

    let err = client
        .agents()
        .put_agent(&broken, vec![], 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AgentError::Listing(_)));

    let too_big = PoolEnvelope {
        pool: PoolId::new(),
        envelope: vec![0; 128 * 1024 + 1],
    };
    let err = client
        .agents()
        .put_agent(&listing(1), vec![too_big], 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AgentError::EnvelopeLimit));
    assert!(hub.agents.puts.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_refused_seat_carries_its_typed_reason() {
    let hub = FakeHub::start_agents().await;
    *hub.agents.refusal.lock().expect("lock") = Some(RefusalReason::MemberQuota);
    let client = hub.signed_in_client().await;

    let err = client
        .agents()
        .start_instance(AgentId::new(), None)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        AgentError::Refused(RefusalReason::MemberQuota)
    ));
}

#[tokio::test]
async fn pool_keys_and_hints_arrive_typed() {
    let hub = FakeHub::start_agents().await;
    let client = hub.signed_in_client().await;

    let keys = client.agents().pool_keys(PoolId::new()).await.unwrap();
    assert_eq!(
        keys,
        PoolKeys {
            encryption: [1; 32],
            signing: [2; 32]
        }
    );

    let mut hints = client.agents().watch_agents().await.unwrap();
    assert_eq!(hints.next().await.unwrap(), Some(7));
    assert_eq!(hints.next().await.unwrap(), None);
}

#[tokio::test]
async fn usage_rows_carry_the_model_they_were_spent_on() {
    let hub = FakeHub::start_agents().await;
    for model in ["small", "large"] {
        hub.agents.usage.lock().expect("lock").push(v1::UsageRow {
            day: 20_000,
            runs: 1,
            model: model.into(),
            ..Default::default()
        });
    }
    let client = hub.signed_in_client().await;

    let report = client
        .agents()
        .usage(v1::GetUsageRequest::default())
        .await
        .unwrap();

    let models: Vec<_> = report.rows.iter().map(|row| row.model.as_str()).collect();
    assert_eq!(models, ["small", "large"]);
}

#[tokio::test]
async fn a_chat_bound_start_names_the_chat_as_lowercase_hex() {
    let hub = FakeHub::start_agents().await;
    *hub.agents.refusal.lock().expect("lock") = Some(RefusalReason::Budget);
    let client = hub.signed_in_client().await;
    let agent = AgentId::new();

    let _ = client.agents().start_instance(agent, None).await;
    let _ = client
        .agents()
        .start_instance_for_chat(agent, None, [0xc4; 16])
        .await;

    let starts = hub.agents.starts.lock().expect("lock");
    assert_eq!(starts[0].chat_id, None);
    assert_eq!(starts[1].chat_id.as_deref(), Some("c4".repeat(16).as_str()));
    assert_eq!(starts[1].agent_id, agent.to_string());
}

#[tokio::test]
async fn org_listings_carry_the_organization_name_the_hub_sent() {
    let hub = FakeHub::start_agents().await;
    let mut named = v1::AgentListing::from(&listing(1));
    named.org_name = "Acme Research".into();
    let mut personal = v1::AgentListing::from(&listing(2));
    personal.scope = Some(AgentScope::Account.into());
    personal.org_name = "ignored".into();
    let unnamed = v1::AgentListing::from(&listing(3));
    hub.agents
        .listing
        .lock()
        .expect("lock")
        .extend([named, personal, unnamed]);
    let client = hub.signed_in_client().await;

    let agents = client
        .agents()
        .list_agents_with_org_names(None)
        .await
        .unwrap();

    let names: Vec<_> = agents.iter().map(|a| a.org_name.as_deref()).collect();
    assert_eq!(names, [Some("Acme Research"), None, None]);
    assert_eq!(agents[2].listing.version, 3);
}
