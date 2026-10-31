//! Conversions between the agent wire messages and the neutral types of `nocterm-hub-model`.
//!
//! Unknown enum values never convert to a permissive default: they return an error (or, for
//! availability, the cautious `Disabled`), so an old client facing a newer hub does not offer
//! an action it cannot perform.

use nocterm_hub_model::agents::{
    AgentAccess, AgentListing, AgentScope, Availability, InstanceState, PoolKeys, RefusalReason,
    ResourceRequest, ScopeError, ScopeKind, ScopeLimits,
};
use nocterm_hub_model::{AccountId, AgentId, InstanceRole, OrgId, PoolId};

use crate::{role_from_wire, role_to_wire, v1};

/// A wire message that does not describe a valid value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// A required field is missing or an enum value is unspecified or unknown.
    #[error("missing or unknown value in field `{0}`")]
    Field(&'static str),
    /// An identifier is not a valid UUID.
    #[error("invalid identifier in field `{0}`")]
    Id(&'static str),
    /// The scope kind and organization id disagree.
    #[error(transparent)]
    Scope(#[from] ScopeError),
}

/// Wire value of an instance role.
pub fn instance_role_to_wire(role: InstanceRole) -> v1::InstanceRole {
    match role {
        InstanceRole::None => v1::InstanceRole::None,
        InstanceRole::Admin => v1::InstanceRole::Admin,
        InstanceRole::Owner => v1::InstanceRole::Owner,
    }
}

/// Instance role from its wire value; unknown values read as the least privileged role.
pub fn instance_role_from_wire(value: i32) -> InstanceRole {
    match v1::InstanceRole::try_from(value) {
        Ok(v1::InstanceRole::Admin) => InstanceRole::Admin,
        Ok(v1::InstanceRole::Owner) => InstanceRole::Owner,
        _ => InstanceRole::None,
    }
}

impl From<AgentScope> for v1::AgentScope {
    fn from(scope: AgentScope) -> Self {
        let kind = match scope.kind() {
            ScopeKind::Account => v1::ScopeKind::Account,
            ScopeKind::Org => v1::ScopeKind::Org,
            ScopeKind::Instance => v1::ScopeKind::Instance,
        };
        Self {
            kind: kind as i32,
            org_id: scope.org().map(|org| org.to_string()).unwrap_or_default(),
        }
    }
}

impl TryFrom<&v1::AgentScope> for AgentScope {
    type Error = WireError;

    fn try_from(wire: &v1::AgentScope) -> Result<Self, WireError> {
        let kind = match v1::ScopeKind::try_from(wire.kind) {
            Ok(v1::ScopeKind::Account) => ScopeKind::Account,
            Ok(v1::ScopeKind::Org) => ScopeKind::Org,
            Ok(v1::ScopeKind::Instance) => ScopeKind::Instance,
            _ => return Err(WireError::Field("scope.kind")),
        };
        let org = if wire.org_id.is_empty() {
            None
        } else {
            Some(
                wire.org_id
                    .parse::<OrgId>()
                    .map_err(|_| WireError::Id("scope.org_id"))?,
            )
        };
        Ok(AgentScope::from_parts(kind, org)?)
    }
}

impl From<Availability> for v1::AgentAvailability {
    fn from(value: Availability) -> Self {
        match value {
            Availability::Ready => Self::Ready,
            Availability::Sleeping => Self::Sleeping,
            Availability::Starting => Self::Starting,
            Availability::NoCapacity => Self::NoCapacity,
            Availability::NeedsKey => Self::NeedsKey,
            Availability::NeedsPoolTrust => Self::NeedsPoolTrust,
            Availability::Disabled => Self::Disabled,
        }
    }
}

/// Availability from its wire value; unknown values read as `Disabled` so no action is offered.
pub fn availability_from_wire(value: i32) -> Availability {
    match v1::AgentAvailability::try_from(value) {
        Ok(v1::AgentAvailability::Ready) => Availability::Ready,
        Ok(v1::AgentAvailability::Sleeping) => Availability::Sleeping,
        Ok(v1::AgentAvailability::Starting) => Availability::Starting,
        Ok(v1::AgentAvailability::NoCapacity) => Availability::NoCapacity,
        Ok(v1::AgentAvailability::NeedsKey) => Availability::NeedsKey,
        Ok(v1::AgentAvailability::NeedsPoolTrust) => Availability::NeedsPoolTrust,
        _ => Availability::Disabled,
    }
}

impl From<InstanceState> for v1::InstanceState {
    fn from(value: InstanceState) -> Self {
        match value {
            InstanceState::Provisioning => Self::Provisioning,
            InstanceState::AwaitingEnrolment => Self::AwaitingEnrolment,
            InstanceState::Ready => Self::Ready,
            InstanceState::Suspended => Self::Suspended,
            InstanceState::Deleting => Self::Deleting,
            InstanceState::Failed => Self::Failed,
        }
    }
}

/// Instance state from its wire value; `None` for unspecified or unknown values.
pub fn instance_state_from_wire(value: i32) -> Option<InstanceState> {
    Some(match v1::InstanceState::try_from(value).ok()? {
        v1::InstanceState::Unspecified => return None,
        v1::InstanceState::Provisioning => InstanceState::Provisioning,
        v1::InstanceState::AwaitingEnrolment => InstanceState::AwaitingEnrolment,
        v1::InstanceState::Ready => InstanceState::Ready,
        v1::InstanceState::Suspended => InstanceState::Suspended,
        v1::InstanceState::Deleting => InstanceState::Deleting,
        v1::InstanceState::Failed => InstanceState::Failed,
    })
}

impl From<RefusalReason> for v1::Refusal {
    fn from(reason: RefusalReason) -> Self {
        match reason {
            RefusalReason::HostCapacity => Self {
                kind: v1::RefusalKind::HostCapacity as i32,
                scope: None,
            },
            RefusalReason::ScopeQuota { scope } => Self {
                kind: v1::RefusalKind::ScopeQuota as i32,
                scope: Some(scope.into()),
            },
            RefusalReason::MemberQuota => Self {
                kind: v1::RefusalKind::MemberQuota as i32,
                scope: None,
            },
            RefusalReason::Budget => Self {
                kind: v1::RefusalKind::Budget as i32,
                scope: None,
            },
        }
    }
}

impl TryFrom<&v1::Refusal> for RefusalReason {
    type Error = WireError;

    fn try_from(wire: &v1::Refusal) -> Result<Self, WireError> {
        match v1::RefusalKind::try_from(wire.kind) {
            Ok(v1::RefusalKind::HostCapacity) => Ok(RefusalReason::HostCapacity),
            Ok(v1::RefusalKind::MemberQuota) => Ok(RefusalReason::MemberQuota),
            Ok(v1::RefusalKind::Budget) => Ok(RefusalReason::Budget),
            Ok(v1::RefusalKind::ScopeQuota) => {
                let scope = wire
                    .scope
                    .as_ref()
                    .ok_or(WireError::Field("refusal.scope"))?;
                Ok(RefusalReason::ScopeQuota {
                    scope: scope.try_into()?,
                })
            }
            _ => Err(WireError::Field("refusal.kind")),
        }
    }
}

impl From<ResourceRequest> for v1::ResourceRequest {
    fn from(value: ResourceRequest) -> Self {
        Self {
            cpu_milli: value.cpu_milli,
            mem_mib: value.mem_mib,
            disk_mib: value.disk_mib,
            max_parallel_runs: value.max_parallel_runs,
        }
    }
}

impl From<&v1::ResourceRequest> for ResourceRequest {
    fn from(wire: &v1::ResourceRequest) -> Self {
        Self {
            cpu_milli: wire.cpu_milli,
            mem_mib: wire.mem_mib,
            disk_mib: wire.disk_mib,
            max_parallel_runs: wire.max_parallel_runs,
        }
    }
}

impl From<ScopeLimits> for v1::ScopeLimits {
    fn from(value: ScopeLimits) -> Self {
        Self {
            max_instances: value.max_instances,
            max_active_leases: value.max_active_leases,
            max_cpu_milli: value.max_cpu_milli,
            max_mem_mib: value.max_mem_mib,
            max_disk_mib: value.max_disk_mib,
            monthly_spend_micros: value.monthly_spend_micros,
        }
    }
}

impl From<&v1::ScopeLimits> for ScopeLimits {
    fn from(wire: &v1::ScopeLimits) -> Self {
        Self {
            max_instances: wire.max_instances,
            max_active_leases: wire.max_active_leases,
            max_cpu_milli: wire.max_cpu_milli,
            max_mem_mib: wire.max_mem_mib,
            max_disk_mib: wire.max_disk_mib,
            monthly_spend_micros: wire.monthly_spend_micros,
        }
    }
}

impl From<PoolKeys> for v1::PoolKeys {
    fn from(keys: PoolKeys) -> Self {
        Self {
            encryption_public_key: keys.encryption.to_vec(),
            signing_public_key: keys.signing.to_vec(),
        }
    }
}

impl TryFrom<&v1::PoolKeys> for PoolKeys {
    type Error = WireError;

    fn try_from(wire: &v1::PoolKeys) -> Result<Self, WireError> {
        Ok(Self {
            encryption: wire
                .encryption_public_key
                .as_slice()
                .try_into()
                .map_err(|_| WireError::Field("pool_keys.encryption_public_key"))?,
            signing: wire
                .signing_public_key
                .as_slice()
                .try_into()
                .map_err(|_| WireError::Field("pool_keys.signing_public_key"))?,
        })
    }
}

impl From<&AgentAccess> for v1::AgentAccess {
    fn from(access: &AgentAccess) -> Self {
        use v1::agent_access::Access;
        let access = match access {
            AgentAccess::MinRole(role) => Access::MinRole(role_to_wire(*role) as i32),
            AgentAccess::All => Access::Everyone(v1::Empty {}),
            AgentAccess::Accounts(accounts) => Access::Accounts(v1::AccountIds {
                account_ids: accounts.iter().map(ToString::to_string).collect(),
            }),
        };
        Self {
            access: Some(access),
        }
    }
}

impl TryFrom<&v1::AgentAccess> for AgentAccess {
    type Error = WireError;

    fn try_from(wire: &v1::AgentAccess) -> Result<Self, WireError> {
        use v1::agent_access::Access;
        match wire.access.as_ref().ok_or(WireError::Field("access"))? {
            Access::MinRole(role) => Ok(AgentAccess::MinRole(
                role_from_wire(*role).ok_or(WireError::Field("access.min_role"))?,
            )),
            Access::Everyone(_) => Ok(AgentAccess::All),
            Access::Accounts(list) => list
                .account_ids
                .iter()
                .map(|id| {
                    id.parse::<AccountId>()
                        .map_err(|_| WireError::Id("access.accounts"))
                })
                .collect::<Result<_, _>>()
                .map(AgentAccess::Accounts),
        }
    }
}

impl From<&AgentListing> for v1::AgentListing {
    fn from(listing: &AgentListing) -> Self {
        Self {
            agent_id: listing.id.to_string(),
            scope: Some(listing.scope.into()),
            version: listing.version,
            name: listing.name.clone(),
            description: listing.description.clone(),
            icon: listing.icon.clone(),
            color: listing.color.clone(),
            provider_kind: listing.provider_kind.clone(),
            models: listing.models.clone(),
            resources: Some(listing.resources.into()),
            idle_ttl_s: listing.idle_ttl_s,
            access: Some((&listing.access).into()),
            allow_personal_on_pool: listing.allow_personal_on_pool,
            enabled: listing.enabled,
            pool_ids: listing.pools.iter().map(ToString::to_string).collect(),
            availability: v1::AgentAvailability::from(listing.availability) as i32,
        }
    }
}

impl TryFrom<&v1::AgentListing> for AgentListing {
    type Error = WireError;

    fn try_from(wire: &v1::AgentListing) -> Result<Self, WireError> {
        let pools = wire
            .pool_ids
            .iter()
            .map(|id| id.parse::<PoolId>().map_err(|_| WireError::Id("pool_ids")))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            id: wire
                .agent_id
                .parse::<AgentId>()
                .map_err(|_| WireError::Id("agent_id"))?,
            scope: wire
                .scope
                .as_ref()
                .ok_or(WireError::Field("scope"))?
                .try_into()?,
            version: wire.version,
            name: wire.name.clone(),
            description: wire.description.clone(),
            icon: wire.icon.clone(),
            color: wire.color.clone(),
            provider_kind: wire.provider_kind.clone(),
            models: wire.models.clone(),
            resources: wire
                .resources
                .as_ref()
                .ok_or(WireError::Field("resources"))?
                .into(),
            idle_ttl_s: wire.idle_ttl_s,
            access: wire
                .access
                .as_ref()
                .ok_or(WireError::Field("access"))?
                .try_into()?,
            allow_personal_on_pool: wire.allow_personal_on_pool,
            enabled: wire.enabled,
            pools,
            availability: availability_from_wire(wire.availability),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn listing(scope: AgentScope) -> AgentListing {
        AgentListing {
            id: AgentId::new(),
            scope,
            version: 3,
            name: "Helper".into(),
            description: "d".into(),
            icon: "i".into(),
            color: "#fff".into(),
            provider_kind: "openai_chat".into(),
            models: vec!["m".into()],
            resources: ResourceRequest {
                cpu_milli: 1000,
                mem_mib: 512,
                disk_mib: 2048,
                max_parallel_runs: 2,
            },
            idle_ttl_s: 300,
            access: AgentAccess::Accounts(vec![AccountId::new()]),
            allow_personal_on_pool: true,
            enabled: true,
            pools: vec![PoolId::new()],
            availability: Availability::NeedsPoolTrust,
        }
    }

    #[test]
    fn a_listing_survives_the_wire_in_every_scope() {
        for scope in [
            AgentScope::Account,
            AgentScope::Instance,
            AgentScope::Org(OrgId::new()),
        ] {
            let original = listing(scope);
            let bytes = v1::AgentListing::from(&original).encode_to_vec();
            let decoded = v1::AgentListing::decode(bytes.as_slice()).unwrap();
            assert_eq!(AgentListing::try_from(&decoded), Ok(original));
        }
    }

    #[test]
    fn an_org_scope_without_an_id_is_refused() {
        let wire = v1::AgentScope {
            kind: v1::ScopeKind::Org as i32,
            org_id: String::new(),
        };
        assert_eq!(
            AgentScope::try_from(&wire),
            Err(WireError::Scope(ScopeError::IdMismatch))
        );
        let unknown = v1::AgentScope {
            kind: 99,
            org_id: String::new(),
        };
        assert_eq!(
            AgentScope::try_from(&unknown),
            Err(WireError::Field("scope.kind"))
        );
    }

    #[test]
    fn every_refusal_reason_round_trips_with_its_scope() {
        let org = OrgId::new();
        for reason in [
            RefusalReason::HostCapacity,
            RefusalReason::ScopeQuota {
                scope: AgentScope::Org(org),
            },
            RefusalReason::ScopeQuota {
                scope: AgentScope::Instance,
            },
            RefusalReason::MemberQuota,
            RefusalReason::Budget,
        ] {
            let wire = v1::Refusal::from(reason);
            let decoded = v1::Refusal::decode(wire.encode_to_vec().as_slice()).unwrap();
            assert_eq!(RefusalReason::try_from(&decoded), Ok(reason));
        }
        let missing = v1::Refusal {
            kind: v1::RefusalKind::ScopeQuota as i32,
            scope: None,
        };
        assert!(RefusalReason::try_from(&missing).is_err());
    }

    #[test]
    fn unknown_values_never_grant_more_than_the_cautious_default() {
        assert_eq!(instance_role_from_wire(77), InstanceRole::None);
        assert_eq!(availability_from_wire(77), Availability::Disabled);
        assert_eq!(instance_state_from_wire(77), None);
        for role in InstanceRole::ALL {
            assert_eq!(
                instance_role_from_wire(instance_role_to_wire(role) as i32),
                role
            );
        }
    }

    #[test]
    fn pool_keys_need_exactly_two_32_byte_keys() {
        let keys = PoolKeys {
            encryption: [1; 32],
            signing: [2; 32],
        };
        assert_eq!(PoolKeys::try_from(&v1::PoolKeys::from(keys)), Ok(keys));
        let short = v1::PoolKeys {
            encryption_public_key: vec![1; 31],
            signing_public_key: vec![2; 32],
        };
        assert!(PoolKeys::try_from(&short).is_err());
    }

    #[test]
    fn instance_states_round_trip() {
        for state in [
            InstanceState::Provisioning,
            InstanceState::AwaitingEnrolment,
            InstanceState::Ready,
            InstanceState::Suspended,
            InstanceState::Deleting,
            InstanceState::Failed,
        ] {
            assert_eq!(
                instance_state_from_wire(v1::InstanceState::from(state) as i32),
                Some(state)
            );
        }
    }

    #[test]
    fn messages_from_a_hub_without_the_new_fields_decode_to_the_old_meaning() {
        // `account_id = "a"` and one publication field, as an older hub would encode them.
        let me = v1::Me::decode(&[0x0a, 1, b'a'][..]).unwrap();
        assert_eq!(
            instance_role_from_wire(me.instance_role),
            InstanceRole::None
        );
        let publication = v1::CloudPublication::decode(&[0x18, 5][..]).unwrap();
        assert_eq!(publication.total_bytes, 5);
        assert_eq!(publication.retry_until_ms, 0);
        let request = v1::StartOidcLoginRequest::decode(&[0x0a, 1, b'p'][..]).unwrap();
        assert_eq!(request.redirect_kind, v1::OidcRedirectKind::Loopback as i32);
    }

    #[test]
    fn host_and_usage_additions_decode_from_messages_without_them() {
        // Old `UsageRow { day = 3 }`, `InstanceUsage { instance_id = "i" }`, `StartLease
        // { lease_id = "l" }` and an `AgentsCapacity { cap_cpu_milli = 1 }`.
        assert_eq!(v1::UsageRow::decode(&[0x08, 3][..]).unwrap().model, "");
        assert_eq!(
            v1::InstanceUsage::decode(&[0x0a, 1, b'i'][..])
                .unwrap()
                .model,
            ""
        );
        let lease = v1::StartLease::decode(&[0x0a, 1, b'l'][..]).unwrap();
        assert_eq!(lease.chat_id, None);
        let start = v1::StartInstanceRequest::decode(&[0x0a, 1, b'a'][..]).unwrap();
        assert_eq!(start.chat_id, None);
        let capacity = v1::AgentsCapacity::decode(&[0x08, 1][..]).unwrap();
        assert!(capacity.running_leases.is_empty());
        assert_eq!(
            capacity.agents_protocol,
            nocterm_hub_model::agents::AGENTS_PROTOCOL_LEGACY
        );
        assert!(!nocterm_hub_model::agents::reports_running_leases(
            capacity.agents_protocol
        ));
    }

    #[test]
    fn running_leases_and_chat_access_round_trip_as_identifiers_only() {
        let hello = v1::NodeHello {
            agents: Some(v1::AgentsCapacity {
                running_leases: vec![v1::RunningLease {
                    lease_id: "l1".into(),
                    instance_id: "i1".into(),
                    chat_id: Some("c1".into()),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let back = v1::NodeHello::decode(hello.encode_to_vec().as_slice()).unwrap();
        let lease = &back.agents.unwrap().running_leases[0];
        assert_eq!(lease.chat_id.as_deref(), Some("c1"));

        let down = v1::NodeDown {
            frame: Some(v1::node_down::Frame::ChatAccess(v1::ChatAccess {
                lease_id: "l1".into(),
                chat_id: "c1".into(),
                op: v1::chat_access::Op::Revoke as i32,
            })),
        };
        let back = v1::NodeDown::decode(down.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(
            back.frame,
            Some(v1::node_down::Frame::ChatAccess(ref a))
                if a.op == v1::chat_access::Op::Revoke as i32 && a.chat_id == "c1"
        ));
    }
}
