use serde::{Deserialize, Serialize};

use super::{AgentScope, ResourceError, ResourceRequest, limits};
use crate::{AccountId, AgentId, PoolId, Role};

/// Who may start instances of an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAccess {
    /// Every member of the scope with at least this organization role.
    MinRole(Role),
    /// Every account that can see the scope.
    All,
    /// Only the listed accounts.
    Accounts(Vec<AccountId>),
}

/// What a client can do with an agent right now, from this account's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Availability {
    /// An instance is registered and a lease can start at once.
    Ready,
    /// The instance exists and is stopped; the next prompt wakes it.
    Sleeping,
    /// An instance is being provisioned or woken.
    Starting,
    /// A seat cannot be reserved now.
    NoCapacity,
    /// A personal agent needs its provider key.
    NeedsKey,
    /// The pool's key is not pinned on this device yet.
    NeedsPoolTrust,
    /// The agent is switched off.
    Disabled,
}

/// Lifecycle state of one seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstanceState {
    /// The host is creating the volume and the runner identity.
    Provisioning,
    /// The runner exists and waits for the account's enrolment ticket.
    AwaitingEnrolment,
    /// Registered; leases may start.
    Ready,
    /// Stopped to free compute; the volume stays.
    Suspended,
    /// Being removed.
    Deleting,
    /// Provisioning failed.
    Failed,
}

/// A hub-supplied listing is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ListingError {
    /// A text field is empty where required or longer than its limit.
    #[error("agent listing field `{0}` has an invalid length")]
    Length(&'static str),
    /// More models than the limit.
    #[error("agent lists too many models")]
    TooManyModels,
    /// The resource request is out of range.
    #[error(transparent)]
    Resources(#[from] ResourceError),
}

/// The hub-visible storefront of an agent. Descriptive only: behaviour comes from the sealed
/// definition, so a hub that alters a listing cannot change what a host executes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentListing {
    /// Identifier of the agent.
    pub id: AgentId,
    /// Owning scope.
    pub scope: AgentScope,
    /// Monotonic version; a write names the version it replaces.
    pub version: u64,
    /// Display name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Icon name.
    pub icon: String,
    /// Color.
    pub color: String,
    /// Provider kind for display, for example `openai_chat`.
    pub provider_kind: String,
    /// Model ids for display.
    pub models: Vec<String>,
    /// What one instance asks of a host.
    pub resources: ResourceRequest,
    /// Seconds without work before the host stops the runner.
    pub idle_ttl_s: u32,
    /// Who may use the agent.
    pub access: AgentAccess,
    /// Whether personal keys may run on the pool (organization and server agents only).
    pub allow_personal_on_pool: bool,
    /// Whether the agent is switched on.
    pub enabled: bool,
    /// Pools holding a sealed definition of this agent.
    pub pools: Vec<PoolId>,
    /// State from the listing account's point of view.
    pub availability: Availability,
}

impl AgentListing {
    /// Checks every bound of the listing.
    pub fn validate(&self) -> Result<(), ListingError> {
        let bounded = |name: &'static str, text: &str, max: usize, required: bool| {
            if text.len() > max || (required && text.is_empty()) {
                Err(ListingError::Length(name))
            } else {
                Ok(())
            }
        };
        bounded("name", &self.name, limits::MAX_NAME_BYTES, true)?;
        bounded(
            "description",
            &self.description,
            limits::MAX_DESCRIPTION_BYTES,
            false,
        )?;
        bounded("icon", &self.icon, limits::MAX_ICON_BYTES, false)?;
        bounded("color", &self.color, limits::MAX_COLOR_BYTES, false)?;
        bounded(
            "provider_kind",
            &self.provider_kind,
            limits::MAX_PROVIDER_KIND_BYTES,
            true,
        )?;
        if self.models.len() > limits::MAX_MODELS {
            return Err(ListingError::TooManyModels);
        }
        for model in &self.models {
            bounded("model", model, limits::MAX_MODEL_ID_BYTES, true)?;
        }
        if let AgentAccess::Accounts(accounts) = &self.access
            && accounts.len() > limits::MAX_ACCESS_ACCOUNTS
        {
            return Err(ListingError::Length("access"));
        }
        self.resources.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing() -> AgentListing {
        AgentListing {
            id: AgentId::new(),
            scope: AgentScope::Instance,
            version: 1,
            name: "Helper".into(),
            description: String::new(),
            icon: String::new(),
            color: String::new(),
            provider_kind: "openai_chat".into(),
            models: vec!["gpt".into()],
            resources: ResourceRequest {
                cpu_milli: 500,
                mem_mib: 256,
                disk_mib: 512,
                max_parallel_runs: 1,
            },
            idle_ttl_s: 600,
            access: AgentAccess::All,
            allow_personal_on_pool: false,
            enabled: true,
            pools: vec![],
            availability: Availability::Ready,
        }
    }

    #[test]
    fn a_normal_listing_validates() {
        assert_eq!(listing().validate(), Ok(()));
    }

    #[test]
    fn an_overlong_name_names_the_field() {
        let mut broken = listing();
        broken.name = "x".repeat(limits::MAX_NAME_BYTES + 1);
        assert_eq!(broken.validate(), Err(ListingError::Length("name")));
        broken.name.clear();
        assert_eq!(broken.validate(), Err(ListingError::Length("name")));
    }

    #[test]
    fn too_many_models_and_bad_resources_are_refused() {
        let mut broken = listing();
        broken.models = vec!["m".into(); limits::MAX_MODELS + 1];
        assert_eq!(broken.validate(), Err(ListingError::TooManyModels));
        let mut broken = listing();
        broken.resources.cpu_milli = 0;
        assert_eq!(
            broken.validate(),
            Err(ListingError::Resources(ResourceError::OutOfRange))
        );
    }
}
