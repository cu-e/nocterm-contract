use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Role of an account inside one organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Sees only what was explicitly shared with them.
    Guest,
    /// Regular member: creates sessions and personal data.
    Member,
    /// Manages members, nodes and policies.
    Admin,
    /// Full control, including the organization itself.
    Owner,
}

impl Role {
    /// Every role, from the least to the most privileged.
    pub const ALL: [Role; 4] = [Role::Guest, Role::Member, Role::Admin, Role::Owner];

    /// Stable lowercase name used in storage, configuration and the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Guest => "guest",
            Role::Member => "member",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Text that names no role.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown role `{0}`")]
pub struct RoleParseError(String);

impl FromStr for Role {
    type Err = RoleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Role::ALL
            .into_iter()
            .find(|role| role.as_str() == s)
            .ok_or_else(|| RoleParseError(s.to_owned()))
    }
}

/// Role of an account on the whole hub instance, independent of any organization.
///
/// It decides who administers server-scope agents, pools and quotas. Organization roles
/// ([`Role`]) never imply an instance role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceRole {
    /// An ordinary account.
    None,
    /// Manages server-scope agents, pools and quotas.
    Admin,
    /// Everything an admin does, and grants or revokes instance roles.
    Owner,
}

impl InstanceRole {
    /// Every instance role, from the least to the most privileged.
    pub const ALL: [InstanceRole; 3] =
        [InstanceRole::None, InstanceRole::Admin, InstanceRole::Owner];

    /// Stable lowercase name used in storage, configuration and the API.
    pub fn as_str(self) -> &'static str {
        match self {
            InstanceRole::None => "none",
            InstanceRole::Admin => "admin",
            InstanceRole::Owner => "owner",
        }
    }

    /// Whether the role may administer the instance (admin or owner).
    pub fn is_administrator(self) -> bool {
        self >= InstanceRole::Admin
    }
}

impl fmt::Display for InstanceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Text that names no instance role.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown instance role `{0}`")]
pub struct InstanceRoleParseError(String);

impl FromStr for InstanceRole {
    type Err = InstanceRoleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        InstanceRole::ALL
            .into_iter()
            .find(|role| role.as_str() == s)
            .ok_or_else(|| InstanceRoleParseError(s.to_owned()))
    }
}

/// An organization-level capability checked before an operation runs.
///
/// Resource-level rules (for example "only the owner of a session may type into it") are
/// applied on top of these by `nocterm-access`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// See the organization and its member list.
    OrgRead,
    /// Rename or delete the organization.
    OrgManage,
    /// Invite, remove and change the role of members.
    MembersManage,
    /// See the nodes of the organization and their status.
    NodesView,
    /// Enroll and remove nodes.
    NodesManage,
    /// Start terminal sessions on the organization's nodes.
    SessionCreate,
    /// Create encrypted collections owned by the organization.
    CollectionCreate,
    /// Read the audit log of the organization.
    AuditRead,
    /// Start instances of agents the account may use.
    AgentsUse,
    /// Create, change and delete agents of a scope.
    AgentsManage,
    /// Create pools, enrol hosts and pin pool keys of a scope.
    PoolsManage,
}

impl Permission {
    /// Stable name used in explanations and the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::OrgRead => "org_read",
            Permission::OrgManage => "org_manage",
            Permission::MembersManage => "members_manage",
            Permission::NodesView => "nodes_view",
            Permission::NodesManage => "nodes_manage",
            Permission::SessionCreate => "session_create",
            Permission::CollectionCreate => "collection_create",
            Permission::AuditRead => "audit_read",
            Permission::AgentsUse => "agents_use",
            Permission::AgentsManage => "agents_manage",
            Permission::PoolsManage => "pools_manage",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How well a device protects its keys at rest. Reported at registration and usable by
/// organization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Assurance {
    /// Keys are protected by file permissions only.
    Software,
    /// Keys are sealed by a TPM, Secure Enclave or an equivalent.
    Hardware,
}

impl Assurance {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Assurance::Software => "software",
            Assurance::Hardware => "hardware",
        }
    }

    /// Parses the stable name; unknown values are treated as the weaker level.
    pub fn parse_lenient(s: &str) -> Self {
        if s == "hardware" {
            Assurance::Hardware
        } else {
            Assurance::Software
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_parse_their_own_names() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>().unwrap(), role);
        }
        assert!("root".parse::<Role>().is_err());
    }

    #[test]
    fn instance_roles_parse_and_order_by_privilege() {
        for role in InstanceRole::ALL {
            assert_eq!(role.as_str().parse::<InstanceRole>().unwrap(), role);
        }
        assert!("root".parse::<InstanceRole>().is_err());
        assert!(InstanceRole::Owner > InstanceRole::Admin);
        assert!(InstanceRole::Admin.is_administrator());
        assert!(!InstanceRole::None.is_administrator());
    }

    #[test]
    fn agent_permissions_have_stable_names() {
        assert_eq!(Permission::AgentsUse.as_str(), "agents_use");
        assert_eq!(Permission::AgentsManage.as_str(), "agents_manage");
        assert_eq!(Permission::PoolsManage.as_str(), "pools_manage");
    }

    #[test]
    fn roles_are_ordered_by_privilege() {
        assert!(Role::Owner > Role::Admin);
        assert!(Role::Admin > Role::Member);
        assert!(Role::Member > Role::Guest);
    }
}
