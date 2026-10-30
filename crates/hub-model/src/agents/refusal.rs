use serde::{Deserialize, Serialize};

use super::AgentScope;

/// Which scope's quota refused a request.
pub type QuotaScope = AgentScope;

/// Why the hub refused to reserve a seat or a lease (`RESOURCE_EXHAUSTED`).
///
/// A client shows a specific message for each reason instead of a generic failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum RefusalReason {
    /// No host of the pool has the CPU, memory, disk or slots free.
    #[error("no host of the pool has free capacity")]
    HostCapacity,
    /// The quota of the owning scope (organization or the whole server) is used up.
    #[error("the {scope} quota is used up")]
    ScopeQuota {
        /// The scope whose quota refused.
        scope: QuotaScope,
    },
    /// The member's own share of the scope quota is used up.
    #[error("the member quota is used up")]
    MemberQuota,
    /// The spend budget of the period is used up.
    #[error("the spend budget is used up")]
    Budget,
}

impl RefusalReason {
    /// Stable machine name: `host_capacity`, `scope_quota`, `member_quota` or `budget`.
    pub fn code(&self) -> &'static str {
        match self {
            RefusalReason::HostCapacity => "host_capacity",
            RefusalReason::ScopeQuota { .. } => "scope_quota",
            RefusalReason::MemberQuota => "member_quota",
            RefusalReason::Budget => "budget",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OrgId;

    #[test]
    fn every_reason_has_a_distinct_code() {
        let reasons = [
            RefusalReason::HostCapacity,
            RefusalReason::ScopeQuota {
                scope: AgentScope::Org(OrgId::new()),
            },
            RefusalReason::MemberQuota,
            RefusalReason::Budget,
        ];
        let mut codes: Vec<_> = reasons.iter().map(RefusalReason::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 4);
    }

    #[test]
    fn scope_quota_names_the_scope() {
        let text = RefusalReason::ScopeQuota {
            scope: AgentScope::Instance,
        }
        .to_string();
        assert!(text.contains("instance"));
    }
}
