//! Agents protocol levels a host states in `NodeHello.agents.agents_protocol`.
//!
//! The level tells the hub which host reports it may rely on. Levels only grow and each one
//! includes the guarantees of the levels below.

/// A host that states no level (the field is absent or zero). Its `running_leases` is not
/// reported, so an empty list does not mean that nothing runs.
pub const AGENTS_PROTOCOL_LEGACY: u32 = 0;

/// The host lists every lease it runs in `running_leases`; an empty list means none runs, so
/// the hub may stop leases the host no longer has.
pub const AGENTS_PROTOCOL_RUNNING_LEASES: u32 = 1;

/// The level a host built from this contract states.
pub const AGENTS_PROTOCOL_CURRENT: u32 = AGENTS_PROTOCOL_RUNNING_LEASES;

/// Whether a host at `level` reports the leases it runs, so that their absence from
/// `running_leases` means they stopped.
pub fn reports_running_leases(level: u32) -> bool {
    level >= AGENTS_PROTOCOL_RUNNING_LEASES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hosts_that_state_a_level_report_their_running_leases() {
        assert!(!reports_running_leases(AGENTS_PROTOCOL_LEGACY));
        assert!(reports_running_leases(AGENTS_PROTOCOL_RUNNING_LEASES));
        assert!(reports_running_leases(AGENTS_PROTOCOL_CURRENT));
        assert!(reports_running_leases(AGENTS_PROTOCOL_CURRENT + 1));
    }
}
