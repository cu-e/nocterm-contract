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

/// The host opens definition envelopes of format version 2
/// (`nocterm_keys::agents::DEFINITION_FORMAT_VERSION_V2`) as well as 1. A hub provisions a
/// format 2 envelope only on hosts at this level or above.
pub const AGENTS_PROTOCOL_DEFINITION_V2: u32 = 2;

/// The host answers `NodeDown.probe_provider` with `NodeUp.probe_result`. A hub sends probes
/// only to hosts at this level or above.
pub const AGENTS_PROTOCOL_PROVIDER_PROBE: u32 = 3;

/// The host reads the hub-stated seat account key (`ProvisionInstance.account_public_key`,
/// `ProbeProvider.account_public_key`) under the rules of ADR 0005: it may use it without a pin
/// for a personal agent, for other scopes only when its operator opted in, and refuses a seat
/// whose pin disagrees with it (`account_key_mismatch`). A hub sends the key only to hosts at
/// this level or above; a host below ignores the field and requires a pin.
pub const AGENTS_PROTOCOL_STATED_ACCOUNT_KEY: u32 = 4;

/// The host opens format 3 model edits, retaining the authenticated base settings.
/// A hub sends a format 3 envelope only to a host at this level or above.
pub const AGENTS_PROTOCOL_DEFINITION_PATCH: u32 = 5;

/// The highest level this contract defines. A host states the level it implements, which is
/// this one only when it implements every level up to it.
pub const AGENTS_PROTOCOL_CURRENT: u32 = AGENTS_PROTOCOL_DEFINITION_PATCH;

/// Whether a host at `level` reports the leases it runs, so that their absence from
/// `running_leases` means they stopped.
pub fn reports_running_leases(level: u32) -> bool {
    level >= AGENTS_PROTOCOL_RUNNING_LEASES
}

/// Whether a host at `level` opens definition envelopes of format version 2.
pub fn opens_definition_v2(level: u32) -> bool {
    level >= AGENTS_PROTOCOL_DEFINITION_V2
}

/// Whether a host at `level` opens definition model edits (format 3).
pub fn opens_definition_patch(level: u32) -> bool {
    level >= AGENTS_PROTOCOL_DEFINITION_PATCH
}

/// Whether a host at `level` reads a sealed definition's format. Unknown formats are refused.
pub fn opens_definition_format(level: u32, format: u8) -> bool {
    match format {
        1 => true,
        2 => opens_definition_v2(level),
        3 => opens_definition_patch(level),
        _ => false,
    }
}

/// Whether a host at `level` answers provider probes.
pub fn answers_provider_probes(level: u32) -> bool {
    level >= AGENTS_PROTOCOL_PROVIDER_PROBE
}

/// Whether a hub may state the seat account key to a host at `level`.
pub fn reads_stated_account_key(level: u32) -> bool {
    level >= AGENTS_PROTOCOL_STATED_ACCOUNT_KEY
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

    #[test]
    fn only_hosts_at_their_level_get_version_two_envelopes_and_probes() {
        assert!(!opens_definition_v2(AGENTS_PROTOCOL_RUNNING_LEASES));
        assert!(opens_definition_v2(AGENTS_PROTOCOL_DEFINITION_V2));
        assert!(!answers_provider_probes(AGENTS_PROTOCOL_DEFINITION_V2));
        assert!(answers_provider_probes(AGENTS_PROTOCOL_PROVIDER_PROBE));
        assert!(answers_provider_probes(AGENTS_PROTOCOL_CURRENT + 1));
        assert!(reports_running_leases(AGENTS_PROTOCOL_PROVIDER_PROBE));
    }

    #[test]
    fn only_hosts_at_their_level_get_a_stated_account_key() {
        assert!(!reads_stated_account_key(AGENTS_PROTOCOL_PROVIDER_PROBE));
        assert!(reads_stated_account_key(AGENTS_PROTOCOL_STATED_ACCOUNT_KEY));
        assert!(reads_stated_account_key(AGENTS_PROTOCOL_CURRENT + 1));
        assert!(answers_provider_probes(AGENTS_PROTOCOL_STATED_ACCOUNT_KEY));
        assert_eq!(AGENTS_PROTOCOL_CURRENT, AGENTS_PROTOCOL_DEFINITION_PATCH);
        assert!(!opens_definition_patch(AGENTS_PROTOCOL_STATED_ACCOUNT_KEY));
        assert!(opens_definition_patch(AGENTS_PROTOCOL_DEFINITION_PATCH));
        assert!(opens_definition_patch(AGENTS_PROTOCOL_CURRENT + 1));
        assert!(!opens_definition_format(
            AGENTS_PROTOCOL_STATED_ACCOUNT_KEY,
            3
        ));
        assert!(opens_definition_format(AGENTS_PROTOCOL_CURRENT, 3));
        assert!(!opens_definition_format(AGENTS_PROTOCOL_CURRENT + 1, 99));
    }
}
