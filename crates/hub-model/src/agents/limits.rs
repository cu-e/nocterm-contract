//! Length and count limits of agent data, in one place so that servers, clients and the web
//! panel (which generates its `limits.ts` from [`ALL`]) enforce the same figures.

/// Maximum UTF-8 bytes of an agent name.
pub const MAX_NAME_BYTES: usize = 64;
/// Maximum UTF-8 bytes of an agent description.
pub const MAX_DESCRIPTION_BYTES: usize = 512;
/// Maximum UTF-8 bytes of an icon name.
pub const MAX_ICON_BYTES: usize = 64;
/// Maximum UTF-8 bytes of a color (`#rrggbb` or a token name).
pub const MAX_COLOR_BYTES: usize = 32;
/// Maximum UTF-8 bytes of a provider kind such as `openai_chat`.
pub const MAX_PROVIDER_KIND_BYTES: usize = 32;
/// Maximum models an agent lists.
pub const MAX_MODELS: usize = 32;
/// Maximum UTF-8 bytes of one model id.
pub const MAX_MODEL_ID_BYTES: usize = 128;
/// Maximum accounts in an explicit access list.
pub const MAX_ACCESS_ACCOUNTS: usize = 1024;
/// Maximum sealed envelopes (one per pool) in one `PutAgent`.
pub const MAX_ENVELOPES_PER_AGENT: usize = 16;
/// Maximum bytes of one sealed definition envelope.
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024;
/// Maximum UTF-8 bytes of a provider endpoint URL.
pub const MAX_ENDPOINT_BYTES: usize = 2048;
/// Maximum bytes of a provider secret inside a definition.
pub const MAX_SECRET_BYTES: usize = 4096;
/// Maximum UTF-8 bytes of the system prompt inside a definition.
pub const MAX_SYSTEM_PROMPT_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 bytes of a pool name.
pub const MAX_POOL_NAME_BYTES: usize = 64;
/// Maximum entries a list or watch page returns.
pub const MAX_PAGE_ENTRIES: usize = 256;
/// Maximum bytes of a runner setup document passed through the hub.
pub const MAX_SETUP_DOCUMENT_BYTES: usize = 16 * 1024;
/// Maximum bytes of an enrolment ticket passed through the hub.
pub const MAX_TICKET_BYTES: usize = 4096;
/// Maximum UTF-8 bytes of a revocable access grant label.
pub const MAX_GRANT_LABEL_BYTES: usize = 256;
/// Maximum bytes of a broker virtual token's text (`nvt1_…`) handed to a runner.
pub const MAX_ACCESS_TOKEN_BYTES: usize = 128;
/// Maximum bytes of one host-to-runner chat access frame, length prefix included.
pub const MAX_CHAT_ACCESS_FRAME_BYTES: usize = 256;
/// Maximum UTF-8 bytes of an organization's display name in an agent listing.
pub const MAX_ORG_NAME_BYTES: usize = 256;

/// One named limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// `snake_case` name; the web turns it into `SCREAMING_SNAKE`.
    pub name: &'static str,
    /// Value in the unit the name states (bytes unless it says otherwise).
    pub value: usize,
}

macro_rules! limits {
    ($($name:ident),+ $(,)?) => {
        /// Every limit above, for code generators and consistency tests.
        pub const ALL: &[Limit] = &[$(Limit { name: stringify!($name), value: $name }),+];
    };
}

limits!(
    MAX_NAME_BYTES,
    MAX_DESCRIPTION_BYTES,
    MAX_ICON_BYTES,
    MAX_COLOR_BYTES,
    MAX_PROVIDER_KIND_BYTES,
    MAX_MODELS,
    MAX_MODEL_ID_BYTES,
    MAX_ACCESS_ACCOUNTS,
    MAX_ENVELOPES_PER_AGENT,
    MAX_ENVELOPE_BYTES,
    MAX_ENDPOINT_BYTES,
    MAX_SECRET_BYTES,
    MAX_SYSTEM_PROMPT_BYTES,
    MAX_POOL_NAME_BYTES,
    MAX_PAGE_ENTRIES,
    MAX_SETUP_DOCUMENT_BYTES,
    MAX_TICKET_BYTES,
    MAX_GRANT_LABEL_BYTES,
    MAX_ACCESS_TOKEN_BYTES,
    MAX_CHAT_ACCESS_FRAME_BYTES,
    MAX_ORG_NAME_BYTES,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_limit_is_positive_and_named_once() {
        let mut names: Vec<_> = ALL.iter().map(|limit| limit.name).collect();
        assert!(ALL.iter().all(|limit| limit.value > 0));
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
        assert_eq!(before, 21);
    }

    #[test]
    fn an_envelope_fits_a_maximal_definition() {
        const { assert!(MAX_ENVELOPE_BYTES > MAX_SYSTEM_PROMPT_BYTES + MAX_SECRET_BYTES) };
    }
}
