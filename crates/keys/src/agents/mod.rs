//! Managed-agent formats: the sealed definition of an agent, the credential broker's virtual
//! tokens and sealed secrets, the SSH CA grant and `authorized_keys` line, and the pure rules
//! of the `agent_ssh_trust` registry.
//!
//! The hub only ever stores the sealed definition; the pool host that holds the pool's
//! encryption key opens it. See `docs/adr/0001-managed-agents.md`.

mod authorized_keys;
mod boxed;
mod broker;
mod canon;
mod definition;
mod sealing;
mod ssh_grant;
mod ssh_trust;

pub use authorized_keys::{
    CaLine, LineError, MAX_COMMENT_BYTES, MAX_LINE_PRINCIPALS, find_ca_lines, remove_ca_lines,
};
pub use broker::{
    BrokerError, BrokerKey, MAX_TOKEN_CHAT_BYTES, MAX_TOKEN_MODELS, MAX_TOKEN_TEXT_BYTES,
    SecretContext, TokenClaims, VirtualToken, open_broker_secret, seal_broker_secret,
};
pub use definition::{
    AgentDefinitionV1, DefinitionError, MAX_DEFINITION_BYTES, MAX_DEFINITION_ENTRIES,
    ProviderBlock, SshTarget,
};
pub use sealing::{
    DEFINITION_FORMAT_VERSION, DefinitionContext, OpenDefinitionError, SealDefinitionError,
    open_definition, seal_definition, sealed_definition_version,
};
pub use ssh_grant::{
    GrantError, MAX_GRANT_LIFETIME_MS, MAX_PRINCIPAL_BYTES, MAX_SOURCE_ADDRESS_BYTES,
    MAX_SOURCE_ADDRESSES, PRINCIPAL_PREFIX, SignedSshCaGrant, SshCaGrant,
};
pub use ssh_trust::{
    MAX_FIELD_BYTES, MAX_RECORD_BYTES, Observation, SSH_TRUST_SCHEMA, SshTrustRecord, TrustAction,
    TrustError, TrustState,
};
