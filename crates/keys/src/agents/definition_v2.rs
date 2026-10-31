//! Version 2 of an agent's plaintext: version 1 plus the tool policy, the limits of a chat and
//! a run, and the owner's model prices. See `docs/adr/0004-agent-definition-v2-history-probe.md`.
use std::collections::BTreeSet;
use std::fmt;

use nocterm_hub_model::agents::limits::{
    MAX_AGENT_OUTPUT_TOKENS, MAX_AGENT_TURNS, MAX_PRICE_MICROS_PER_MTOK,
    MAX_PRICING_REVISION_BYTES, MAX_TOOL_NAME_BYTES, MAX_TOOL_POLICY_ENTRIES,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::definition::{
    AgentDefinitionV1, BaseFields, DefinitionError, ProviderBlock, SshTarget, decode_bounded,
    encode_bounded, fits, validate_base,
};

/// Which tools the agent may call.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolSelection {
    /// Every tool the runner offers.
    #[default]
    All,
    /// Only the named tools (at most `MAX_TOOL_POLICY_ENTRIES`, each at most
    /// `MAX_TOOL_NAME_BYTES`, no duplicates). An empty list allows no tool.
    Only(Vec<String>),
}

/// When a person approves a call of a tool with effects (writes, commands, network).
/// Read-only tools are not asked about under any value.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolApproval {
    /// Effectful tools run without asking.
    Never,
    /// The chat's person is asked and may allow once or for the rest of the chat.
    #[default]
    Ask,
    /// The chat's person is asked on every call; an allowance for the chat is not offered.
    Always,
}

/// What an agent may call and when a person approves it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPolicy {
    /// The tools the agent may call.
    pub allowed: ToolSelection,
    /// Approval of effectful tools.
    pub approval: ToolApproval,
}

/// Ceilings of an agent's work; `None` leaves the runner's and the operator's ceilings in
/// force. A set value is at least 1. The broker's budget stays the spend authority; these
/// limits can only lower what a chat or run may use.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentLimits {
    /// Model turns in one run, at most `MAX_AGENT_TURNS`.
    pub max_turns: Option<u32>,
    /// Output tokens of one model call, at most `MAX_AGENT_OUTPUT_TOKENS`.
    pub max_output_tokens: Option<u32>,
    /// Spend of one run, in micro-units; not above `max_spend_micros_per_chat` when both are set.
    pub max_spend_micros_per_run: Option<u64>,
    /// Spend of one chat over its life, in micro-units.
    pub max_spend_micros_per_chat: Option<u64>,
}

/// The owner's price of one model. Prices are per million tokens in micro-units of the
/// billing currency, at most `MAX_PRICE_MICROS_PER_MTOK`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelPrice {
    /// One of the provider block's model ids.
    pub model: String,
    /// Price of a million input tokens.
    pub input_micros_per_mtok: u64,
    /// Price of a million output tokens.
    pub output_micros_per_mtok: u64,
    /// Price of a million cached input tokens; `None` bills them as input.
    pub cached_input_micros_per_mtok: Option<u64>,
    /// Revision of the price table this price comes from, for example `owner-2026-10`
    /// (1..=`MAX_PRICING_REVISION_BYTES` bytes of `[A-Za-z0-9._-]`). Usage is attributed to it.
    pub revision: String,
}

/// Version 2 of the plaintext of an agent. The first six fields are version 1 in its order;
/// field order is the wire format: append only in a new version, never reorder.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct AgentDefinitionV2 {
    /// Agent name shown to people.
    pub name: String,
    /// The system prompt.
    pub instructions: String,
    /// Model provider.
    pub provider: ProviderBlock,
    /// Named secrets exposed to tools through the broker.
    pub secrets: Vec<(String, String)>,
    /// Hosts the agent's network tools may reach.
    pub allowed_hosts: Vec<String>,
    /// SSH targets.
    pub ssh_targets: Vec<SshTarget>,
    /// Tools the agent may call and their approval.
    #[zeroize(skip)]
    pub tools: ToolPolicy,
    /// Ceilings of a run and a chat.
    #[zeroize(skip)]
    pub limits: AgentLimits,
    /// The owner's prices, at most one per provider model.
    #[zeroize(skip)]
    pub pricing: Vec<ModelPrice>,
}

impl fmt::Debug for AgentDefinitionV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentDefinitionV2")
            .field("name", &self.name)
            .field("tools", &self.tools)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl From<AgentDefinitionV1> for AgentDefinitionV2 {
    /// The meaning a version 1 definition has: every tool with approval [`ToolApproval::Ask`],
    /// no limits of its own and no prices (the operator's ceilings apply).
    fn from(mut v1: AgentDefinitionV1) -> Self {
        Self {
            name: std::mem::take(&mut v1.name),
            instructions: std::mem::take(&mut v1.instructions),
            provider: v1.provider.clone(),
            secrets: std::mem::take(&mut v1.secrets),
            allowed_hosts: std::mem::take(&mut v1.allowed_hosts),
            ssh_targets: std::mem::take(&mut v1.ssh_targets),
            tools: ToolPolicy::default(),
            limits: AgentLimits::default(),
            pricing: Vec::new(),
        }
    }
}

impl AgentDefinitionV2 {
    /// Checks every bound of version 1 and of the new fields.
    pub fn validate(&self) -> Result<(), DefinitionError> {
        validate_base(&BaseFields {
            name: &self.name,
            instructions: &self.instructions,
            provider: &self.provider,
            secrets: &self.secrets,
            allowed_hosts: &self.allowed_hosts,
            ssh_targets: &self.ssh_targets,
        })?;
        self.tools.validate()?;
        self.limits.validate()?;
        validate_pricing(&self.pricing, &self.provider.models)
    }

    /// The price of `model`, when the owner set one.
    pub fn price(&self, model: &str) -> Option<&ModelPrice> {
        self.pricing.iter().find(|price| price.model == model)
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DefinitionError> {
        self.validate()?;
        encode_bounded(self)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DefinitionError> {
        let definition: Self = decode_bounded(bytes)?;
        definition.validate()?;
        Ok(definition)
    }
}

impl ToolPolicy {
    fn validate(&self) -> Result<(), DefinitionError> {
        let ToolSelection::Only(names) = &self.allowed else {
            return Ok(());
        };
        fits(names.len() <= MAX_TOOL_POLICY_ENTRIES, "tool policy")?;
        if names.iter().any(String::is_empty) {
            return Err(DefinitionError::Invalid("tool name"));
        }
        fits(
            names.iter().all(|n| n.len() <= MAX_TOOL_NAME_BYTES),
            "tool name",
        )?;
        let unique: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        if unique.len() != names.len() {
            return Err(DefinitionError::Invalid("tool policy (duplicate tool)"));
        }
        Ok(())
    }
}

impl AgentLimits {
    fn validate(&self) -> Result<(), DefinitionError> {
        let positive = |value: Option<u64>| value.is_none_or(|v| v > 0);
        if !positive(self.max_turns.map(u64::from))
            || !positive(self.max_output_tokens.map(u64::from))
            || !positive(self.max_spend_micros_per_run)
            || !positive(self.max_spend_micros_per_chat)
        {
            return Err(DefinitionError::Invalid("limit (zero)"));
        }
        let within = |value: Option<u32>, max: usize| {
            value.is_none_or(|v| usize::try_from(v).is_ok_and(|v| v <= max))
        };
        fits(within(self.max_turns, MAX_AGENT_TURNS), "max turns")?;
        fits(
            within(self.max_output_tokens, MAX_AGENT_OUTPUT_TOKENS),
            "max output tokens",
        )?;
        if let (Some(run), Some(chat)) = (
            self.max_spend_micros_per_run,
            self.max_spend_micros_per_chat,
        ) && run > chat
        {
            return Err(DefinitionError::Invalid(
                "limit (run spend above chat spend)",
            ));
        }
        Ok(())
    }
}

fn validate_pricing(pricing: &[ModelPrice], models: &[String]) -> Result<(), DefinitionError> {
    fits(pricing.len() <= models.len(), "pricing")?;
    let mut seen = BTreeSet::new();
    for price in pricing {
        if !models.contains(&price.model) {
            return Err(DefinitionError::Invalid("price (model not listed)"));
        }
        if !seen.insert(price.model.as_str()) {
            return Err(DefinitionError::Invalid("price (duplicate model)"));
        }
        let max = u64::try_from(MAX_PRICE_MICROS_PER_MTOK).unwrap_or(u64::MAX);
        let amounts = [
            Some(price.input_micros_per_mtok),
            Some(price.output_micros_per_mtok),
            price.cached_input_micros_per_mtok,
        ];
        fits(amounts.iter().flatten().all(|v| *v <= max), "price")?;
        if price.revision.is_empty()
            || !price
                .revision
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(DefinitionError::Invalid("pricing revision"));
        }
        fits(
            price.revision.len() <= MAX_PRICING_REVISION_BYTES,
            "pricing revision",
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn sample_v2() -> AgentDefinitionV2 {
    let mut definition = AgentDefinitionV2::from(super::definition::sample());
    definition.tools = ToolPolicy {
        allowed: ToolSelection::Only(vec!["read_file".into(), "run_command".into()]),
        approval: ToolApproval::Always,
    };
    definition.limits = AgentLimits {
        max_turns: Some(40),
        max_output_tokens: Some(8192),
        max_spend_micros_per_run: Some(500_000),
        max_spend_micros_per_chat: Some(5_000_000),
    };
    definition.pricing = vec![ModelPrice {
        model: "gpt".into(),
        input_micros_per_mtok: 2_500_000,
        output_micros_per_mtok: 10_000_000,
        cached_input_micros_per_mtok: Some(1_250_000),
        revision: "owner-2026-10".into(),
    }];
    definition
}

#[cfg(test)]
mod tests {
    use nocterm_hub_model::agents::limits::MAX_SYSTEM_PROMPT_BYTES;

    use super::super::definition::sample;
    use super::*;

    fn invalid(change: impl FnOnce(&mut AgentDefinitionV2)) -> DefinitionError {
        let mut definition = sample_v2();
        change(&mut definition);
        definition.encode().unwrap_err()
    }

    #[test]
    fn a_version_two_definition_round_trips_and_debug_hides_secrets() {
        let definition = sample_v2();
        let bytes = definition.encode().unwrap();
        assert_eq!(AgentDefinitionV2::decode(&bytes).unwrap(), definition);
        let debug = format!("{definition:?}");
        assert!(!debug.contains("sk-secret") && !debug.contains("prod-1"));
        assert_eq!(definition.price("gpt").unwrap().revision, "owner-2026-10");
        assert!(definition.price("other").is_none());
    }

    #[test]
    fn version_two_bytes_start_with_the_version_one_bytes() {
        let v1 = sample().encode().unwrap();
        let v2 = AgentDefinitionV2::from(sample()).encode().unwrap();
        assert!(v2.starts_with(&v1));
        assert!(v2.len() > v1.len());
    }

    #[test]
    fn version_one_and_two_bytes_do_not_decode_as_each_other() {
        let v1 = sample().encode().unwrap();
        assert!(matches!(
            AgentDefinitionV2::decode(&v1),
            Err(DefinitionError::Malformed(_))
        ));
        let v2 = sample_v2().encode().unwrap();
        assert!(matches!(
            AgentDefinitionV1::decode(&v2),
            Err(DefinitionError::Invalid(_))
        ));
    }

    #[test]
    fn an_upgraded_version_one_definition_keeps_its_fields_and_asks_for_tools() {
        let upgraded = AgentDefinitionV2::from(sample());
        assert_eq!(upgraded.name, sample().name);
        assert_eq!(upgraded.provider, sample().provider);
        assert_eq!(upgraded.ssh_targets, sample().ssh_targets);
        assert_eq!(upgraded.tools.allowed, ToolSelection::All);
        assert_eq!(upgraded.tools.approval, ToolApproval::Ask);
        assert_eq!(upgraded.limits, AgentLimits::default());
        assert!(upgraded.pricing.is_empty());
        upgraded.validate().unwrap();
    }

    #[test]
    fn version_one_bounds_still_apply() {
        assert!(matches!(
            invalid(|d| d.instructions = "x".repeat(MAX_SYSTEM_PROMPT_BYTES + 1)),
            DefinitionError::TooLarge("instructions")
        ));
        assert!(matches!(
            invalid(|d| d.name.clear()),
            DefinitionError::Missing(_)
        ));
    }

    #[test]
    fn tool_policy_bounds_are_enforced() {
        let only = |names: Vec<String>| ToolSelection::Only(names);
        assert!(matches!(
            invalid(|d| d.tools.allowed = only(vec!["t".into(); MAX_TOOL_POLICY_ENTRIES + 1])),
            DefinitionError::TooLarge("tool policy")
        ));
        assert!(matches!(
            invalid(|d| d.tools.allowed = only(vec!["x".repeat(MAX_TOOL_NAME_BYTES + 1)])),
            DefinitionError::TooLarge("tool name")
        ));
        assert!(matches!(
            invalid(|d| d.tools.allowed = only(vec![String::new()])),
            DefinitionError::Invalid(_)
        ));
        assert!(matches!(
            invalid(|d| d.tools.allowed = only(vec!["a".into(), "a".into()])),
            DefinitionError::Invalid(_)
        ));
        let mut none = sample_v2();
        none.tools.allowed = only(Vec::new());
        none.validate().unwrap();
    }

    #[test]
    fn limits_are_positive_bounded_and_consistent() {
        assert!(matches!(
            invalid(|d| d.limits.max_turns = Some(0)),
            DefinitionError::Invalid(_)
        ));
        assert!(matches!(
            invalid(|d| d.limits.max_turns = Some(u32::try_from(MAX_AGENT_TURNS).unwrap() + 1)),
            DefinitionError::TooLarge("max turns")
        ));
        assert!(matches!(
            invalid(|d| d.limits.max_output_tokens =
                Some(u32::try_from(MAX_AGENT_OUTPUT_TOKENS).unwrap() + 1)),
            DefinitionError::TooLarge("max output tokens")
        ));
        assert!(matches!(
            invalid(|d| d.limits.max_spend_micros_per_run = Some(6_000_000)),
            DefinitionError::Invalid(_)
        ));
        assert!(matches!(
            invalid(|d| d.limits.max_spend_micros_per_chat = Some(0)),
            DefinitionError::Invalid(_)
        ));
    }

    #[test]
    fn prices_name_listed_models_once_with_bounded_amounts() {
        let max = u64::try_from(MAX_PRICE_MICROS_PER_MTOK).unwrap();
        assert!(matches!(
            invalid(|d| d.pricing[0].model = "unlisted".into()),
            DefinitionError::Invalid(_)
        ));
        assert!(matches!(
            invalid(|d| d.pricing.push(d.pricing[0].clone())),
            DefinitionError::TooLarge("pricing")
        ));
        assert!(matches!(
            invalid(|d| {
                d.provider.models.push("other".into());
                d.pricing.push(d.pricing[0].clone());
            }),
            DefinitionError::Invalid(_)
        ));
        assert!(matches!(
            invalid(|d| d.pricing[0].output_micros_per_mtok = max + 1),
            DefinitionError::TooLarge("price")
        ));
        assert!(matches!(
            invalid(|d| d.pricing[0].cached_input_micros_per_mtok = Some(max + 1)),
            DefinitionError::TooLarge("price")
        ));
        assert!(matches!(
            invalid(|d| d.pricing[0].revision = "has space".into()),
            DefinitionError::Invalid(_)
        ));
        assert!(matches!(
            invalid(|d| d.pricing[0].revision = "r".repeat(MAX_PRICING_REVISION_BYTES + 1)),
            DefinitionError::TooLarge("pricing revision")
        ));
    }
}
