//! The shared vocabulary of a managed agent's model provider and tools.
//!
//! The sealed definition keeps the provider kind as text
//! (`nocterm_keys::agents::ProviderBlock::kind`) and a tool policy names tools as text, so every
//! side must agree on the words. Editors write [`ProviderKind::as_str`]; hosts, brokers and
//! runners read with [`ProviderKind::parse`], which also accepts the legacy alias `anthropic`.

use std::fmt;
use std::str::FromStr;

/// The wire protocol of a model provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// OpenAI Chat Completions and compatible endpoints (`openai_chat`).
    OpenAiChat,
    /// Anthropic Messages (`anthropic_messages`; legacy alias `anthropic`).
    AnthropicMessages,
}

/// A provider kind this contract does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown model provider kind")]
pub struct UnknownProviderKind;

impl ProviderKind {
    /// Every kind, in the order an editor offers them.
    pub const ALL: [Self; 2] = [Self::OpenAiChat, Self::AnthropicMessages];

    /// The canonical text, which editors seal and listings show.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiChat => "openai_chat",
            Self::AnthropicMessages => "anthropic_messages",
        }
    }

    /// Reads a kind: the canonical text, or the legacy alias `anthropic` that earlier web
    /// panels sealed for [`ProviderKind::AnthropicMessages`]. Matching is exact.
    pub fn parse(text: &str) -> Result<Self, UnknownProviderKind> {
        match text {
            "openai_chat" => Ok(Self::OpenAiChat),
            "anthropic_messages" | "anthropic" => Ok(Self::AnthropicMessages),
            _ => Err(UnknownProviderKind),
        }
    }
}

impl FromStr for ProviderKind {
    type Err = UnknownProviderKind;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The tools a managed runner offers its model, in catalog order: the names a tool policy's
/// `Only` list may usefully contain. An editor uses it to suggest names and to flag a name no
/// runner offers; a runner ignores a name it does not offer, so the list is a hint, not a
/// validation rule of the sealed format. Mirrors the desktop tool catalog the runner offers.
pub const MANAGED_TOOL_NAMES: &[&str] = &[
    "list_terminals",
    "open_terminal",
    "read_terminal",
    "send_input",
    "run_command",
    "exec_command",
    "read_command",
    "cancel_command",
    "transfer_files",
    "read_transfer",
    "cancel_transfer",
];

/// Whether a managed runner offers a tool of this name.
pub fn is_managed_tool(name: &str) -> bool {
    MANAGED_TOOL_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::super::limits::{MAX_PROVIDER_KIND_BYTES, MAX_TOOL_NAME_BYTES};
    use super::*;

    #[test]
    fn canonical_kinds_round_trip() {
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::parse(kind.as_str()), Ok(kind));
            assert_eq!(kind.to_string().parse::<ProviderKind>(), Ok(kind));
            assert!(kind.as_str().len() <= MAX_PROVIDER_KIND_BYTES);
        }
    }

    #[test]
    fn the_legacy_anthropic_alias_reads_as_messages_and_writes_canonically() {
        let kind = ProviderKind::parse("anthropic").unwrap();
        assert_eq!(kind, ProviderKind::AnthropicMessages);
        assert_eq!(kind.as_str(), "anthropic_messages");
    }

    #[test]
    fn other_kinds_are_refused() {
        for text in ["", "openai", "OpenAI_Chat", "anthropic_messages ", "gemini"] {
            assert_eq!(ProviderKind::parse(text), Err(UnknownProviderKind));
        }
    }

    #[test]
    fn managed_tool_names_are_distinct_and_bounded() {
        let mut names = MANAGED_TOOL_NAMES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), MANAGED_TOOL_NAMES.len());
        assert!(MANAGED_TOOL_NAMES.iter().all(|name| {
            !name.is_empty()
                && name.len() <= MAX_TOOL_NAME_BYTES
                && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        }));
        assert!(is_managed_tool("transfer_files"));
        assert!(!is_managed_tool("no_such_tool"));
    }
}
