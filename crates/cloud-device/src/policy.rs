//! What a prompt from this device may spend, and the inference grant that allows it (ADR 0129
//! of the native client: the grant carries exactly the prompt's bounds, issued after the prompt
//! was accepted, for half the inference lifetime so it stays inside the prompt's window).
use crate::CloudDeviceError;
use nocterm_hub_model::cloud::{
    CloudTextId, MAX_COMMAND_LIFETIME_MS,
    payload::{
        CloudCommandPayload, GrantPayload, GrantReference, GrantWindow, InferenceLimits,
        ModelSelection, PromptPart, PromptPayload,
    },
};

/// Provider id of a managed agent's model (the runner's broker decides the real provider).
pub const MANAGED_PROVIDER: &str = "managed";
/// Pricing policy of managed models.
pub const MANAGED_PRICING: &str = "managed-v1";
/// Pricing policy of the person's own provider.
pub const OWN_PRICING: &str = "own-v1";

/// Runner-default bounds of one prompt, as native clients send them for managed chats.
pub const DEFAULT_TURNS: u32 = 64;
pub const DEFAULT_IO_BYTES: u64 = 1024 * 1024;
/// Each model call reserves what remains, so the bound stays inside one call's pricing ceiling.
pub const DEFAULT_OUTPUT_TOKENS: u64 = 4096;
pub const DEFAULT_SPEND_MICROS: u64 = 5_000_000;
pub const DEFAULT_LIFETIME_MS: i64 = 10 * 60 * 1000;

/// The bounds a prompt and its inference grant carry. No target and no session: the runner runs
/// prompts at its configured default destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptPolicy {
    model: ModelSelection,
    calls: u32,
    turns: u32,
    io_bytes: u64,
    output_tokens: u64,
    spend_micros: u64,
    lifetime_ms: i64,
}
impl PromptPolicy {
    /// A managed agent's model with the runner-default bounds.
    pub fn managed(model: &str) -> Result<Self, CloudDeviceError> {
        Self::runner_default(ModelSelection {
            provider: CloudTextId::new(MANAGED_PROVIDER)?,
            model: CloudTextId::new(model)?,
            pricing_policy: CloudTextId::new(MANAGED_PRICING)?,
        })
    }
    /// The person's own provider configured on the runner, with the runner-default bounds.
    pub fn own(provider: &str, model: &str) -> Result<Self, CloudDeviceError> {
        Self::runner_default(ModelSelection {
            provider: CloudTextId::new(provider)?,
            model: CloudTextId::new(model)?,
            pricing_policy: CloudTextId::new(OWN_PRICING)?,
        })
    }
    pub fn runner_default(model: ModelSelection) -> Result<Self, CloudDeviceError> {
        Self::new(
            model,
            DEFAULT_TURNS,
            DEFAULT_IO_BYTES,
            DEFAULT_OUTPUT_TOKENS,
            DEFAULT_SPEND_MICROS,
            DEFAULT_LIFETIME_MS,
        )
    }
    /// Explicit bounds; calls equal turns. Every bound must be positive and the lifetime at most
    /// the longest command lifetime.
    pub fn new(
        model: ModelSelection,
        turns: u32,
        io_bytes: u64,
        output_tokens: u64,
        spend_micros: u64,
        lifetime_ms: i64,
    ) -> Result<Self, CloudDeviceError> {
        if turns == 0
            || turns > 1024
            || io_bytes == 0
            || output_tokens == 0
            || spend_micros == 0
            || !(2..=MAX_COMMAND_LIFETIME_MS).contains(&lifetime_ms)
        {
            return Err(CloudDeviceError::Policy);
        }
        Ok(Self {
            model,
            calls: turns,
            turns,
            io_bytes,
            output_tokens,
            spend_micros,
            lifetime_ms,
        })
    }
    pub fn model(&self) -> &ModelSelection {
        &self.model
    }
    /// How long a command of this policy may wait for admission.
    pub fn lifetime_ms(&self) -> i64 {
        self.lifetime_ms
    }
    /// `SubmitPrompt` for `text`, issued at `issued_at_ms`: the inference deadline is the end of
    /// the policy lifetime.
    pub fn prompt<'a>(
        &self,
        text: &'a str,
        issued_at_ms: i64,
    ) -> Result<CloudCommandPayload<'a>, CloudDeviceError> {
        let deadline = issued_at_ms
            .checked_add(self.lifetime_ms)
            .ok_or(CloudDeviceError::Time)?;
        Ok(CloudCommandPayload::SubmitPrompt(Box::new(PromptPayload {
            content: vec![PromptPart::Text(text)],
            model: self.model.clone(),
            target: None,
            existing_session: None,
            inference: self.limits(deadline),
        })))
    }
    /// `IssueGrant(Inference)` with this policy's bounds, valid from `issued_at_ms` for half the
    /// lifetime.
    pub fn inference_grant(
        &self,
        grant_id: [u8; 16],
        issued_at_ms: i64,
    ) -> Result<CloudCommandPayload<'static>, CloudDeviceError> {
        let deadline = issued_at_ms
            .checked_add(self.lifetime_ms / 2)
            .ok_or(CloudDeviceError::Time)?;
        Ok(CloudCommandPayload::IssueGrant(Box::new(
            GrantPayload::Inference {
                grant: GrantReference {
                    id: grant_id,
                    epoch: 1,
                },
                model: self.model.clone(),
                window: GrantWindow {
                    issued_at_ms,
                    expires_at_ms: deadline,
                },
                limits: self.limits(deadline),
            },
        )))
    }
    fn limits(&self, deadline_ms: i64) -> InferenceLimits {
        InferenceLimits {
            calls: self.calls,
            turns: self.turns,
            request_bytes: self.io_bytes,
            output_bytes: self.io_bytes,
            output_tokens: self.output_tokens,
            spend_micros: self.spend_micros,
            deadline_ms,
        }
    }
}
