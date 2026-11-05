//! What a prompt from this device may spend, and the inference grant that allows it (ADR 0129
//! of the native client: the grant carries exactly the prompt's bounds, issued after the prompt
//! was accepted, for half the inference lifetime so it stays inside the prompt's window).
use crate::{
    CloudDeviceError,
    open::{MAX_PROMPT_IMAGE_BYTES, MAX_PROMPT_IMAGE_TOTAL_BYTES, MAX_PROMPT_IMAGES, PromptImage},
};
use nocterm_hub_model::cloud::{
    CloudTextId, MAX_COMMAND_LIFETIME_MS,
    payload::{
        CloudCommandPayload, GrantPayload, GrantReference, GrantWindow, InferenceLimits,
        ModelSelection, PromptPart, PromptPayload, TargetAccess,
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

/// The bounds a prompt and its inference grant carry, and where the prompt runs: the runner's
/// configured default destination, or a bound server named by its session access
/// ([`PromptPolicy::with_target`], contract ADR 0011). A prompt never names an existing session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptPolicy {
    model: ModelSelection,
    target: Option<TargetAccess>,
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
            target: None,
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
    /// This policy for prompts that run against the session target `access` (a bound server's
    /// [`crate::transcript::SessionTarget::access`]).
    #[must_use]
    pub fn with_target(mut self, access: TargetAccess) -> Self {
        self.target = Some(access);
        self
    }
    /// The session target prompts of this policy name; `None` for the runner's default.
    pub fn target(&self) -> Option<&TargetAccess> {
        self.target.as_ref()
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
        self.prompt_with_images(text, &[], issued_at_ms)
    }
    /// The same policy with bounded inline images, in the existing signed prompt layout.
    pub fn prompt_with_images<'a>(
        &self,
        text: &'a str,
        images: &'a [PromptImage],
        issued_at_ms: i64,
    ) -> Result<CloudCommandPayload<'a>, CloudDeviceError> {
        if images.len() > MAX_PROMPT_IMAGES
            || images
                .iter()
                .any(|image| image.bytes.is_empty() || image.bytes.len() > MAX_PROMPT_IMAGE_BYTES)
            || images.iter().map(|image| image.bytes.len()).sum::<usize>()
                > MAX_PROMPT_IMAGE_TOTAL_BYTES
        {
            return Err(CloudDeviceError::Capacity);
        }
        if text.is_empty() && images.is_empty() {
            return Err(CloudDeviceError::Policy);
        }
        let deadline = issued_at_ms
            .checked_add(self.lifetime_ms)
            .ok_or(CloudDeviceError::Time)?;
        Ok(CloudCommandPayload::SubmitPrompt(Box::new(PromptPayload {
            content: std::iter::once(PromptPart::Text(text))
                .filter(|_| !text.is_empty())
                .chain(images.iter().map(|image| PromptPart::Image {
                    mime: image.mime,
                    bytes: &image.bytes,
                }))
                .collect(),
            model: self.model.clone(),
            target: self.target.clone(),
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
