//! Wire data only; none of these descriptive values establishes execution authority.
use crate::cloud::{CloudTextId, RunCoordinate, provider::ProviderLeaseContext};
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelSelection {
    pub provider: CloudTextId,
    pub model: CloudTextId,
    pub pricing_policy: CloudTextId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSelection {
    pub host_key: [u8; 32],
    pub route: [u8; 32],
    pub principal: CloudTextId,
    pub workspace: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticationSelection {
    pub public_key: [u8; 32],
    pub credential_revision: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetAccess {
    pub target: TargetSelection,
    pub authentication: AuthenticationSelection,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionReference {
    pub id: [u8; 16],
    pub epoch: u64,
    pub access: TargetAccess,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantReference {
    pub id: [u8; 16],
    pub epoch: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReference {
    pub run: RunCoordinate,
    pub session: SessionReference,
    pub grant: GrantReference,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InferenceLimits {
    pub calls: u32,
    pub turns: u32,
    pub request_bytes: u64,
    pub output_bytes: u64,
    pub output_tokens: u64,
    pub spend_micros: u64,
    pub deadline_ms: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantWindow {
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantClass {
    Inference,
    Tools,
    Provider,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedGrantReference {
    pub class: GrantClass,
    pub grant: GrantReference,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalChoice {
    Approve,
    Deny,
    ReconcileSucceeded,
    ReconcileFailed,
    /// An explicit original-result fingerprint, not an observed success or result body.
    ReconcileKnown {
        result_digest: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageMime {
    Png,
    Jpeg,
    Gif,
    Webp,
}
#[derive(Clone, PartialEq, Eq)]
pub enum PromptPart<'a> {
    Text(&'a str),
    Image { mime: ImageMime, bytes: &'a [u8] },
}
impl fmt::Debug for PromptPart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, length) = match self {
            Self::Text(text) => ("text", text.len()),
            Self::Image { bytes, .. } => ("image", bytes.len()),
        };
        f.debug_struct("PromptPart")
            .field("kind", &kind)
            .field("bytes", &length)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptPayload<'a> {
    pub content: Vec<PromptPart<'a>>,
    pub model: ModelSelection,
    pub target: Option<TargetAccess>,
    pub existing_session: Option<SessionReference>,
    pub inference: InferenceLimits,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalPayload {
    pub intent: [u8; 16],
    pub arguments_digest: [u8; 32],
    pub execution: ExecutionReference,
    pub choice: ApprovalChoice,
}

#[derive(Clone, PartialEq, Eq)]
pub enum GrantPayload<'a> {
    Inference {
        grant: GrantReference,
        model: ModelSelection,
        window: GrantWindow,
        limits: InferenceLimits,
    },
    Tools {
        grant: GrantReference,
        session: SessionReference,
        window: GrantWindow,
        operations: u32,
        capabilities: u8,
    },
    Provider {
        grant: GrantReference,
        context: ProviderLeaseContext,
        allowed_models: Vec<CloudTextId>,
        capsule: &'a [u8],
    },
}
impl fmt::Debug for GrantPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inference { grant, .. } => f.debug_tuple("InferenceGrant").field(grant).finish(),
            Self::Tools { grant, .. } => f.debug_tuple("ToolGrant").field(grant).finish(),
            Self::Provider { grant, capsule, .. } => f
                .debug_struct("ProviderGrant")
                .field("grant", grant)
                .field("capsule_bytes", &capsule.len())
                .finish_non_exhaustive(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerRevocation {
    pub device: CloudTextId,
    pub signing_key: [u8; 32],
    pub control_cutoff: u64,
    pub grants: Vec<ScopedGrantReference>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SshConsentBinding<'a> {
    pub run: RunCoordinate,
    pub access: TargetAccess,
    pub attempt: [u8; 16],
    pub nonce: [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub user_key_blob: &'a [u8],
}
#[derive(Clone, PartialEq, Eq)]
pub struct SshProof<'a> {
    pub host_key_blob: &'a [u8],
    pub host_signature_blob: &'a [u8],
    pub userauth_payload: &'a [u8],
}
#[derive(Clone, PartialEq, Eq)]
pub enum SshConsentDecision<'a> {
    Deny,
    Approve { signature_blob: &'a [u8] },
}
#[derive(Clone, PartialEq, Eq)]
pub struct SshConsentAnswer<'a> {
    pub binding: SshConsentBinding<'a>,
    pub proof: SshProof<'a>,
    pub decision: SshConsentDecision<'a>,
}
impl fmt::Debug for SshConsentBinding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshConsentBinding")
            .field("run", &self.run)
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for SshProof<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshProof")
            .field("userauth_bytes", &self.userauth_payload.len())
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for SshConsentDecision<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Deny => "SshConsentDecision::Deny",
            Self::Approve { .. } => "SshConsentDecision::Approve(…)",
        })
    }
}
impl fmt::Debug for SshConsentAnswer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshConsentAnswer")
            .field("attempt", &self.binding.attempt)
            .field(
                "approved",
                &matches!(self.decision, SshConsentDecision::Approve { .. }),
            )
            .finish_non_exhaustive()
    }
}
