//! Device commands in two steps, for a device whose signing key stays outside this crate.
//!
//! 1. [`UnsignedCommand::prepare`] builds the canonical `CommandHeader` and payload; the caller
//!    signs [`UnsignedCommand::signing_bytes`] with the device's Ed25519 key.
//! 2. [`UnsignedCommand::seal`] verifies that signature under the device key the header names,
//!    seals the command from the account key pair to the pinned runner and returns the
//!    [`Publication`] to send in bounded relay frames.
//!
//! Keep the returned publication and resend exactly its bytes on retry: the publication id makes
//! the hub's delivery idempotent and the expected chat revision stops a second admission. Across
//! a restart keep it as a [`StoredCommand`] ([`stored`]).
use crate::{
    CloudDeviceError, DeviceIdentity, flow::SignRequest, policy::PromptPolicy,
    records::ChatSelector, transcript::ApprovalRequest, trust::HubCapabilities,
};
use nocterm_hub_model::cloud::{
    CloudRoute, CloudTextId, CommandContext, CommandHeader, CommandKeys, CommandKind,
    MAX_COMMAND_LIFETIME_MS, RunCoordinate, SignedCommand,
    payload::{
        ApprovalChoice, CloudCommandPayload, GrantClass, GrantPayload, GrantReference,
        ScopedGrantReference,
    },
    provider::ProviderLeaseContext,
    relay::{PublicationMetadata, RelayBinding},
    ssh::SignedSshBinding,
};
use nocterm_keys::{AccountKeyPair, PublicKey, cloud::seal_command, random_bytes};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;

pub mod delivery;
pub mod stored;
pub use delivery::{Deliver, DeliveryUpdate};
pub use stored::StoredCommand;

/// How long a stop or an approval answer may wait for admission.
pub const CONTROL_LIFETIME_MS: i64 = 10 * 60 * 1000;

/// What the person asked for.
#[derive(Clone, Copy, Debug)]
pub enum CommandAction<'a> {
    /// A new prompt (a new run) under `policy`.
    Prompt {
        policy: &'a PromptPolicy,
        text: &'a str,
    },
    /// A prompt with bounded inline images, using the existing wire payload.
    PromptWithImages {
        policy: &'a PromptPolicy,
        text: &'a str,
        images: &'a [crate::open::PromptImage],
    },
    /// Stop a run.
    Stop { run: RunCoordinate },
    /// The inference grant for a run whose prompt this device sent (Allow).
    Allow {
        policy: &'a PromptPolicy,
        run: RunCoordinate,
    },
    /// Answer a pending approval.
    Answer {
        approval: &'a ApprovalRequest,
        choice: ApprovalChoice,
    },
    /// Lease the own provider key to the runner's verified boot (`IssueGrant(Provider)`).
    Provider {
        grant: GrantReference,
        context: &'a ProviderLeaseContext,
        models: &'a [CloudTextId],
        capsule: &'a [u8],
    },
    /// Bind the chat to servers under a CA-signed binding (`IssueGrant(SshBinding)`).
    SshBinding { binding: &'a SignedSshBinding },
    /// Answer certificate request `request` of binding `grant` (`IssueGrant(SshCertificate)`).
    SshCertificate {
        grant: GrantReference,
        request: [u8; 16],
        certificate: &'a [u8],
    },
    /// Revoke the chat's binding `grant` (`RevokeGrant(SshBinding)`).
    RevokeSshBinding { grant: GrantReference },
}

/// What an action becomes: its command kind, run, admission lifetime and payload.
struct Shape<'a> {
    kind: CommandKind,
    run: Option<RunCoordinate>,
    lifetime: i64,
    payload: CloudCommandPayload<'a>,
}
impl<'a> CommandAction<'a> {
    fn shape(self, grant_id: [u8; 16], now_ms: i64) -> Result<Shape<'a>, CloudDeviceError> {
        let (kind, run, lifetime, payload) = match self {
            Self::Prompt { policy, text } => (
                CommandKind::SubmitPrompt,
                None,
                policy.lifetime_ms(),
                policy.prompt(text, now_ms)?,
            ),
            Self::PromptWithImages {
                policy,
                text,
                images,
            } => (
                CommandKind::SubmitPrompt,
                None,
                policy.lifetime_ms(),
                policy.prompt_with_images(text, images, now_ms)?,
            ),
            Self::Stop { run } => (
                CommandKind::Stop,
                Some(run),
                CONTROL_LIFETIME_MS,
                CloudCommandPayload::Stop,
            ),
            Self::Allow { policy, run } => (
                CommandKind::IssueGrant,
                Some(run),
                policy.lifetime_ms(),
                policy.inference_grant(grant_id, now_ms)?,
            ),
            Self::Answer { approval, choice } => (
                CommandKind::ResolveApproval,
                Some(approval.run()),
                CONTROL_LIFETIME_MS,
                CloudCommandPayload::ResolveApproval(Box::new(approval.answer(choice))),
            ),
            Self::Provider {
                grant,
                context,
                models,
                capsule,
            } => (
                CommandKind::IssueGrant,
                None,
                CONTROL_LIFETIME_MS,
                CloudCommandPayload::IssueGrant(Box::new(GrantPayload::Provider {
                    grant,
                    context: context.clone(),
                    allowed_models: models.to_vec(),
                    capsule,
                })),
            ),
            Self::SshBinding { binding } => (
                CommandKind::IssueGrant,
                None,
                CONTROL_LIFETIME_MS,
                CloudCommandPayload::IssueGrant(Box::new(GrantPayload::SshBinding {
                    binding: binding.clone(),
                })),
            ),
            Self::SshCertificate {
                grant,
                request,
                certificate,
            } => (
                CommandKind::IssueGrant,
                None,
                CONTROL_LIFETIME_MS,
                CloudCommandPayload::IssueGrant(Box::new(GrantPayload::SshCertificate {
                    grant,
                    request,
                    certificate,
                })),
            ),
            Self::RevokeSshBinding { grant } => (
                CommandKind::RevokeGrant,
                None,
                CONTROL_LIFETIME_MS,
                CloudCommandPayload::RevokeGrant(ScopedGrantReference {
                    class: GrantClass::SshBinding,
                    grant,
                }),
            ),
        };
        Ok(Shape {
            kind,
            run,
            lifetime,
            payload,
        })
    }
}

/// A command waiting for the device signature.
#[derive(Debug)]
pub struct UnsignedCommand {
    header: CommandHeader,
    payload: Zeroizing<Vec<u8>>,
}
impl UnsignedCommand {
    /// Builds the command for one chat generation. `expected_chat_revision` is the chat's
    /// latest control revision ([`crate::transcript::Transcript::control_revision`]).
    pub fn prepare(
        selector: &ChatSelector,
        account_public_key: [u8; 32],
        device: &DeviceIdentity,
        action: CommandAction<'_>,
        expected_chat_revision: u64,
        now_ms: i64,
    ) -> Result<Self, CloudDeviceError> {
        Self::prepare_with_ids(
            selector,
            account_public_key,
            device,
            action,
            expected_chat_revision,
            now_ms,
            (random_bytes()?, random_bytes()?, random_bytes()?),
        )
    }
    /// As [`Self::prepare`] with caller-chosen command id, nonce and grant id (fixtures, and
    /// flows that track a command before they prepare it).
    pub fn prepare_with_ids(
        selector: &ChatSelector,
        account_public_key: [u8; 32],
        device: &DeviceIdentity,
        action: CommandAction<'_>,
        expected_chat_revision: u64,
        now_ms: i64,
        (command_id, nonce, grant_id): ([u8; 16], [u8; 16], [u8; 16]),
    ) -> Result<Self, CloudDeviceError> {
        if !selector.scope().is_account_key(&account_public_key) {
            return Err(CloudDeviceError::Binding);
        }
        let Shape {
            kind,
            run,
            lifetime,
            payload,
        } = action.shape(grant_id, now_ms)?;
        require_deadline(&payload, now_ms, device.session_expires_at_ms())?;
        let accept_before_ms = now_ms
            .checked_add(lifetime)
            .ok_or(CloudDeviceError::Time)?
            .min(device.session_expires_at_ms());
        if accept_before_ms <= now_ms {
            return Err(CloudDeviceError::SessionTooShort);
        }
        let route = CloudRoute {
            namespace: selector.scope().namespace(),
            runner: selector.runner(),
            chat_id: selector.chat_id(),
            command_id,
        };
        let context = CommandContext {
            nonce,
            expected_chat_revision,
            run,
            kind,
            issued_at_ms: now_ms,
            accept_before_ms,
        };
        let bytes = Zeroizing::new(payload.canonical_bytes()?);
        let header = CommandHeader::new(
            route,
            CommandKeys {
                account: account_public_key,
                runner: selector.pins().encryption,
            },
            device.issuer(),
            context,
            &bytes,
        )?;
        payload.require_header(&header)?;
        Ok(Self {
            header,
            payload: bytes,
        })
    }
    pub fn command_id(&self) -> [u8; 16] {
        self.header.route().command_id
    }
    pub fn kind(&self) -> CommandKind {
        self.header.context().kind
    }
    /// The exact bytes the device signs (Ed25519, no prehash).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CloudDeviceError> {
        Ok(self.header.canonical_bytes()?)
    }
    /// The signing bytes as a request a device signing service accepts.
    pub fn sign_request(&self) -> Result<SignRequest, CloudDeviceError> {
        Ok(SignRequest::new(
            self.signing_bytes()?,
            self.header.issuer().signing_key,
        ))
    }
    pub fn expected_control_revision(&self) -> u64 {
        self.header.context().expected_chat_revision
    }
    pub(crate) fn require_publication(
        &self,
        capabilities: &HubCapabilities,
    ) -> Result<(), CloudDeviceError> {
        use nocterm_hub_model::cloud::{MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES};
        let bytes = self
            .header
            .plaintext_len()?
            .checked_add(MAX_ENVELOPE_BYTES - MAX_PLAINTEXT_BYTES)
            .ok_or(CloudDeviceError::Capacity)?;
        capabilities.require_publication(bytes)
    }
    /// Verifies the device signature and seals the command to the pinned runner. The ciphertext
    /// fits the logical envelope limit; transports split it into bounded frames when needed.
    pub fn seal(
        self,
        account: &AccountKeyPair,
        signature: &[u8],
        capabilities: &HubCapabilities,
    ) -> Result<SealedCommand, CloudDeviceError> {
        self.require_publication(capabilities)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| {
            CloudDeviceError::Signature(nocterm_keys::SignatureError::MalformedSignature)
        })?;
        let message = self.header.canonical_bytes()?;
        let command = SignedCommand::new(self.header, &self.payload, signature).map_err(
            |error| match error {
                nocterm_hub_model::cloud::CommandError::Signature(error) => {
                    CloudDeviceError::Signature(error)
                }
                error => error.into(),
            },
        )?;
        let runner = PublicKey::from_bytes(&command.header().keys().runner)
            .map_err(|_| CloudDeviceError::Binding)?;
        let ciphertext = seal_command(account, &runner, &command)?;
        let publication = Publication::new(
            RelayBinding::command(command.header().route().clone())?,
            ciphertext,
            capabilities,
        )?;
        Ok(SealedCommand {
            publication,
            semantic_digest: Sha256::digest(&message).into(),
            expected_control_revision: command.header().context().expected_chat_revision,
            accept_before_ms: command.header().context().accept_before_ms,
        })
    }
}

/// A sealed command ready for bounded publication, with what a receipt probe later names.
#[derive(Clone, Debug)]
pub struct SealedCommand {
    publication: Publication,
    semantic_digest: [u8; 32],
    expected_control_revision: u64,
    accept_before_ms: i64,
}
impl SealedCommand {
    pub fn publication(&self) -> &Publication {
        &self.publication
    }
    /// SHA-256 of the canonical header: `HeadTarget::CommandReceipt.semantic_digest`.
    pub fn semantic_digest(&self) -> [u8; 32] {
        self.semantic_digest
    }
    pub fn expected_control_revision(&self) -> u64 {
        self.expected_control_revision
    }
    /// After this time the runner refuses the command; stop retrying.
    pub fn accept_before_ms(&self) -> i64 {
        self.accept_before_ms
    }
}

/// One logical relay publication. Its immutable ciphertext may span bounded transport frames.
#[derive(Clone, Debug)]
pub struct Publication {
    metadata: PublicationMetadata,
    ciphertext: Arc<[u8]>,
    frame_bytes: u32,
}
impl Publication {
    pub(crate) fn new(
        binding: RelayBinding,
        ciphertext: Vec<u8>,
        capabilities: &HubCapabilities,
    ) -> Result<Self, CloudDeviceError> {
        Self::with_id(random_bytes()?, binding, ciphertext, capabilities)
    }
    pub(crate) fn with_id(
        id: [u8; 16],
        binding: RelayBinding,
        ciphertext: Vec<u8>,
        capabilities: &HubCapabilities,
    ) -> Result<Self, CloudDeviceError> {
        let total = u32::try_from(ciphertext.len()).map_err(|_| CloudDeviceError::Capacity)?;
        capabilities.require_publication(ciphertext.len())?;
        let metadata =
            PublicationMetadata::new(id, binding, total, Sha256::digest(&ciphertext).into())?;
        Ok(Self {
            metadata,
            ciphertext: ciphertext.into(),
            frame_bytes: capabilities.limits().max_frame_bytes,
        })
    }
    /// `CloudPublication.publication_id`.
    pub fn publication_id(&self) -> [u8; 16] {
        self.metadata.id()
    }
    /// `CloudPublication.binding`.
    pub fn binding(&self) -> Result<Vec<u8>, CloudDeviceError> {
        Ok(self.metadata.binding().canonical_bytes()?)
    }
    /// `CloudPublication.total_bytes`.
    pub fn total_bytes(&self) -> u32 {
        self.metadata.total_bytes()
    }
    /// The signed negotiated transport frame bound, distinct from the logical envelope bound.
    pub fn max_frame_bytes(&self) -> u32 {
        self.frame_bytes
    }
    /// `CloudPublication.ciphertext_sha256`.
    pub fn ciphertext_sha256(&self) -> [u8; 32] {
        self.metadata.digest()
    }
    /// `CloudPublishOne.data`.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    /// True when `receipt` (`CloudDeliveryReceipt`) acknowledges this publication.
    pub fn is_receipt(&self, publication_id: &[u8], cursor: u64, ciphertext_sha256: &[u8]) -> bool {
        publication_id == self.metadata.id()
            && ciphertext_sha256 == self.metadata.digest()
            && cursor != 0
    }
}

/// Refuses a prompt or grant whose deadline outlives the session or the command lifetime.
fn require_deadline(
    payload: &CloudCommandPayload<'_>,
    issued_at_ms: i64,
    session_expires_at_ms: i64,
) -> Result<(), CloudDeviceError> {
    use nocterm_hub_model::cloud::payload::GrantPayload;
    let deadline = match payload {
        CloudCommandPayload::SubmitPrompt(prompt) => prompt.inference.deadline_ms,
        CloudCommandPayload::IssueGrant(grant) => match grant.as_ref() {
            GrantPayload::Inference { window, .. } | GrantPayload::Tools { window, .. } => {
                window.expires_at_ms
            }
            GrantPayload::Provider { context, .. } => context.expires_at_ms(),
            // A binding outlives its command by design (up to 30 days); a certificate's
            // validity is bounded by its own binding.
            GrantPayload::SshBinding { .. } | GrantPayload::SshCertificate { .. } => {
                return Ok(());
            }
        },
        _ => return Ok(()),
    };
    let maximum = issued_at_ms
        .checked_add(MAX_COMMAND_LIFETIME_MS)
        .ok_or(CloudDeviceError::Time)?;
    if deadline <= issued_at_ms || deadline > maximum {
        return Err(CloudDeviceError::Time);
    }
    if deadline > session_expires_at_ms {
        return Err(CloudDeviceError::SessionTooShort);
    }
    Ok(())
}

#[cfg(test)]
mod image_tests;
#[cfg(test)]
mod tests;
