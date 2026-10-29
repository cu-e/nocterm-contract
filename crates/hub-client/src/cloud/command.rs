//! One actual authenticated invocation; refresh never rewrites an existing signed message.
use super::{CloudClient, CloudError, CloudSubject, Credentials};
use crate::Keyset;
use nocterm_hub_model::cloud::{
    CloudNamespace, CloudRoute, CommandContext, CommandHeader, CommandIssuer, CommandKeys,
    SignedCommand,
    payload::{CloudCommandPayload, GrantPayload},
    relay::{PublicationMetadata, RelayBinding},
};
use nocterm_keys::{PublicKey, cloud::seal_command, random_bytes};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{Arc, Weak},
};

pub struct CloudCommandInvocation {
    namespace: CloudNamespace,
    subject: CloudSubject,
    source: Weak<Credentials>,
    generation: u64,
    max_envelope_bytes: u32,
}
impl CloudCommandInvocation {
    pub(super) fn capture(client: &CloudClient) -> Result<Self, CloudError> {
        client.check_source()?;
        let capture = client
            .credentials
            .capture()
            .ok_or(CloudError::NotSignedIn)?;
        if capture.generation != client.generation
            || capture.account_id != client.subject().account.as_str()
            || capture.device_id != client.subject().device.as_str()
            || capture.signing_key != client.subject().signing_key
        {
            return Err(CloudError::SourceChanged);
        }
        Ok(Self {
            namespace: client.namespace().clone(),
            subject: CloudSubject::captured(&capture)?,
            source: Arc::downgrade(&client.credentials),
            generation: capture.generation,
            max_envelope_bytes: client.limits().max_envelope_bytes,
        })
    }
    /// Use this exact capture when capping the grant's signed hard-session deadline.
    pub fn subject(&self) -> &CloudSubject {
        &self.subject
    }
    pub fn seal(
        &self,
        keyset: &Keyset,
        pinned_runner: &PublicKey,
        route: CloudRoute,
        context: CommandContext,
        payload: &[u8],
    ) -> Result<PreparedCloudCommand, CloudError> {
        self.seal_inner(keyset, pinned_runner, route, context, payload, None)
    }
    /// Encodes the sole semantic schema and rejects requested authority beyond
    /// this invocation's actual captured hard session deadline.
    pub fn seal_payload(
        &self,
        keyset: &Keyset,
        pinned_runner: &PublicKey,
        route: CloudRoute,
        context: CommandContext,
        payload: &CloudCommandPayload<'_>,
    ) -> Result<PreparedCloudCommand, CloudError> {
        let deadline = match payload {
            CloudCommandPayload::SubmitPrompt(prompt) => Some(prompt.inference.deadline_ms),
            CloudCommandPayload::IssueGrant(grant) => Some(match grant.as_ref() {
                GrantPayload::Inference { window, .. } | GrantPayload::Tools { window, .. } => {
                    window.expires_at_ms
                }
                GrantPayload::Provider { context, .. } => context.expires_at_ms(),
            }),
            CloudCommandPayload::AnswerSshConsent(answer) => {
                Some(i64::try_from(answer.binding.expires_ms).map_err(|_| CloudError::Protocol)?)
            }
            _ => None,
        };
        if let Some(deadline) = deadline {
            let maximum = context
                .issued_at_ms
                .checked_add(nocterm_hub_model::cloud::MAX_COMMAND_LIFETIME_MS)
                .ok_or(CloudError::Protocol)?;
            if deadline <= context.issued_at_ms
                || deadline > maximum
                || deadline > self.subject.hard_refresh_expires_at_ms
            {
                return Err(CloudError::Protocol);
            }
        }
        let bytes = zeroize::Zeroizing::new(payload.canonical_bytes()?);
        self.seal_inner(keyset, pinned_runner, route, context, &bytes, Some(payload))
    }
    fn seal_inner(
        &self,
        keyset: &Keyset,
        pinned_runner: &PublicKey,
        route: CloudRoute,
        context: CommandContext,
        payload: &[u8],
        semantic: Option<&CloudCommandPayload<'_>>,
    ) -> Result<PreparedCloudCommand, CloudError> {
        let source = self.source.upgrade().ok_or(CloudError::SourceChanged)?;
        source
            .require_generation(self.generation)
            .map_err(|_| CloudError::SourceChanged)?;
        if keyset.account_id() != self.subject.account.as_str() || route.namespace != self.namespace
        {
            return Err(CloudError::SourceChanged);
        }
        let issuer = CommandIssuer {
            device_id: self.subject.device.clone(),
            signing_key: self.subject.signing_key,
            access_token_digest: self.subject.origin_access_digest,
        };
        let header = CommandHeader::new(
            route.clone(),
            CommandKeys {
                account: keyset.public_key().to_bytes(),
                runner: pinned_runner.to_bytes(),
            },
            issuer,
            context,
            payload,
        )?;
        if let Some(semantic) = semantic {
            semantic.require_header(&header)?;
        }
        let message = header.canonical_bytes()?;
        let signature = source.key.sign(&message);
        let command = SignedCommand::new(header, payload, signature)?;
        let ciphertext = seal_command(keyset.key_pair(), pinned_runner, &command)?;
        let metadata = PublicationMetadata::new(
            random_bytes::<16>()?,
            RelayBinding::command(route)?,
            u32::try_from(ciphertext.len()).map_err(|_| CloudError::Protocol)?,
            Sha256::digest(&ciphertext).into(),
        )?;
        if metadata.total_bytes() > self.max_envelope_bytes {
            return Err(CloudError::Protocol);
        }
        source
            .require_generation(self.generation)
            .map_err(|_| CloudError::SourceChanged)?;
        Ok(PreparedCloudCommand {
            metadata,
            ciphertext,
            semantic_digest: Sha256::digest(&message).into(),
            source: Arc::downgrade(&source),
            generation: self.generation,
        })
    }
}
impl fmt::Debug for CloudCommandInvocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudCommandInvocation")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

pub struct PreparedCloudCommand {
    metadata: PublicationMetadata,
    ciphertext: Vec<u8>,
    semantic_digest: [u8; 32],
    source: Weak<Credentials>,
    generation: u64,
}
impl PreparedCloudCommand {
    /// The native caller MUST authenticate its account-owned durable outbox
    /// before staging these bytes. Only R can open the encrypted command; this
    /// checks transport bounds/source and never re-signs, reseals or extends M.
    pub(super) fn stage_stored(
        client: &super::CloudClient,
        metadata: PublicationMetadata,
        ciphertext: Vec<u8>,
        semantic_digest: [u8; 32],
    ) -> Result<Self, CloudError> {
        client.check_source()?;
        let route = metadata
            .binding()
            .command_route()
            .ok_or(CloudError::Protocol)?;
        if route.namespace != *client.namespace()
            || metadata.total_bytes() > client.limits().max_envelope_bytes
            || usize::try_from(metadata.total_bytes()).ok() != Some(ciphertext.len())
            || metadata.digest() != <[u8; 32]>::from(Sha256::digest(&ciphertext))
        {
            return Err(CloudError::Protocol);
        }
        client.check_source()?;
        Ok(Self {
            metadata,
            ciphertext,
            semantic_digest,
            source: Arc::downgrade(&client.credentials),
            generation: client.generation,
        })
    }
    pub fn metadata(&self) -> &PublicationMetadata {
        &self.metadata
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    /// SHA256 of the exact canonical CommandHeader, as used by native acceptance.
    /// This is not a ciphertext or complete signed-message digest.
    pub fn semantic_digest(&self) -> [u8; 32] {
        self.semantic_digest
    }
    pub(super) fn require_source(
        &self,
        source: &Arc<Credentials>,
        generation: u64,
    ) -> Result<(), CloudError> {
        if self.generation != generation
            || !self
                .source
                .upgrade()
                .is_some_and(|original| Arc::ptr_eq(&original, source))
        {
            return Err(CloudError::SourceChanged);
        }
        source
            .require_generation(generation)
            .map_err(|_| CloudError::SourceChanged)
    }
}
impl fmt::Debug for PreparedCloudCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCloudCommand")
            .field("bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}
