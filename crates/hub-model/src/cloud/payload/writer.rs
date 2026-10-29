//! One aggregate bound before every allocation; nested fields get no extra allowance.
use super::{
    PayloadError,
    values::{
        ApprovalChoice, ApprovalPayload, ExecutionReference, GrantClass, GrantPayload,
        GrantReference, GrantWindow, ImageMime, InferenceLimits, IssuerRevocation, ModelSelection,
        PromptPart, PromptPayload, ScopedGrantReference, SessionReference, SshConsentAnswer,
        SshConsentDecision, TargetAccess,
    },
};
use crate::cloud::provider::MAX_PROVIDER_LEASE_BYTES;
use crate::cloud::{MAX_PLAINTEXT_BYTES, codec::BoundedWriter};
pub(in crate::cloud) struct PayloadWriter {
    output: BoundedWriter,
}
impl PayloadWriter {
    pub(in crate::cloud) fn new() -> Self {
        Self {
            output: BoundedWriter::buffer(MAX_PLAINTEXT_BYTES),
        }
    }
    pub(in crate::cloud) fn counter() -> Self {
        Self {
            output: BoundedWriter::counter(MAX_PLAINTEXT_BYTES),
        }
    }
    pub(in crate::cloud) fn exact_buffer(length: usize) -> Result<Self, PayloadError> {
        if length > MAX_PLAINTEXT_BYTES {
            return Err(PayloadError::Bounds);
        }
        Ok(Self {
            output: BoundedWriter::exact_buffer(length),
        })
    }
    pub(in crate::cloud) fn len(&self) -> usize {
        self.output.len()
    }
    pub(in crate::cloud) fn finish(self) -> Result<Vec<u8>, PayloadError> {
        Ok(self.output.into_bytes()?)
    }
    pub(in crate::cloud) fn raw(&mut self, bytes: &[u8]) -> Result<(), PayloadError> {
        Ok(self.output.extend(bytes)?)
    }
    pub(in crate::cloud) fn field(&mut self, bytes: &[u8]) -> Result<(), PayloadError> {
        Ok(self.output.field(bytes)?)
    }
    pub(in crate::cloud) fn tool_arguments(
        &mut self,
        value: &crate::cloud::tool_arguments::ToolArguments<'_>,
    ) -> Result<(), PayloadError> {
        Ok(value.write_field_to(&mut self.output)?)
    }
    pub(in crate::cloud) fn tag(&mut self, value: u8) -> Result<(), PayloadError> {
        self.raw(&[value])
    }
    pub(in crate::cloud) fn target(&mut self, value: &TargetAccess) -> Result<(), PayloadError> {
        self.raw(&value.target.host_key)?;
        self.raw(&value.target.route)?;
        self.field(value.target.principal.as_str().as_bytes())?;
        self.raw(&value.target.workspace)?;
        self.raw(&value.authentication.public_key)?;
        self.raw(&value.authentication.credential_revision)
    }
    pub(in crate::cloud) fn session(
        &mut self,
        value: &SessionReference,
    ) -> Result<(), PayloadError> {
        if value.epoch == 0 {
            return Err(PayloadError::Value);
        }
        self.raw(&value.id)?;
        self.raw(&value.epoch.to_be_bytes())?;
        self.target(&value.access)
    }
    pub(in crate::cloud) fn grant(&mut self, value: GrantReference) -> Result<(), PayloadError> {
        if value.epoch == 0 {
            return Err(PayloadError::Value);
        }
        self.raw(&value.id)?;
        self.raw(&value.epoch.to_be_bytes())
    }
    pub(in crate::cloud) fn model(&mut self, value: &ModelSelection) -> Result<(), PayloadError> {
        self.field(value.provider.as_str().as_bytes())?;
        self.field(value.model.as_str().as_bytes())?;
        self.field(value.pricing_policy.as_str().as_bytes())
    }
    pub(in crate::cloud) fn limits(&mut self, value: InferenceLimits) -> Result<(), PayloadError> {
        if value.calls == 0
            || value.turns == 0
            || value.request_bytes == 0
            || value.output_bytes == 0
            || value.output_tokens == 0
        {
            return Err(PayloadError::Value);
        }
        self.raw(&value.calls.to_be_bytes())?;
        self.raw(&value.turns.to_be_bytes())?;
        for limit in [
            value.request_bytes,
            value.output_bytes,
            value.output_tokens,
            value.spend_micros,
        ] {
            self.raw(&limit.to_be_bytes())?;
        }
        self.raw(&value.deadline_ms.to_be_bytes())
    }
    pub(in crate::cloud) fn window(&mut self, value: GrantWindow) -> Result<(), PayloadError> {
        let duration = value
            .expires_at_ms
            .checked_sub(value.issued_at_ms)
            .ok_or(PayloadError::Value)?;
        if duration <= 0 || duration > 30 * 60 * 1000 {
            return Err(PayloadError::Value);
        }
        self.raw(&value.issued_at_ms.to_be_bytes())?;
        self.raw(&value.expires_at_ms.to_be_bytes())
    }
    pub(in crate::cloud) fn execution(
        &mut self,
        value: &ExecutionReference,
    ) -> Result<(), PayloadError> {
        if value.run.expected_epoch == 0 {
            return Err(PayloadError::Value);
        }
        self.raw(&value.run.id)?;
        self.raw(&value.run.expected_epoch.to_be_bytes())?;
        self.session(&value.session)?;
        self.grant(value.grant)
    }
    pub(in crate::cloud) fn prompt(
        &mut self,
        value: &PromptPayload<'_>,
    ) -> Result<(), PayloadError> {
        self.prompt_selection(
            &value.model,
            value.target.as_ref(),
            value.existing_session.as_ref(),
        )?;
        self.limits(value.inference)?;
        self.prompt_content(&value.content)
    }
    pub(in crate::cloud) fn prompt_selection(
        &mut self,
        model: &ModelSelection,
        target: Option<&TargetAccess>,
        session: Option<&SessionReference>,
    ) -> Result<(), PayloadError> {
        if session.is_some_and(|s| Some(&s.access) != target) {
            return Err(PayloadError::Value);
        }
        self.model(model)?;
        self.tag(u8::from(target.is_some()))?;
        if let Some(target) = target {
            self.target(target)?;
        }
        self.tag(u8::from(session.is_some()))?;
        if let Some(session) = session {
            self.session(session)?;
        }
        Ok(())
    }
    pub(in crate::cloud) fn prompt_content(
        &mut self,
        content: &[PromptPart<'_>],
    ) -> Result<(), PayloadError> {
        if content.is_empty() || content.len() > 128 {
            return Err(PayloadError::Value);
        }
        let count = u16::try_from(content.len()).map_err(|_| PayloadError::Bounds)?;
        self.raw(&count.to_be_bytes())?;
        for part in content {
            match part {
                PromptPart::Text(text) => {
                    if text.is_empty() {
                        return Err(PayloadError::Value);
                    }
                    self.tag(1)?;
                    self.field(text.as_bytes())?;
                }
                PromptPart::Image { mime, bytes } => {
                    if bytes.is_empty() {
                        return Err(PayloadError::Value);
                    }
                    self.tag(2)?;
                    self.tag(match mime {
                        ImageMime::Png => 1,
                        ImageMime::Jpeg => 2,
                        ImageMime::Gif => 3,
                        ImageMime::Webp => 4,
                    })?;
                    self.field(bytes)?;
                }
            }
        }
        Ok(())
    }
    pub(in crate::cloud) fn approval(
        &mut self,
        value: &ApprovalPayload,
    ) -> Result<(), PayloadError> {
        self.raw(&value.intent)?;
        self.raw(&value.arguments_digest)?;
        self.execution(&value.execution)?;
        self.tag(match value.choice {
            ApprovalChoice::Approve => 1,
            ApprovalChoice::Deny => 2,
            ApprovalChoice::ReconcileSucceeded => 3,
            ApprovalChoice::ReconcileFailed => 4,
            ApprovalChoice::ReconcileKnown { .. } => 5,
        })?;
        if let ApprovalChoice::ReconcileKnown { result_digest } = value.choice {
            self.raw(&result_digest)?;
        }
        Ok(())
    }
    pub(in crate::cloud) fn grant_payload(
        &mut self,
        value: &GrantPayload<'_>,
    ) -> Result<(), PayloadError> {
        match value {
            GrantPayload::Inference {
                grant,
                model,
                window,
                limits,
            } => {
                self.tag(1)?;
                self.grant(*grant)?;
                self.model(model)?;
                self.window(*window)?;
                if limits.deadline_ms > window.expires_at_ms
                    || limits.deadline_ms <= window.issued_at_ms
                {
                    return Err(PayloadError::Value);
                }
                self.limits(*limits)
            }
            GrantPayload::Tools {
                grant,
                session,
                window,
                operations,
                capabilities,
            } => {
                self.tag(2)?;
                self.grant(*grant)?;
                self.session(session)?;
                self.window(*window)?;
                if *operations == 0 || *capabilities == 0 || capabilities & !0x0f != 0 {
                    return Err(PayloadError::Value);
                }
                self.raw(&operations.to_be_bytes())?;
                self.tag(*capabilities)
            }
            GrantPayload::Provider {
                grant,
                context,
                allowed_models,
                capsule,
            } => {
                self.tag(3)?;
                self.grant(*grant)?;
                if allowed_models.is_empty()
                    || allowed_models.len() > 32
                    || capsule.len() <= 74
                    || capsule.len() > MAX_PROVIDER_LEASE_BYTES
                {
                    return Err(PayloadError::Bounds);
                }
                if allowed_models
                    .iter()
                    .enumerate()
                    .any(|(i, model)| allowed_models[..i].contains(model))
                {
                    return Err(PayloadError::Value);
                }
                self.field(&context.canonical_bytes()?)?;
                self.tag(u8::try_from(allowed_models.len()).map_err(|_| PayloadError::Bounds)?)?;
                for model in allowed_models {
                    self.field(model.as_str().as_bytes())?;
                }
                self.field(capsule)
            }
        }
    }
    pub(in crate::cloud) fn scoped_grant(
        &mut self,
        value: ScopedGrantReference,
    ) -> Result<(), PayloadError> {
        self.tag(match value.class {
            GrantClass::Inference => 1,
            GrantClass::Tools => 2,
            GrantClass::Provider => 3,
        })?;
        self.grant(value.grant)
    }
    pub(in crate::cloud) fn issuer_revoke(
        &mut self,
        value: &IssuerRevocation,
    ) -> Result<(), PayloadError> {
        if value.grants.len() > 64 {
            return Err(PayloadError::Bounds);
        }
        if value
            .grants
            .iter()
            .enumerate()
            .any(|(i, grant)| value.grants[..i].contains(grant))
        {
            return Err(PayloadError::Value);
        }
        self.field(value.device.as_str().as_bytes())?;
        self.raw(&value.signing_key)?;
        self.raw(&value.control_cutoff.to_be_bytes())?;
        self.tag(u8::try_from(value.grants.len()).map_err(|_| PayloadError::Bounds)?)?;
        for grant in &value.grants {
            self.scoped_grant(*grant)?;
        }
        Ok(())
    }
    pub(in crate::cloud) fn ssh_answer(
        &mut self,
        value: &SshConsentAnswer<'_>,
    ) -> Result<(), PayloadError> {
        let binding = &value.binding;
        let duration = binding
            .expires_ms
            .checked_sub(binding.issued_ms)
            .ok_or(PayloadError::Value)?;
        if duration == 0 || duration > 60_000 || binding.run.expected_epoch == 0 {
            return Err(PayloadError::Value);
        }
        for blob in [
            binding.user_key_blob,
            value.proof.host_key_blob,
            value.proof.host_signature_blob,
        ] {
            if blob.is_empty() || blob.len() > 1024 {
                return Err(PayloadError::Bounds);
            }
        }
        if value.proof.userauth_payload.is_empty() || value.proof.userauth_payload.len() > 4096 {
            return Err(PayloadError::Bounds);
        }
        self.raw(&binding.run.id)?;
        self.raw(&binding.run.expected_epoch.to_be_bytes())?;
        self.target(&binding.access)?;
        self.raw(&binding.attempt)?;
        self.raw(&binding.nonce)?;
        self.raw(&binding.issued_ms.to_be_bytes())?;
        self.raw(&binding.expires_ms.to_be_bytes())?;
        self.field(binding.user_key_blob)?;
        self.field(value.proof.host_key_blob)?;
        self.field(value.proof.host_signature_blob)?;
        self.field(value.proof.userauth_payload)?;
        match value.decision {
            SshConsentDecision::Deny => self.tag(0),
            SshConsentDecision::Approve { signature_blob } => {
                if signature_blob.is_empty() || signature_blob.len() > 128 {
                    return Err(PayloadError::Bounds);
                }
                self.tag(1)?;
                self.field(signature_blob)
            }
        }
    }
}
