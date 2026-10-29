//! Borrow variable-length content from an already bounded decrypted command.
use super::{
    PayloadError,
    values::{
        ApprovalChoice, ApprovalPayload, AuthenticationSelection, ExecutionReference, GrantClass,
        GrantPayload, GrantReference, GrantWindow, ImageMime, InferenceLimits, IssuerRevocation,
        ModelSelection, PromptPart, PromptPayload, ScopedGrantReference, SessionReference,
        SshConsentAnswer, SshConsentDecision, TargetAccess, TargetSelection,
    },
};
use crate::cloud::{
    MAX_PLAINTEXT_BYTES, RunCoordinate,
    codec::Reader,
    provider::{MAX_PROVIDER_LEASE_BYTES, ProviderLeaseContext},
};
pub(in crate::cloud) struct PayloadReader<'a> {
    reader: Reader<'a>,
}
impl<'a> PayloadReader<'a> {
    pub(in crate::cloud) fn new(bytes: &'a [u8]) -> Result<Self, PayloadError> {
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(PayloadError::Bounds);
        }
        Ok(Self {
            reader: Reader::new(bytes),
        })
    }
    pub(in crate::cloud) fn finish(self) -> Result<(), PayloadError> {
        Ok(self.reader.finish()?)
    }
    pub(in crate::cloud) fn array<const N: usize>(&mut self) -> Result<[u8; N], PayloadError> {
        Ok(self.reader.array()?)
    }
    pub(in crate::cloud) fn field(&mut self, limit: usize) -> Result<&'a [u8], PayloadError> {
        Ok(self.reader.field(limit)?)
    }
    pub(in crate::cloud) fn tag(&mut self) -> Result<u8, PayloadError> {
        Ok(self.array::<1>()?[0])
    }
    pub(in crate::cloud) fn present(&mut self) -> Result<bool, PayloadError> {
        match self.tag()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PayloadError::Value),
        }
    }
    pub(in crate::cloud) fn target(&mut self) -> Result<TargetAccess, PayloadError> {
        let target = TargetSelection {
            host_key: self.array()?,
            route: self.array()?,
            principal: self.reader.text()?,
            workspace: self.array()?,
        };
        let authentication = AuthenticationSelection {
            public_key: self.array()?,
            credential_revision: self.array()?,
        };
        Ok(TargetAccess {
            target,
            authentication,
        })
    }
    pub(in crate::cloud) fn session(&mut self) -> Result<SessionReference, PayloadError> {
        Ok(SessionReference {
            id: self.array()?,
            epoch: u64::from_be_bytes(self.array()?),
            access: self.target()?,
        })
    }
    pub(in crate::cloud) fn grant(&mut self) -> Result<GrantReference, PayloadError> {
        Ok(GrantReference {
            id: self.array()?,
            epoch: u64::from_be_bytes(self.array()?),
        })
    }
    pub(in crate::cloud) fn model(&mut self) -> Result<ModelSelection, PayloadError> {
        Ok(ModelSelection {
            provider: self.reader.text()?,
            model: self.reader.text()?,
            pricing_policy: self.reader.text()?,
        })
    }
    pub(in crate::cloud) fn limits(&mut self) -> Result<InferenceLimits, PayloadError> {
        Ok(InferenceLimits {
            calls: u32::from_be_bytes(self.array()?),
            turns: u32::from_be_bytes(self.array()?),
            request_bytes: u64::from_be_bytes(self.array()?),
            output_bytes: u64::from_be_bytes(self.array()?),
            output_tokens: u64::from_be_bytes(self.array()?),
            spend_micros: u64::from_be_bytes(self.array()?),
            deadline_ms: i64::from_be_bytes(self.array()?),
        })
    }
    pub(in crate::cloud) fn window(&mut self) -> Result<GrantWindow, PayloadError> {
        Ok(GrantWindow {
            issued_at_ms: i64::from_be_bytes(self.array()?),
            expires_at_ms: i64::from_be_bytes(self.array()?),
        })
    }
    pub(in crate::cloud) fn execution(&mut self) -> Result<ExecutionReference, PayloadError> {
        Ok(ExecutionReference {
            run: RunCoordinate {
                id: self.array()?,
                expected_epoch: u64::from_be_bytes(self.array()?),
            },
            session: self.session()?,
            grant: self.grant()?,
        })
    }
    pub(in crate::cloud) fn prompt(&mut self) -> Result<PromptPayload<'a>, PayloadError> {
        let (model, target, existing_session) = self.prompt_selection()?;
        let inference = self.limits()?;
        let content = self.prompt_content()?;
        Ok(PromptPayload {
            content,
            model,
            target,
            existing_session,
            inference,
        })
    }
    pub(in crate::cloud) fn prompt_selection(
        &mut self,
    ) -> Result<
        (
            ModelSelection,
            Option<TargetAccess>,
            Option<SessionReference>,
        ),
        PayloadError,
    > {
        let model = self.model()?;
        let target = if self.present()? {
            Some(self.target()?)
        } else {
            None
        };
        let session = if self.present()? {
            Some(self.session()?)
        } else {
            None
        };
        Ok((model, target, session))
    }
    pub(in crate::cloud) fn prompt_content(&mut self) -> Result<Vec<PromptPart<'a>>, PayloadError> {
        let count = usize::from(u16::from_be_bytes(self.array()?));
        if count == 0 || count > 128 {
            return Err(PayloadError::Bounds);
        }
        let mut content = Vec::with_capacity(count);
        for _ in 0..count {
            content.push(match self.tag()? {
                1 => PromptPart::Text(
                    core::str::from_utf8(self.field(MAX_PLAINTEXT_BYTES)?)
                        .map_err(|_| PayloadError::Value)?,
                ),
                2 => {
                    let mime = match self.tag()? {
                        1 => ImageMime::Png,
                        2 => ImageMime::Jpeg,
                        3 => ImageMime::Gif,
                        4 => ImageMime::Webp,
                        _ => return Err(PayloadError::Value),
                    };
                    PromptPart::Image {
                        mime,
                        bytes: self.field(MAX_PLAINTEXT_BYTES)?,
                    }
                }
                _ => return Err(PayloadError::Value),
            });
        }
        Ok(content)
    }
    pub(in crate::cloud) fn approval(&mut self) -> Result<ApprovalPayload, PayloadError> {
        let intent = self.array()?;
        let arguments_digest = self.array()?;
        let execution = self.execution()?;
        let choice = match self.tag()? {
            1 => ApprovalChoice::Approve,
            2 => ApprovalChoice::Deny,
            3 => ApprovalChoice::ReconcileSucceeded,
            4 => ApprovalChoice::ReconcileFailed,
            5 => ApprovalChoice::ReconcileKnown {
                result_digest: self.array()?,
            },
            _ => return Err(PayloadError::Value),
        };
        Ok(ApprovalPayload {
            intent,
            arguments_digest,
            execution,
            choice,
        })
    }
    pub(in crate::cloud) fn grant_payload(&mut self) -> Result<GrantPayload<'a>, PayloadError> {
        Ok(match self.tag()? {
            1 => GrantPayload::Inference {
                grant: self.grant()?,
                model: self.model()?,
                window: self.window()?,
                limits: self.limits()?,
            },
            2 => GrantPayload::Tools {
                grant: self.grant()?,
                session: self.session()?,
                window: self.window()?,
                operations: u32::from_be_bytes(self.array()?),
                capabilities: self.tag()?,
            },
            3 => {
                let grant = self.grant()?;
                let context = ProviderLeaseContext::from_canonical_bytes(self.field(1024)?)?;
                let count = usize::from(self.tag()?);
                if count == 0 || count > 32 {
                    return Err(PayloadError::Bounds);
                }
                let mut allowed_models = Vec::with_capacity(count);
                for _ in 0..count {
                    allowed_models.push(self.reader.text()?);
                }
                GrantPayload::Provider {
                    grant,
                    context,
                    allowed_models,
                    capsule: self.field(MAX_PROVIDER_LEASE_BYTES)?,
                }
            }
            _ => return Err(PayloadError::Value),
        })
    }
    pub(in crate::cloud) fn scoped_grant(&mut self) -> Result<ScopedGrantReference, PayloadError> {
        let class = match self.tag()? {
            1 => GrantClass::Inference,
            2 => GrantClass::Tools,
            3 => GrantClass::Provider,
            _ => return Err(PayloadError::Value),
        };
        Ok(ScopedGrantReference {
            class,
            grant: self.grant()?,
        })
    }
    pub(in crate::cloud) fn issuer_revoke(&mut self) -> Result<IssuerRevocation, PayloadError> {
        let device = self.reader.text()?;
        let signing_key = self.array()?;
        let control_cutoff = u64::from_be_bytes(self.array()?);
        let count = usize::from(self.tag()?);
        if count > 64 {
            return Err(PayloadError::Bounds);
        }
        let mut grants = Vec::with_capacity(count);
        for _ in 0..count {
            grants.push(self.scoped_grant()?);
        }
        Ok(IssuerRevocation {
            device,
            signing_key,
            control_cutoff,
            grants,
        })
    }
    pub(in crate::cloud) fn ssh_answer(&mut self) -> Result<SshConsentAnswer<'a>, PayloadError> {
        let binding = super::session_codec::read_ssh_binding(self)?;
        let proof = super::session_codec::read_proof(self)?;
        let decision = match self.tag()? {
            0 => SshConsentDecision::Deny,
            1 => SshConsentDecision::Approve {
                signature_blob: self.field(128)?,
            },
            _ => return Err(PayloadError::Value),
        };
        Ok(SshConsentAnswer {
            binding,
            proof,
            decision,
        })
    }
}
