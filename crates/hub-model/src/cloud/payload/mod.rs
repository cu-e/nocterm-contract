//! The sole versioned semantic command payload codec. Descriptive values grant no authority.
pub(in crate::cloud) mod reader;
mod session;
pub(in crate::cloud) mod session_codec;
mod values;
pub use session::*;
pub(in crate::cloud) mod writer;
use crate::cloud::{
    CommandError, CommandHeader, CommandKind, SignedCommand, provider::ProviderLeaseError,
};
use reader::PayloadReader;
pub use values::*;
use writer::PayloadWriter;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloudCommandPayload<'a> {
    SubmitPrompt(Box<PromptPayload<'a>>),
    Stop,
    ResolveApproval(Box<ApprovalPayload>),
    IssueGrant(Box<GrantPayload<'a>>),
    RevokeGrant(ScopedGrantReference),
    AnswerSshConsent(Box<SshConsentAnswer<'a>>),
    DeleteChat,
    RevokeIssuerGrants(Box<IssuerRevocation>),
    BeginSession(Box<BeginSession<'a>>),
}
impl<'a> CloudCommandPayload<'a> {
    pub fn kind(&self) -> CommandKind {
        match self {
            Self::SubmitPrompt(_) => CommandKind::SubmitPrompt,
            Self::Stop => CommandKind::Stop,
            Self::ResolveApproval(_) => CommandKind::ResolveApproval,
            Self::IssueGrant(_) => CommandKind::IssueGrant,
            Self::RevokeGrant(_) => CommandKind::RevokeGrant,
            Self::DeleteChat => CommandKind::DeleteChat,
            Self::RevokeIssuerGrants(_) => CommandKind::RevokeIssuerGrants,
            Self::AnswerSshConsent(_) => CommandKind::AnswerSshConsent,
            Self::BeginSession(_) => CommandKind::BeginSession,
        }
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PayloadError> {
        let mut out = PayloadWriter::new();
        self.write(&mut out)?;
        out.finish()
    }
    /// Validate with a counting sink; prompt and capsule bodies stay borrowed.
    pub fn validate(&self) -> Result<(), PayloadError> {
        self.write(&mut PayloadWriter::counter())
    }
    /// The signature/box producer still checks trust, expiry, replay and durable admission.
    pub fn from_command(command: &SignedCommand<'a>) -> Result<Self, PayloadError> {
        let value = Self::from_canonical_bytes(command.header().context().kind, command.payload())?;
        value.require_header(command.header())?;
        Ok(value)
    }
    pub fn require_header(&self, header: &CommandHeader) -> Result<(), PayloadError> {
        if self.kind() != header.context().kind {
            return Err(PayloadError::Kind);
        }
        let run = header.context().run;
        let requires_run = matches!(
            self,
            Self::Stop
                | Self::ResolveApproval(_)
                | Self::RevokeGrant(_)
                | Self::AnswerSshConsent(_)
                | Self::BeginSession(_)
        ) || matches!(self,Self::IssueGrant(grant) if !matches!(grant.as_ref(),GrantPayload::Provider {..}));
        if requires_run && run.is_none() {
            return Err(PayloadError::Value);
        }
        match self {
            Self::IssueGrant(value) if matches!(value.as_ref(),GrantPayload::Provider {context,..} if context.boot().namespace()!=&header.route().namespace || context.boot().runner()!=header.route().runner) => {
                Err(PayloadError::Value)
            }
            Self::ResolveApproval(value) if Some(value.execution.run) != run => {
                Err(PayloadError::Value)
            }
            Self::AnswerSshConsent(value) if Some(value.binding.run) != run => {
                Err(PayloadError::Value)
            }
            Self::BeginSession(value)
                if Some(value.run()) != run
                    || u64::try_from(header.context().issued_at_ms)
                        .ok()
                        .is_none_or(|issued| {
                            issued < value.issued_ms() || issued >= value.expires_ms()
                        }) =>
            {
                Err(PayloadError::Value)
            }
            Self::RevokeIssuerGrants(value)
                if value.device != header.issuer().device_id
                    || value.signing_key != header.issuer().signing_key
                    || value.control_cutoff > header.context().expected_chat_revision =>
            {
                Err(PayloadError::Value)
            }
            _ => Ok(()),
        }
    }
    pub fn from_canonical_bytes(
        expected: CommandKind,
        bytes: &'a [u8],
    ) -> Result<Self, PayloadError> {
        let mut reader = PayloadReader::new(bytes)?;
        if reader.field(64)? != b"nocterm/cloud-command-payload/v1" {
            return Err(PayloadError::Value);
        }
        let kind = CommandKind::try_from(u16::from_be_bytes(reader.array()?))?;
        if kind != expected {
            return Err(PayloadError::Kind);
        }
        let value = match kind {
            CommandKind::SubmitPrompt => Self::SubmitPrompt(Box::new(reader.prompt()?)),
            CommandKind::Stop => Self::Stop,
            CommandKind::ResolveApproval => Self::ResolveApproval(Box::new(reader.approval()?)),
            CommandKind::IssueGrant => Self::IssueGrant(Box::new(reader.grant_payload()?)),
            CommandKind::RevokeGrant => Self::RevokeGrant(reader.scoped_grant()?),
            CommandKind::DeleteChat => Self::DeleteChat,
            CommandKind::RevokeIssuerGrants => {
                Self::RevokeIssuerGrants(Box::new(reader.issuer_revoke()?))
            }
            CommandKind::AnswerSshConsent => Self::AnswerSshConsent(Box::new(reader.ssh_answer()?)),
            CommandKind::BeginSession => {
                Self::BeginSession(Box::new(session_codec::read_start(&mut reader)?))
            }
        };
        reader.finish()?;
        value.validate()?;
        Ok(value)
    }
    fn write(&self, out: &mut PayloadWriter) -> Result<(), PayloadError> {
        out.field(b"nocterm/cloud-command-payload/v1")?;
        out.raw(&(self.kind() as u16).to_be_bytes())?;
        match self {
            Self::SubmitPrompt(value) => out.prompt(value),
            Self::ResolveApproval(value) => out.approval(value),
            Self::IssueGrant(value) => out.grant_payload(value),
            Self::RevokeGrant(value) => out.scoped_grant(*value),
            Self::AnswerSshConsent(value) => out.ssh_answer(value),
            Self::BeginSession(value) => session_codec::write_start(out, value),
            Self::RevokeIssuerGrants(value) => out.issuer_revoke(value),
            Self::Stop | Self::DeleteChat => Ok(()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    #[error("Cloud command payload exceeds an aggregate or collection bound")]
    Bounds,
    #[error("Cloud command payload contains an invalid or unknown value")]
    Value,
    #[error("Cloud command payload does not match its signed purpose")]
    Kind,
    #[error("Cloud command payload framing is invalid")]
    Command(#[from] CommandError),
    #[error("Cloud provider grant context is invalid")]
    Provider(#[from] ProviderLeaseError),
}
#[cfg(test)]
mod tests;
