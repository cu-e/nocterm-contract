//! Shared canonical binding/proof fields for Begin, Request, State and old Answer6.
use super::{
    AuthenticationRequest, BeginSession, PayloadError, SessionBinding, SessionOutcome,
    SessionStartup, SessionState, SshConsentBinding, SshProof, reader::PayloadReader, session,
    writer::PayloadWriter,
};
use crate::cloud::RunCoordinate;

pub(super) fn write_binding(
    out: &mut PayloadWriter,
    value: &SessionBinding,
) -> Result<(), PayloadError> {
    session::check_attempt(value.run, &value.nonce, value.issued_ms, value.expires_ms)?;
    write_common(
        out,
        value.run,
        &value.access,
        &value.attempt,
        &value.nonce,
        value.issued_ms,
        value.expires_ms,
    )
}
fn write_common(
    out: &mut PayloadWriter,
    run: RunCoordinate,
    access: &super::TargetAccess,
    attempt: &[u8; 16],
    nonce: &[u8; 32],
    issued: u64,
    expires: u64,
) -> Result<(), PayloadError> {
    out.raw(&run.id)?;
    out.raw(&run.expected_epoch.to_be_bytes())?;
    out.target(access)?;
    out.raw(attempt)?;
    out.raw(nonce)?;
    out.raw(&issued.to_be_bytes())?;
    out.raw(&expires.to_be_bytes())
}
pub(super) fn write_ssh_binding(
    out: &mut PayloadWriter,
    value: &SshConsentBinding<'_>,
) -> Result<(), PayloadError> {
    // Keep Answer6's existing validation/layout unchanged. New Begin/Request
    // additionally check the nonzero nonce and representable original window.
    session::check_window(value.run, value.issued_ms, value.expires_ms)?;
    blob(value.user_key_blob, 1024)?;
    write_common(
        out,
        value.run,
        &value.access,
        &value.attempt,
        &value.nonce,
        value.issued_ms,
        value.expires_ms,
    )?;
    out.field(value.user_key_blob)
}
pub(super) fn write_proof(
    out: &mut PayloadWriter,
    value: &SshProof<'_>,
) -> Result<(), PayloadError> {
    blob(value.host_key_blob, 1024)?;
    blob(value.host_signature_blob, 1024)?;
    blob(value.userauth_payload, 4096)?;
    out.field(value.host_key_blob)?;
    out.field(value.host_signature_blob)?;
    out.field(value.userauth_payload)
}
fn blob(bytes: &[u8], maximum: usize) -> Result<(), PayloadError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(PayloadError::Bounds);
    }
    Ok(())
}
pub(super) fn write_start(
    out: &mut PayloadWriter,
    value: &BeginSession<'_>,
) -> Result<(), PayloadError> {
    match value {
        BeginSession::Local { binding, startup } => {
            out.tag(1)?;
            out.tag(*startup as u8)?;
            write_binding(out, binding)
        }
        BeginSession::Ssh { binding, startup } => {
            out.tag(2)?;
            out.tag(*startup as u8)?;
            session::check_attempt(
                binding.run,
                &binding.nonce,
                binding.issued_ms,
                binding.expires_ms,
            )?;
            write_ssh_binding(out, binding)
        }
    }
}
pub(in crate::cloud) fn write_request(
    out: &mut PayloadWriter,
    value: &AuthenticationRequest<'_>,
) -> Result<(), PayloadError> {
    session::check_attempt(
        value.binding.run,
        &value.binding.nonce,
        value.binding.issued_ms,
        value.binding.expires_ms,
    )?;
    out.tag(value.startup as u8)?;
    write_ssh_binding(out, &value.binding)?;
    write_proof(out, &value.proof)
}
pub(in crate::cloud) fn write_state(
    out: &mut PayloadWriter,
    value: &SessionState,
) -> Result<(), PayloadError> {
    write_binding(out, &value.binding)?;
    match &value.outcome {
        SessionOutcome::Established(receipt) => {
            if receipt.access != value.binding.access {
                return Err(PayloadError::Value);
            }
            out.tag(1)?;
            out.session(receipt)
        }
        SessionOutcome::Lost { session, reason } => {
            if session.access != value.binding.access {
                return Err(PayloadError::Value);
            }
            out.tag(2)?;
            out.session(session)?;
            out.tag(*reason as u8)
        }
        SessionOutcome::Refused(reason) => {
            out.tag(3)?;
            out.tag(*reason as u8)
        }
    }
}
fn read_common(input: &mut PayloadReader<'_>) -> Result<SessionBinding, PayloadError> {
    Ok(SessionBinding {
        run: RunCoordinate {
            id: input.array()?,
            expected_epoch: u64::from_be_bytes(input.array()?),
        },
        access: input.target()?,
        attempt: input.array()?,
        nonce: input.array()?,
        issued_ms: u64::from_be_bytes(input.array()?),
        expires_ms: u64::from_be_bytes(input.array()?),
    })
}
pub(super) fn read_ssh_binding<'a>(
    input: &mut PayloadReader<'a>,
) -> Result<SshConsentBinding<'a>, PayloadError> {
    let value = read_common(input)?;
    Ok(SshConsentBinding {
        run: value.run,
        access: value.access,
        attempt: value.attempt,
        nonce: value.nonce,
        issued_ms: value.issued_ms,
        expires_ms: value.expires_ms,
        user_key_blob: input.field(1024)?,
    })
}
pub(super) fn read_proof<'a>(input: &mut PayloadReader<'a>) -> Result<SshProof<'a>, PayloadError> {
    Ok(SshProof {
        host_key_blob: input.field(1024)?,
        host_signature_blob: input.field(1024)?,
        userauth_payload: input.field(4096)?,
    })
}
pub(super) fn read_start<'a>(
    input: &mut PayloadReader<'a>,
) -> Result<BeginSession<'a>, PayloadError> {
    let transport = input.tag()?;
    let startup = SessionStartup::from_tag(input.tag()?)?;
    match transport {
        1 => Ok(BeginSession::Local {
            binding: read_common(input)?,
            startup,
        }),
        2 => Ok(BeginSession::Ssh {
            binding: read_ssh_binding(input)?,
            startup,
        }),
        _ => Err(PayloadError::Value),
    }
}
pub(in crate::cloud) fn read_request<'a>(
    input: &mut PayloadReader<'a>,
) -> Result<AuthenticationRequest<'a>, PayloadError> {
    let startup = SessionStartup::from_tag(input.tag()?)?;
    Ok(AuthenticationRequest {
        binding: read_ssh_binding(input)?,
        startup,
        proof: read_proof(input)?,
    })
}
pub(in crate::cloud) fn read_state(
    input: &mut PayloadReader<'_>,
) -> Result<SessionState, PayloadError> {
    let binding = read_common(input)?;
    let outcome = match input.tag()? {
        1 => SessionOutcome::Established(input.session()?),
        2 => SessionOutcome::Lost {
            session: input.session()?,
            reason: super::SessionFailure::from_tag(input.tag()?)?,
        },
        3 => SessionOutcome::Refused(super::SessionFailure::from_tag(input.tag()?)?),
        _ => return Err(PayloadError::Value),
    };
    Ok(SessionState { binding, outcome })
}
