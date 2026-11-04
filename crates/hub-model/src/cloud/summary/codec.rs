//! The strict canonical bytes of a summary under its context.
use super::{
    BoundServer, ChatState, ChatSummary, MAX_BOUND_SERVERS, MAX_SUMMARY_BYTES, MAX_TITLE_BYTES,
    SUMMARY_LABEL, ServerState, SummaryContext, SummaryError, SummaryHead, SummaryHost,
    SummaryModel,
};
use crate::cloud::{
    CommandError, MAX_HEADER_BYTES,
    codec::{BoundedWriter, Reader},
};

struct Out(BoundedWriter);
impl Out {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), SummaryError> {
        self.0.extend(bytes).map_err(bounds)
    }
    fn field(&mut self, bytes: &[u8]) -> Result<(), SummaryError> {
        self.0.field(bytes).map_err(bounds)
    }
    fn flag(&mut self, value: bool) -> Result<(), SummaryError> {
        self.raw(&[u8::from(value)])
    }
}
fn bounds(error: CommandError) -> SummaryError {
    match error {
        CommandError::PlaintextTooLarge => SummaryError::Bounds,
        other => other.into(),
    }
}

pub(super) fn write(
    context: &SummaryContext,
    summary: &ChatSummary,
) -> Result<Vec<u8>, SummaryError> {
    let mut out = Out(BoundedWriter::buffer(MAX_SUMMARY_BYTES));
    out.field(SUMMARY_LABEL)?;
    out.field(&context.canonical_bytes()?)?;
    out.flag(summary.head.is_some())?;
    if let Some(head) = summary.head {
        out.raw(&head.sequence.to_be_bytes())?;
        out.raw(&head.ciphertext_digest)?;
    }
    out.raw(&summary.control_revision.to_be_bytes())?;
    out.raw(&summary.created_at_ms.to_be_bytes())?;
    out.raw(&summary.last_activity_ms.to_be_bytes())?;
    out.field(summary.title.as_bytes())?;
    match &summary.host {
        SummaryHost::Managed { agent_id } => {
            out.raw(&[1])?;
            out.field(agent_id.as_str().as_bytes())?;
        }
        SummaryHost::Own => out.raw(&[2])?,
    }
    out.flag(summary.model.is_some())?;
    if let Some(model) = &summary.model {
        out.field(model.provider.as_str().as_bytes())?;
        out.field(model.model.as_str().as_bytes())?;
    }
    out.raw(&[summary.state as u8])?;
    out.raw(&summary.pending_approvals.to_be_bytes())?;
    out.raw(&[u8::try_from(summary.servers.len()).map_err(|_| SummaryError::Value)?])?;
    for server in &summary.servers {
        out.field(server.host.as_str().as_bytes())?;
        out.raw(&server.port.to_be_bytes())?;
        out.field(server.user.as_str().as_bytes())?;
        out.raw(&[server.state as u8])?;
        out.flag(server.valid_before_ms.is_some())?;
        if let Some(at) = server.valid_before_ms {
            out.raw(&at.to_be_bytes())?;
        }
    }
    out.raw(&summary.features.to_be_bytes())?;
    Ok(out.0.into_bytes()?)
}

fn flag(reader: &mut Reader<'_>) -> Result<bool, SummaryError> {
    match reader.array::<1>()? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(SummaryError::Malformed),
    }
}
fn u64_of(reader: &mut Reader<'_>) -> Result<u64, SummaryError> {
    Ok(u64::from_be_bytes(reader.array()?))
}
fn i64_of(reader: &mut Reader<'_>) -> Result<i64, SummaryError> {
    Ok(i64::from_be_bytes(reader.array()?))
}

pub(super) fn read(bytes: &[u8]) -> Result<(SummaryContext, ChatSummary), SummaryError> {
    if bytes.len() > MAX_SUMMARY_BYTES {
        return Err(SummaryError::Bounds);
    }
    let mut reader = Reader::new(bytes);
    if reader.field(64)? != SUMMARY_LABEL {
        return Err(SummaryError::Malformed);
    }
    let context = SummaryContext::from_canonical_bytes(reader.field(MAX_HEADER_BYTES)?)?;
    let head = if flag(&mut reader)? {
        Some(SummaryHead {
            sequence: u64_of(&mut reader)?,
            ciphertext_digest: reader.array()?,
        })
    } else {
        None
    };
    let control_revision = u64_of(&mut reader)?;
    let created_at_ms = i64_of(&mut reader)?;
    let last_activity_ms = i64_of(&mut reader)?;
    let title = core::str::from_utf8(reader.field(MAX_TITLE_BYTES)?)
        .map_err(|_| SummaryError::Malformed)?
        .to_owned();
    let host = match reader.array::<1>()? {
        [1] => SummaryHost::Managed {
            agent_id: reader.text()?,
        },
        [2] => SummaryHost::Own,
        _ => return Err(SummaryError::Value),
    };
    let model = if flag(&mut reader)? {
        Some(SummaryModel {
            provider: reader.text()?,
            model: reader.text()?,
        })
    } else {
        None
    };
    let [state] = reader.array::<1>()?;
    let state = ChatState::from_tag(state)?;
    let pending_approvals = u16::from_be_bytes(reader.array()?);
    let [count] = reader.array::<1>()?;
    let count = usize::from(count);
    if count > MAX_BOUND_SERVERS {
        return Err(SummaryError::Value);
    }
    let mut servers = Vec::with_capacity(count);
    for _ in 0..count {
        let host = reader.text()?;
        let port = u16::from_be_bytes(reader.array()?);
        let user = reader.text()?;
        let [state] = reader.array::<1>()?;
        let state = ServerState::from_tag(state)?;
        let valid_before_ms = if flag(&mut reader)? {
            Some(i64_of(&mut reader)?)
        } else {
            None
        };
        servers.push(BoundServer {
            host,
            port,
            user,
            state,
            valid_before_ms,
        });
    }
    let features = u32::from_be_bytes(reader.array()?);
    reader.finish()?;
    Ok((
        context,
        ChatSummary {
            head,
            control_revision,
            created_at_ms,
            last_activity_ms,
            title,
            host,
            model,
            state,
            pending_approvals,
            servers,
            features,
        },
    ))
}
