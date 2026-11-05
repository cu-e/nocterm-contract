//! The strict canonical bytes of the SSH binding values.
use super::{
    BindingWindow, MAX_BINDING_BYTES, MAX_BINDING_TARGETS, MAX_REQUEST_BYTES,
    MAX_SIGNED_BINDING_BYTES, MAX_SOURCE_ADDRESS_BYTES, MAX_SOURCE_ADDRESSES, SignedSshBinding,
    SshAccess, SshAccessUpdate, SshBinding, SshBindingRefusal, SshCertificateRequest,
    SshFormatError, SshServerId, SshServerReach, SshServerStatus, SshTarget,
};
use crate::cloud::{
    ChatCoordinate, CommandError, MAX_HEADER_BYTES,
    codec::{BoundedWriter, Reader},
    payload::GrantReference,
};

const BINDING_LABEL: &[u8] = b"nocterm/cloud-ssh-binding/v1";
const REQUEST_LABEL: &[u8] = b"nocterm/cloud-ssh-request/v1";
const ACCESS_LABEL: &[u8] = b"nocterm/cloud-ssh-access/v1";

struct Out(BoundedWriter);
impl Out {
    fn new(maximum: usize) -> Self {
        Self(BoundedWriter::buffer(maximum))
    }
    fn raw(&mut self, bytes: &[u8]) -> Result<(), SshFormatError> {
        self.0.extend(bytes).map_err(bounds)
    }
    fn field(&mut self, bytes: &[u8]) -> Result<(), SshFormatError> {
        self.0.field(bytes).map_err(bounds)
    }
    fn count(&mut self, count: usize) -> Result<(), SshFormatError> {
        self.raw(&[u8::try_from(count).map_err(|_| SshFormatError::Value)?])
    }
    fn grant(&mut self, grant: GrantReference) -> Result<(), SshFormatError> {
        self.raw(&grant.id)?;
        self.raw(&grant.epoch.to_be_bytes())
    }
    fn finish(self) -> Result<Vec<u8>, SshFormatError> {
        Ok(self.0.into_bytes()?)
    }
}
fn bounds(error: CommandError) -> SshFormatError {
    match error {
        CommandError::PlaintextTooLarge => SshFormatError::Bounds,
        other => other.into(),
    }
}

fn i64_of(reader: &mut Reader<'_>) -> Result<i64, SshFormatError> {
    Ok(i64::from_be_bytes(reader.array()?))
}
fn grant_of(reader: &mut Reader<'_>) -> Result<GrantReference, SshFormatError> {
    Ok(GrantReference {
        id: reader.array()?,
        epoch: u64::from_be_bytes(reader.array()?),
    })
}
fn count_of(reader: &mut Reader<'_>, maximum: usize) -> Result<usize, SshFormatError> {
    let [count] = reader.array::<1>()?;
    let count = usize::from(count);
    if count > maximum {
        return Err(SshFormatError::Value);
    }
    Ok(count)
}
fn label(reader: &mut Reader<'_>, expected: &[u8]) -> Result<(), SshFormatError> {
    if reader.field(64)? == expected {
        Ok(())
    } else {
        Err(SshFormatError::Malformed)
    }
}
fn bounded(bytes: &[u8], maximum: usize) -> Result<Reader<'_>, SshFormatError> {
    if bytes.len() > maximum {
        return Err(SshFormatError::Bounds);
    }
    Ok(Reader::new(bytes))
}

pub(super) fn write_binding(binding: &SshBinding) -> Result<Vec<u8>, SshFormatError> {
    let mut out = Out::new(MAX_BINDING_BYTES);
    out.field(BINDING_LABEL)?;
    out.field(&binding.chat.canonical_bytes()?)?;
    out.grant(binding.grant)?;
    out.raw(&binding.window.issued_at_ms.to_be_bytes())?;
    out.raw(&binding.window.expires_at_ms.to_be_bytes())?;
    out.raw(&binding.ca_key)?;
    out.count(binding.targets.len())?;
    for target in &binding.targets {
        out.raw(target.server.as_bytes())?;
        out.field(target.host.as_str().as_bytes())?;
        out.raw(&target.port.to_be_bytes())?;
        out.field(target.user.as_str().as_bytes())?;
        out.raw(&target.host_key_sha256)?;
    }
    out.finish()
}

pub(super) fn read_binding(bytes: &[u8]) -> Result<SshBinding, SshFormatError> {
    let mut reader = bounded(bytes, MAX_BINDING_BYTES)?;
    label(&mut reader, BINDING_LABEL)?;
    let chat = ChatCoordinate::from_canonical_bytes(reader.field(MAX_HEADER_BYTES)?)?;
    let grant = grant_of(&mut reader)?;
    let window = BindingWindow {
        issued_at_ms: i64_of(&mut reader)?,
        expires_at_ms: i64_of(&mut reader)?,
    };
    let ca_key = reader.array()?;
    let count = count_of(&mut reader, MAX_BINDING_TARGETS)?;
    let mut targets = Vec::with_capacity(count);
    for _ in 0..count {
        targets.push(SshTarget {
            server: SshServerId::from_bytes(reader.array()?),
            host: reader.text()?,
            port: u16::from_be_bytes(reader.array()?),
            user: reader.text()?,
            host_key_sha256: reader.array()?,
        });
    }
    reader.finish()?;
    Ok(SshBinding {
        chat,
        grant,
        window,
        ca_key,
        targets,
    })
}

pub(super) fn write_request(request: &SshCertificateRequest) -> Result<Vec<u8>, SshFormatError> {
    let mut out = Out::new(MAX_REQUEST_BYTES);
    out.field(REQUEST_LABEL)?;
    out.raw(&request.request)?;
    out.field(&request.binding.canonical_bytes()?)?;
    out.raw(&request.subject_key)?;
    out.count(request.source_addresses.len())?;
    for address in &request.source_addresses {
        out.field(address.as_bytes())?;
    }
    out.count(request.servers.len())?;
    for server in &request.servers {
        out.raw(server.as_bytes())?;
    }
    out.raw(&request.not_after_ms.to_be_bytes())?;
    out.finish()
}

pub(super) fn read_request(bytes: &[u8]) -> Result<SshCertificateRequest, SshFormatError> {
    let mut reader = bounded(bytes, MAX_REQUEST_BYTES)?;
    label(&mut reader, REQUEST_LABEL)?;
    let request = reader.array()?;
    let binding = SignedSshBinding::from_canonical_bytes(reader.field(MAX_SIGNED_BINDING_BYTES)?)?;
    let subject_key = reader.array()?;
    let count = count_of(&mut reader, MAX_SOURCE_ADDRESSES)?;
    let mut source_addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let address = core::str::from_utf8(reader.field(MAX_SOURCE_ADDRESS_BYTES)?)
            .map_err(|_| SshFormatError::Malformed)?;
        source_addresses.push(address.to_owned());
    }
    let count = count_of(&mut reader, MAX_BINDING_TARGETS)?;
    let mut servers = Vec::with_capacity(count);
    for _ in 0..count {
        servers.push(SshServerId::from_bytes(reader.array()?));
    }
    let not_after_ms = i64_of(&mut reader)?;
    reader.finish()?;
    Ok(SshCertificateRequest {
        request,
        binding,
        subject_key,
        source_addresses,
        servers,
        not_after_ms,
    })
}

pub(super) fn write_update(update: &SshAccessUpdate) -> Result<Vec<u8>, SshFormatError> {
    let mut out = Out::new(1024);
    out.field(ACCESS_LABEL)?;
    out.grant(update.grant)?;
    match update.access {
        SshAccess::Pending => out.raw(&[1])?,
        SshAccess::Active {
            request,
            valid_before_ms,
        } => {
            out.raw(&[2])?;
            out.raw(&request)?;
            out.raw(&valid_before_ms.to_be_bytes())?;
        }
        SshAccess::Refused(reason) => out.raw(&[3, reason as u8])?,
        SshAccess::Revoked => out.raw(&[4])?,
        SshAccess::Expired => out.raw(&[5])?,
    }
    out.count(update.servers.len())?;
    for status in &update.servers {
        out.raw(status.server.as_bytes())?;
        out.raw(&[status.reach as u8])?;
    }
    out.finish()
}

pub(super) fn read_update(bytes: &[u8]) -> Result<SshAccessUpdate, SshFormatError> {
    let mut reader = bounded(bytes, 1024)?;
    label(&mut reader, ACCESS_LABEL)?;
    let grant = grant_of(&mut reader)?;
    let access = match reader.array::<1>()? {
        [1] => SshAccess::Pending,
        [2] => SshAccess::Active {
            request: reader.array()?,
            valid_before_ms: i64_of(&mut reader)?,
        },
        [3] => SshAccess::Refused(match reader.array::<1>()? {
            [1] => SshBindingRefusal::NoSourceAddress,
            [2] => SshBindingRefusal::NoReachableServer,
            [3] => SshBindingRefusal::Invalid,
            _ => return Err(SshFormatError::Value),
        }),
        [4] => SshAccess::Revoked,
        [5] => SshAccess::Expired,
        _ => return Err(SshFormatError::Value),
    };
    let count = count_of(&mut reader, MAX_BINDING_TARGETS)?;
    let mut servers = Vec::with_capacity(count);
    for _ in 0..count {
        let server = SshServerId::from_bytes(reader.array()?);
        let reach = match reader.array::<1>()? {
            [1] => SshServerReach::Admitted,
            [2] => SshServerReach::Unreachable,
            _ => return Err(SshFormatError::Value),
        };
        servers.push(SshServerStatus { server, reach });
    }
    reader.finish()?;
    Ok(SshAccessUpdate {
        grant,
        access,
        servers,
    })
}
