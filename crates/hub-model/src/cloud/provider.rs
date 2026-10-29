//! Finite, runner-attested boot recipients for memory-only provider credentials.
use super::{
    CloudNamespace, CloudTextId, CommandError, RunnerCoordinate,
    codec::{self, Reader},
};
use crate::pop::{self, SignatureError};
pub const MAX_PROVIDER_SECRET_BYTES: usize = 16 * 1024;
pub const MAX_PROVIDER_LEASE_BYTES: usize = MAX_PROVIDER_SECRET_BYTES + 74;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootWindow {
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootDescriptor {
    namespace: CloudNamespace,
    runner: RunnerCoordinate,
    boot_id: [u8; 16],
    recipient: [u8; 32],
    window: BootWindow,
}
impl BootDescriptor {
    pub fn new(
        namespace: CloudNamespace,
        runner: RunnerCoordinate,
        boot_id: [u8; 16],
        recipient: [u8; 32],
        window: BootWindow,
    ) -> Result<Self, ProviderLeaseError> {
        let duration = window
            .expires_at_ms
            .checked_sub(window.issued_at_ms)
            .ok_or(ProviderLeaseError::Time)?;
        if runner.key_epoch == 0 || duration <= 0 || duration > 30 * 60 * 1000 {
            return Err(ProviderLeaseError::Time);
        }
        Ok(Self {
            namespace,
            runner,
            boot_id,
            recipient,
            window,
        })
    }
    pub fn namespace(&self) -> &CloudNamespace {
        &self.namespace
    }
    pub fn runner(&self) -> RunnerCoordinate {
        self.runner
    }
    pub fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }
    pub fn recipient(&self) -> [u8; 32] {
        self.recipient
    }
    pub fn window(&self) -> BootWindow {
        self.window
    }
    pub fn require_current(&self, now_ms: i64) -> Result<(), ProviderLeaseError> {
        if now_ms >= self.window.expires_at_ms
            || self.window.issued_at_ms > now_ms.saturating_add(60_000)
        {
            return Err(ProviderLeaseError::Time);
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProviderLeaseError> {
        let mut out = Vec::with_capacity(512);
        codec::field(&mut out, b"nocterm/cloud-provider-boot/v1")?;
        codec::field(&mut out, self.namespace.hub_instance_id.as_str().as_bytes())?;
        codec::field(&mut out, self.namespace.account_id.as_str().as_bytes())?;
        out.extend_from_slice(&self.runner.id);
        out.extend_from_slice(&self.runner.key_epoch.to_be_bytes());
        out.extend_from_slice(&self.boot_id);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.window.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.window.expires_at_ms.to_be_bytes());
        Ok(out)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProviderLeaseError> {
        if bytes.len() > 512 {
            return Err(ProviderLeaseError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-provider-boot/v1" {
            return Err(ProviderLeaseError::Malformed);
        }
        let namespace = CloudNamespace {
            hub_instance_id: reader.text()?,
            account_id: reader.text()?,
        };
        let runner = RunnerCoordinate {
            id: reader.array()?,
            key_epoch: u64::from_be_bytes(reader.array()?),
        };
        let boot_id = reader.array()?;
        let recipient = reader.array()?;
        let window = BootWindow {
            issued_at_ms: i64::from_be_bytes(reader.array()?),
            expires_at_ms: i64::from_be_bytes(reader.array()?),
        };
        reader.finish()?;
        Self::new(namespace, runner, boot_id, recipient, window)
    }
}

/// Verify against the stable runner signing key retained in account setup.
#[derive(Clone, Debug)]
pub struct SignedBootDescriptor {
    descriptor: BootDescriptor,
    signature: [u8; 64],
}
impl SignedBootDescriptor {
    pub fn new(descriptor: BootDescriptor, signature: [u8; 64]) -> Self {
        Self {
            descriptor,
            signature,
        }
    }
    pub fn descriptor(&self) -> &BootDescriptor {
        &self.descriptor
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProviderLeaseError> {
        let mut out = Vec::with_capacity(580);
        codec::field(&mut out, &self.descriptor.canonical_bytes()?)?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProviderLeaseError> {
        if bytes.len() > 580 {
            return Err(ProviderLeaseError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        let descriptor = BootDescriptor::from_canonical_bytes(reader.field(512)?)?;
        let signature = reader.array()?;
        reader.finish()?;
        Ok(Self::new(descriptor, signature))
    }
    pub fn verify(
        &self,
        pinned_signer: &[u8; 32],
        expected_namespace: &CloudNamespace,
        expected_runner: RunnerCoordinate,
        now_ms: i64,
    ) -> Result<VerifiedBootDescriptor, ProviderLeaseError> {
        if self.descriptor.namespace() != expected_namespace
            || self.descriptor.runner() != expected_runner
        {
            return Err(ProviderLeaseError::Context);
        }
        self.descriptor.require_current(now_ms)?;
        pop::verify(
            pinned_signer,
            &self.descriptor.canonical_bytes()?,
            &self.signature,
        )?;
        Ok(VerifiedBootDescriptor {
            descriptor: self.descriptor.clone(),
        })
    }
}
#[derive(Clone, Debug)]
pub struct VerifiedBootDescriptor {
    descriptor: BootDescriptor,
}
impl VerifiedBootDescriptor {
    pub fn descriptor(&self) -> &BootDescriptor {
        &self.descriptor
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderLeaseContext {
    boot: BootDescriptor,
    provider_reference: CloudTextId,
    lease_id: [u8; 16],
    expires_at_ms: i64,
}
impl ProviderLeaseContext {
    pub fn new(
        boot: BootDescriptor,
        provider_reference: CloudTextId,
        lease_id: [u8; 16],
        expires_at_ms: i64,
    ) -> Result<Self, ProviderLeaseError> {
        if expires_at_ms > boot.window().expires_at_ms
            || expires_at_ms <= boot.window().issued_at_ms
        {
            return Err(ProviderLeaseError::Time);
        }
        Ok(Self {
            boot,
            provider_reference,
            lease_id,
            expires_at_ms,
        })
    }
    pub fn boot(&self) -> &BootDescriptor {
        &self.boot
    }
    pub fn provider_reference(&self) -> &CloudTextId {
        &self.provider_reference
    }
    pub fn lease_id(&self) -> [u8; 16] {
        self.lease_id
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
    pub fn require_current(&self, now_ms: i64) -> Result<(), ProviderLeaseError> {
        self.boot.require_current(now_ms)?;
        if now_ms >= self.expires_at_ms {
            return Err(ProviderLeaseError::Time);
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProviderLeaseError> {
        let mut out = Vec::with_capacity(768);
        codec::field(&mut out, b"nocterm/cloud-provider-lease-context/v1")?;
        codec::field(&mut out, &self.boot.canonical_bytes()?)?;
        codec::field(&mut out, self.provider_reference.as_str().as_bytes())?;
        out.extend_from_slice(&self.lease_id);
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(out)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProviderLeaseError> {
        if bytes.len() > 1024 {
            return Err(ProviderLeaseError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-provider-lease-context/v1" {
            return Err(ProviderLeaseError::Malformed);
        }
        let boot = BootDescriptor::from_canonical_bytes(reader.field(512)?)?;
        let reference = reader.text()?;
        let lease_id = reader.array()?;
        let expires = i64::from_be_bytes(reader.array()?);
        reader.finish()?;
        Self::new(boot, reference, lease_id, expires)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderLeaseError {
    #[error("malformed provider boot/lease context")]
    Malformed,
    #[error("provider boot/lease time window is invalid or expired")]
    Time,
    #[error("provider boot belongs to another account, hub or runner")]
    Context,
    #[error("provider boot/lease framing is invalid")]
    Framing(#[from] CommandError),
    #[error("provider boot attestation is invalid")]
    Signature(#[from] SignatureError),
}
