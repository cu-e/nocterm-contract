//! A fresh proof by a retained stable hub authority; an offered key is not a trust pin.
use super::{
    CloudTextId, CommandError, MAX_ENVELOPE_BYTES,
    codec::{self, Reader},
    relay::MAX_RELAY_FRAME_BYTES,
};
use crate::pop::{self, SignatureError};

pub const CLOUD_CAPABILITY_VERSION: u32 = 1;
/// Optional additive relay support; require this before publishing chat key material.
pub const CLOUD_FEATURE_CHAT_KEY_MATERIAL: u64 = 8;
/// Optional read-only rendezvous for a nonce-bound witness by the trusted R.
pub const CLOUD_FEATURE_FRESH_HEAD: u64 = 16;
/// Optional additive BeginSession9 and AuthenticationRequested12/SessionState13.
pub const CLOUD_FEATURE_SESSION_START: u64 = 32;
pub const CLOUD_REQUIRED_FEATURES: u64 = 1 | 2 | 4; // E2EE commands, replay, scoped runners.
pub const MAX_CAPABILITY_CLAIM_BYTES: usize = 512;
const MAX_WINDOW_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityLimits {
    pub version: u32,
    pub max_frame_bytes: u32,
    pub max_envelope_bytes: u32,
    pub features: u64,
}
impl CapabilityLimits {
    pub const fn v1() -> Self {
        Self {
            version: 1,
            max_frame_bytes: 16 * 1024,
            max_envelope_bytes: 32 * 1024 * 1024 + 78,
            features: CLOUD_REQUIRED_FEATURES,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityWindow {
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilitiesClaim {
    instance: CloudTextId,
    authority: [u8; 32],
    limits: CapabilityLimits,
    nonce: [u8; 16],
    window: CapabilityWindow,
}
impl CapabilitiesClaim {
    pub fn new(
        instance: CloudTextId,
        authority: [u8; 32],
        limits: CapabilityLimits,
        nonce: [u8; 16],
        window: CapabilityWindow,
    ) -> Result<Self, CapabilityError> {
        if limits.version != CLOUD_CAPABILITY_VERSION
            || limits.features & CLOUD_REQUIRED_FEATURES != CLOUD_REQUIRED_FEATURES
        {
            return Err(CapabilityError::Unsupported);
        }
        let frame = usize::try_from(limits.max_frame_bytes).map_err(|_| CapabilityError::Limits)?;
        let envelope =
            usize::try_from(limits.max_envelope_bytes).map_err(|_| CapabilityError::Limits)?;
        if frame == 0
            || frame > MAX_RELAY_FRAME_BYTES
            || envelope == 0
            || envelope > MAX_ENVELOPE_BYTES
        {
            return Err(CapabilityError::Limits);
        }
        let duration = window
            .expires_at_ms
            .checked_sub(window.issued_at_ms)
            .ok_or(CapabilityError::Window)?;
        if !(1..=MAX_WINDOW_MS).contains(&duration) {
            return Err(CapabilityError::Window);
        }
        Ok(Self {
            instance,
            authority,
            limits,
            nonce,
            window,
        })
    }
    pub fn instance(&self) -> &CloudTextId {
        &self.instance
    }
    pub fn authority(&self) -> [u8; 32] {
        self.authority
    }
    pub fn limits(&self) -> CapabilityLimits {
        self.limits
    }
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    pub fn window(&self) -> CapabilityWindow {
        self.window
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CapabilityError> {
        let mut bytes = Vec::with_capacity(256);
        codec::field(&mut bytes, b"nocterm/cloud-hub-capabilities/v1")?;
        codec::field(&mut bytes, self.instance.as_str().as_bytes())?;
        bytes.extend_from_slice(&self.authority);
        bytes.extend_from_slice(&self.limits.version.to_be_bytes());
        bytes.extend_from_slice(&self.limits.max_frame_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.limits.max_envelope_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.limits.features.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.window.issued_at_ms.to_be_bytes());
        bytes.extend_from_slice(&self.window.expires_at_ms.to_be_bytes());
        Ok(bytes)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CapabilityError> {
        if bytes.len() > MAX_CAPABILITY_CLAIM_BYTES {
            return Err(CapabilityError::Malformed);
        }
        let mut reader = Reader::new(bytes);
        if reader.field(64)? != b"nocterm/cloud-hub-capabilities/v1" {
            return Err(CapabilityError::Malformed);
        }
        let instance = reader.text()?;
        let authority = reader.array()?;
        let limits = CapabilityLimits {
            version: u32::from_be_bytes(reader.array()?),
            max_frame_bytes: u32::from_be_bytes(reader.array()?),
            max_envelope_bytes: u32::from_be_bytes(reader.array()?),
            features: u64::from_be_bytes(reader.array()?),
        };
        let nonce = reader.array()?;
        let window = CapabilityWindow {
            issued_at_ms: i64::from_be_bytes(reader.array()?),
            expires_at_ms: i64::from_be_bytes(reader.array()?),
        };
        reader.finish()?;
        Self::new(instance, authority, limits, nonce, window)
    }
}

/// Valid self-signature only. Call require_expected with an independent retained pin.
#[derive(Clone, Debug)]
pub struct SignedCapabilities {
    claim: CapabilitiesClaim,
    signature: [u8; 64],
}
impl SignedCapabilities {
    pub fn new(claim: CapabilitiesClaim, signature: [u8; 64]) -> Result<Self, CapabilityError> {
        pop::verify(&claim.authority, &claim.canonical_bytes()?, &signature)?;
        Ok(Self { claim, signature })
    }
    pub fn claim(&self) -> &CapabilitiesClaim {
        &self.claim
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
    pub fn require_expected(
        &self,
        instance: &str,
        authority: &[u8; 32],
        nonce: &[u8; 16],
        now_ms: i64,
    ) -> Result<(), CapabilityError> {
        if self.claim.instance.as_str() != instance || &self.claim.authority != authority {
            return Err(CapabilityError::Identity);
        }
        if &self.claim.nonce != nonce {
            return Err(CapabilityError::Nonce);
        }
        if now_ms >= self.claim.window.expires_at_ms {
            return Err(CapabilityError::Expired);
        }
        let future = self
            .claim
            .window
            .issued_at_ms
            .checked_sub(now_ms)
            .ok_or(CapabilityError::Window)?;
        if future > MAX_WINDOW_MS {
            return Err(CapabilityError::Window);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    #[error("malformed Cloud capability proof")]
    Malformed,
    #[error("the hub does not offer the required Cloud protocol")]
    Unsupported,
    #[error("the Cloud capability limits are unsafe or invalid")]
    Limits,
    #[error("the Cloud capability time window is invalid")]
    Window,
    #[error("the Cloud capability proof has expired")]
    Expired,
    #[error("the Cloud capability proof names another hub or authority")]
    Identity,
    #[error("the Cloud capability proof answers another invocation")]
    Nonce,
    #[error("the Cloud capability signature is invalid")]
    Signature(#[from] SignatureError),
    #[error("the Cloud capability framing is invalid")]
    Framing(#[from] CommandError),
}
