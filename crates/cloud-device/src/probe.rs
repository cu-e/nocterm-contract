//! Device head probes in two steps, for a device whose signing key stays outside this crate.
//!
//! 1. [`UnsignedHeadProbe::new`] builds the fresh read-only query; the caller signs
//!    [`UnsignedHeadProbe::signing_bytes`] with the device's Ed25519 key.
//! 2. [`UnsignedHeadProbe::seal`] verifies that signature under the device key the query names
//!    and seals the query from the account key pair to the pinned runner.
//! 3. The caller sends `CloudService.ProbeHead` with [`SealedHeadProbe::scope`],
//!    [`SealedHeadProbe::probe_id`], [`SealedHeadProbe::ciphertext`] and
//!    [`SealedHeadProbe::expires_at_ms`], and passes the reply to
//!    [`SealedHeadProbe::open_reply`], which accepts only the pinned runner's witness to this
//!    exact query while it is fresh.
use crate::{AccountScope, CloudDeviceError, DeviceIdentity, records::TrustedRunner};
use nocterm_hub_model::cloud::{
    capabilities::CapabilityWindow,
    head::{
        CatalogHeadCursor, HeadProbeError, HeadProbeKeys, HeadProbeScope, HeadQuery, HeadTarget,
        HeadValue, MAX_HEAD_PROBE_LIFETIME_MS, MAX_HEAD_QUERY_ENVELOPE_BYTES,
        MAX_HEAD_REPLY_ENVELOPE_BYTES, SignedHeadQuery,
    },
};
use nocterm_keys::{
    AccountKeyPair,
    cloud::{open_head_witness, seal_head_query},
    random_bytes,
};

/// What a probe asks the runner: a page of its chat catalog, or one chat's head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeTarget {
    /// The first catalog page (`None`) or the page after a witnessed cursor.
    Catalog(Option<CatalogHeadCursor>),
    Chat {
        chat_id: [u8; 16],
        key_epoch: u64,
    },
}
impl ProbeTarget {
    fn head(self) -> HeadTarget {
        match self {
            Self::Catalog(after) => HeadTarget::Catalog { after },
            Self::Chat { chat_id, key_epoch } => HeadTarget::Chat {
                chat_id,
                chat_key_epoch: key_epoch,
            },
        }
    }
}

/// A fresh query waiting for the device signature.
#[derive(Clone, Debug)]
pub struct UnsignedHeadProbe {
    query: HeadQuery,
}
impl UnsignedHeadProbe {
    /// Builds a query with a fresh probe id and challenge from the operating system.
    pub fn new(
        scope: &AccountScope,
        account_public_key: [u8; 32],
        runner: &TrustedRunner,
        device: &DeviceIdentity,
        target: ProbeTarget,
        now_ms: i64,
    ) -> Result<Self, CloudDeviceError> {
        Self::with_nonces(
            scope,
            account_public_key,
            runner,
            device,
            target,
            now_ms,
            (random_bytes()?, random_bytes()?),
        )
    }
    /// As [`Self::new`] with a caller-chosen probe id and challenge (fixtures only: a reused
    /// challenge is not a freshness proof).
    pub fn with_nonces(
        scope: &AccountScope,
        account_public_key: [u8; 32],
        runner: &TrustedRunner,
        device: &DeviceIdentity,
        target: ProbeTarget,
        now_ms: i64,
        (probe_id, challenge): ([u8; 16], [u8; 32]),
    ) -> Result<Self, CloudDeviceError> {
        if !scope.is_account_key(&account_public_key) {
            return Err(CloudDeviceError::Binding);
        }
        let expires_at_ms = now_ms
            .checked_add(MAX_HEAD_PROBE_LIFETIME_MS)
            .ok_or(HeadProbeError::Time)?
            .min(device.session_expires_at_ms());
        let pins = runner.pins();
        let query = HeadQuery {
            scope: HeadProbeScope {
                namespace: scope.namespace(),
                runner: runner.runner(),
                keys: HeadProbeKeys {
                    account: account_public_key,
                    runner_encryption: pins.encryption,
                    runner_signing: pins.signing,
                },
            },
            issuer: device.issuer(),
            probe_id,
            challenge,
            window: CapabilityWindow {
                issued_at_ms: now_ms,
                expires_at_ms,
            },
            target: target.head(),
        };
        query.require_fresh(now_ms)?;
        Ok(Self { query })
    }
    /// The exact bytes the device signs (Ed25519, no prehash).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CloudDeviceError> {
        Ok(self.query.canonical_bytes()?)
    }
    /// Verifies the device signature and seals the query to the runner.
    pub fn seal(
        self,
        account: &AccountKeyPair,
        signature: &[u8],
    ) -> Result<SealedHeadProbe, CloudDeviceError> {
        let signature: [u8; 64] = signature.try_into().map_err(|_| {
            CloudDeviceError::Signature(nocterm_keys::SignatureError::MalformedSignature)
        })?;
        let signed = SignedHeadQuery::new(self.query, signature).map_err(|error| match error {
            HeadProbeError::Signature(error) => CloudDeviceError::Signature(error),
            error => error.into(),
        })?;
        let ciphertext = seal_head_query(account, &signed)?;
        if ciphertext.len() > MAX_HEAD_QUERY_ENVELOPE_BYTES {
            return Err(HeadProbeError::Bounds.into());
        }
        let scope = signed.query().scope.canonical_bytes()?;
        Ok(SealedHeadProbe {
            query: signed.query().clone(),
            scope,
            ciphertext,
        })
    }
}

/// A sealed query; it is single-use and answers only within its window.
#[derive(Clone, Debug)]
pub struct SealedHeadProbe {
    query: HeadQuery,
    scope: Vec<u8>,
    ciphertext: Vec<u8>,
}
impl SealedHeadProbe {
    /// `CloudHeadProbe.scope`.
    pub fn scope(&self) -> &[u8] {
        &self.scope
    }
    /// `CloudHeadProbe.probe_id`.
    pub fn probe_id(&self) -> [u8; 16] {
        self.query.probe_id
    }
    /// `CloudHeadProbe.ciphertext`.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    /// `CloudHeadProbe.expires_at_ms`; the caller should also stop waiting at this time.
    pub fn expires_at_ms(&self) -> i64 {
        self.query.window.expires_at_ms
    }
    /// Opens `CloudHeadProbeReply` and returns the witnessed value.
    pub fn open_reply(
        &self,
        account: &AccountKeyPair,
        reply_scope: &[u8],
        reply_probe_id: &[u8],
        ciphertext: &[u8],
        now_ms: i64,
    ) -> Result<HeadValue, CloudDeviceError> {
        if reply_scope != self.scope.as_slice() || reply_probe_id != self.query.probe_id {
            return Err(HeadProbeError::Scope.into());
        }
        if ciphertext.is_empty() || ciphertext.len() > MAX_HEAD_REPLY_ENVELOPE_BYTES {
            return Err(HeadProbeError::Bounds.into());
        }
        let witness = open_head_witness(account, &self.query, ciphertext, now_ms)?;
        Ok(witness.witness().value.clone())
    }
}

#[cfg(test)]
mod tests;
