//! Purpose-specific runner event identity; no public generic signing oracle.
use crate::{DeviceKey, KeyError};
use core::fmt;
use zeroize::Zeroizing;

pub struct RunnerSigningKey {
    key: DeviceKey,
}
impl RunnerSigningKey {
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Self {
            key: DeviceKey::generate()?,
        })
    }
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: DeviceKey::from_seed(seed),
        }
    }
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        self.key.seed()
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }
    /// Attests a finite boot recipient, with a distinct canonical purpose.
    pub fn attest_boot(
        &self,
        descriptor: nocterm_hub_model::cloud::provider::BootDescriptor,
    ) -> Result<
        nocterm_hub_model::cloud::provider::SignedBootDescriptor,
        nocterm_hub_model::cloud::provider::ProviderLeaseError,
    > {
        let signature = self.key.sign(&descriptor.canonical_bytes()?);
        Ok(nocterm_hub_model::cloud::provider::SignedBootDescriptor::new(descriptor, signature))
    }
    /// Attests only a bounded read-only witness under its dedicated canonical
    /// purpose. The caller supplies actual authenticated journal metadata.
    pub fn attest_head(
        &self,
        witness: nocterm_hub_model::cloud::head::HeadWitness,
    ) -> Result<
        nocterm_hub_model::cloud::head::SignedHeadWitness,
        nocterm_hub_model::cloud::head::HeadProbeError,
    > {
        use nocterm_hub_model::cloud::head::{HeadProbeError, SignedHeadWitness};
        if witness.query.scope.keys.runner_signing != self.public_key() {
            return Err(HeadProbeError::Scope);
        }
        let signature = self.key.sign(&witness.canonical_bytes()?);
        SignedHeadWitness::new(witness, signature)
    }
    pub(super) fn sign_record(&self, canonical_header: &[u8]) -> [u8; 64] {
        self.key.sign(canonical_header)
    }
}
impl fmt::Debug for RunnerSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerSigningKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}
