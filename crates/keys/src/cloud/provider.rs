//! Memory-only credential recipients deliberately have no seed export or restore API.
use crate::{
    AccountKeyPair, KeyError, OpenError, PublicKey, SealError,
    authenticated_box::AuthenticatedBoxKeys, random_bytes, seal,
};
use core::fmt;
pub use nocterm_hub_model::cloud::provider::{MAX_PROVIDER_LEASE_BYTES, MAX_PROVIDER_SECRET_BYTES};
use nocterm_hub_model::cloud::provider::{
    ProviderLeaseContext, ProviderLeaseError, VerifiedBootDescriptor,
};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

const HEADER_BYTES: usize = 2 + 32 + 24;
const INFO: &[u8] = b"nocterm-cloud-provider-lease-v1/auth";

/// One process boot's non-restorable X25519 identity. Drop destroys the recipient.
pub struct RunnerBootKey {
    secret: StaticSecret,
}
impl RunnerBootKey {
    pub fn generate() -> Result<Self, KeyError> {
        let seed = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self {
            secret: StaticSecret::from(*seed),
        })
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_array(x25519_dalek::PublicKey::from(&self.secret).to_bytes())
    }
    /// Opens only this live boot and finite context. Admission/replay/clock rollback
    /// handling belong to the runner's authority owner before installing the lease.
    pub fn open_provider_lease(
        &self,
        pinned_account: &PublicKey,
        context: &ProviderLeaseContext,
        ciphertext: &[u8],
        now_ms: i64,
    ) -> Result<OpenedProviderLease, ProviderSecretError> {
        context.require_current(now_ms)?;
        if context.boot().recipient() != self.public_key().to_bytes() {
            return Err(ProviderSecretError::Context);
        }
        if ciphertext.len() <= HEADER_BYTES + 16 || ciphertext.len() > MAX_PROVIDER_LEASE_BYTES {
            return Err(ProviderSecretError::Length);
        }
        if ciphertext[..2]
            != [
                seal::FORMAT_VERSION,
                seal::Purpose::CloudProviderLease as u8,
            ]
        {
            return Err(ProviderSecretError::Context);
        }
        let ephemeral: [u8; 32] = ciphertext[2..34]
            .try_into()
            .map_err(|_| ProviderSecretError::Length)?;
        let nonce = ciphertext[34..HEADER_BYTES]
            .try_into()
            .map_err(|_| ProviderSecretError::Length)?;
        let dh_ephemeral = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral));
        let dh_account = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*pinned_account.as_bytes()));
        if !dh_ephemeral.was_contributory() || !dh_account.was_contributory() {
            return Err(OpenError::Rejected.into());
        }
        let recipient = self.public_key();
        let key =
            AuthenticatedBoxKeys::new(&ephemeral, pinned_account.as_bytes(), recipient.as_bytes())
                .key(&dh_ephemeral, &dh_account, INFO)?;
        let associated = associated(context, pinned_account, &recipient)?;
        let secret = seal::decrypt(
            &key,
            seal::Purpose::CloudProviderLease,
            &[&associated],
            &nonce,
            &ciphertext[HEADER_BYTES..],
        )?;
        if secret.is_empty() || secret.len() > MAX_PROVIDER_SECRET_BYTES {
            return Err(ProviderSecretError::Length);
        }
        Ok(OpenedProviderLease { secret })
    }
}
impl fmt::Debug for RunnerBootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerBootKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

pub struct OpenedProviderLease {
    secret: Zeroizing<Vec<u8>>,
}
impl OpenedProviderLease {
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}
impl fmt::Debug for OpenedProviderLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenedProviderLease(…)")
    }
}

/// The device must verify the stable runner's boot attestation before sealing.
/// Unlike a stable runner recipient, this key cannot reopen a saved envelope after restart.
pub fn seal_provider_lease(
    account: &AccountKeyPair,
    recipient: &VerifiedBootDescriptor,
    context: &ProviderLeaseContext,
    secret: &[u8],
    now_ms: i64,
) -> Result<Vec<u8>, ProviderSecretError> {
    context.require_current(now_ms)?;
    if recipient.descriptor() != context.boot() {
        return Err(ProviderSecretError::Context);
    }
    if secret.is_empty() || secret.len() > MAX_PROVIDER_SECRET_BYTES {
        return Err(ProviderSecretError::Length);
    }
    let public = PublicKey::from_array(context.boot().recipient());
    let ephemeral = AccountKeyPair::from_seed(&Zeroizing::new(random_bytes::<32>()?));
    let dh_ephemeral = ephemeral.agree(public.as_bytes());
    let dh_account = account.agree(public.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_account.was_contributory() {
        return Err(SealError::UnusableRecipientKey.into());
    }
    let ep = ephemeral.public_key();
    let sender = account.public_key();
    let key = AuthenticatedBoxKeys::new(ep.as_bytes(), sender.as_bytes(), public.as_bytes()).key(
        &dh_ephemeral,
        &dh_account,
        INFO,
    )?;
    let associated = associated(context, &sender, &public)?;
    let nonce = random_bytes::<24>()?;
    let encrypted = seal::encrypt(
        &key,
        seal::Purpose::CloudProviderLease,
        &[&associated],
        &nonce,
        secret,
    )?;
    let mut out = Vec::with_capacity(HEADER_BYTES + encrypted.len());
    out.extend_from_slice(&[
        seal::FORMAT_VERSION,
        seal::Purpose::CloudProviderLease as u8,
    ]);
    out.extend_from_slice(ep.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    Ok(out)
}
fn associated(
    context: &ProviderLeaseContext,
    account: &PublicKey,
    recipient: &PublicKey,
) -> Result<String, ProviderSecretError> {
    let mut out = context.canonical_bytes()?;
    out.extend_from_slice(account.as_bytes());
    out.extend_from_slice(recipient.as_bytes());
    Ok(hex::encode(out))
}
#[derive(Debug, thiserror::Error)]
pub enum ProviderSecretError {
    #[error("provider lease ciphertext or secret length is invalid")]
    Length,
    #[error("provider lease belongs to another purpose, context or boot")]
    Context,
    #[error("provider lease context is invalid")]
    Lease(#[from] ProviderLeaseError),
    #[error("provider lease key generation or derivation failed")]
    Key(#[from] KeyError),
    #[error("provider lease encryption failed")]
    Seal(#[from] SealError),
    #[error("provider lease authentication failed")]
    Open(#[from] OpenError),
}
#[cfg(test)]
mod tests;
