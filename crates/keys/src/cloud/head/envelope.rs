//! Shared implementation of the existing static+ephemeral authenticated box,
//! with a closed private choice of query/witness purposes and size bounds.
use super::HeadCryptoError;
use crate::{
    AccountKeyPair, OpenError, PublicKey, SealError, authenticated_box::AuthenticatedBoxKeys,
    cloud::RunnerEncryptionKey, random_bytes, seal,
};
use nocterm_hub_model::cloud::head::{
    MAX_HEAD_QUERY_ENVELOPE_BYTES, MAX_HEAD_REPLY_ENVELOPE_BYTES,
};
use x25519_dalek::SharedSecret;
use zeroize::Zeroizing;

const HEADER: usize = 2 + 32 + 24;
#[derive(Clone, Copy)]
pub(super) enum HeadBox {
    Query,
    Witness,
}
impl HeadBox {
    fn purpose(self) -> seal::Purpose {
        match self {
            Self::Query => seal::Purpose::CloudHeadQuery,
            Self::Witness => seal::Purpose::CloudHeadWitness,
        }
    }
    fn info(self) -> &'static [u8] {
        match self {
            Self::Query => b"nocterm-cloud-head-query-v1/auth",
            Self::Witness => b"nocterm-cloud-head-witness-v1/auth",
        }
    }
    fn maximum(self) -> usize {
        match self {
            Self::Query => MAX_HEAD_QUERY_ENVELOPE_BYTES,
            Self::Witness => MAX_HEAD_REPLY_ENVELOPE_BYTES,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum KeyOwner<'a> {
    Account(&'a AccountKeyPair),
    Runner(&'a RunnerEncryptionKey),
}
impl KeyOwner<'_> {
    fn public(&self) -> PublicKey {
        match self {
            Self::Account(key) => key.public_key(),
            Self::Runner(key) => key.public_key(),
        }
    }
    fn agree(&self, peer: &[u8; 32]) -> SharedSecret {
        match self {
            Self::Account(key) => key.agree(peer),
            Self::Runner(key) => key.agree(peer),
        }
    }
}
pub(super) fn seal(
    kind: HeadBox,
    sender: KeyOwner<'_>,
    recipient: &PublicKey,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, HeadCryptoError> {
    if plaintext.len().saturating_add(HEADER + 16) > kind.maximum() {
        return Err(HeadCryptoError::Bounds);
    }
    let ephemeral = AccountKeyPair::from_seed(&Zeroizing::new(random_bytes::<32>()?));
    let dh_ephemeral = ephemeral.agree(recipient.as_bytes());
    let dh_sender = sender.agree(recipient.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_sender.was_contributory() {
        return Err(SealError::UnusableRecipientKey.into());
    }
    let ep = ephemeral.public_key();
    let sender = sender.public();
    let key = AuthenticatedBoxKeys::new(ep.as_bytes(), sender.as_bytes(), recipient.as_bytes())
        .key(&dh_ephemeral, &dh_sender, kind.info())?;
    let nonce = random_bytes::<24>()?;
    let ciphertext = seal::encrypt(
        &key,
        kind.purpose(),
        &[&hex::encode(context)],
        &nonce,
        plaintext,
    )?;
    let mut bytes = Vec::with_capacity(HEADER + ciphertext.len());
    bytes.extend_from_slice(&[seal::FORMAT_VERSION, kind.purpose() as u8]);
    bytes.extend_from_slice(ep.as_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    Ok(bytes)
}
pub(super) fn open(
    kind: HeadBox,
    recipient: KeyOwner<'_>,
    sender: &PublicKey,
    context: &[u8],
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, HeadCryptoError> {
    if bytes.len() > kind.maximum() {
        return Err(HeadCryptoError::Bounds);
    }
    if bytes.len() < HEADER + 16 || bytes[..2] != [seal::FORMAT_VERSION, kind.purpose() as u8] {
        return Err(OpenError::Malformed.into());
    }
    let ep: [u8; 32] = bytes[2..34].try_into().map_err(|_| OpenError::Malformed)?;
    let nonce = bytes[34..HEADER]
        .try_into()
        .map_err(|_| OpenError::Malformed)?;
    let dh_ephemeral = recipient.agree(&ep);
    let dh_sender = recipient.agree(sender.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_sender.was_contributory() {
        return Err(OpenError::Rejected.into());
    }
    let recipient = recipient.public();
    let key = AuthenticatedBoxKeys::new(&ep, sender.as_bytes(), recipient.as_bytes()).key(
        &dh_ephemeral,
        &dh_sender,
        kind.info(),
    )?;
    Ok(seal::decrypt(
        &key,
        kind.purpose(),
        &[&hex::encode(context)],
        &nonce,
        &bytes[HEADER..],
    )?)
}
