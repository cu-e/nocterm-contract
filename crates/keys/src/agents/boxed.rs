//! The authenticated X25519 box shared by the agent formats: static sender key plus a fresh
//! ephemeral key, HKDF-SHA256 and XChaCha20-Poly1305, purpose and context in the AAD.
use zeroize::Zeroizing;

use crate::authenticated_box::AuthenticatedBoxKeys;
use crate::seal::{FORMAT_VERSION, NONCE_LEN, Purpose, decrypt, encrypt};
use crate::{AccountKeyPair, OpenError, PublicKey, SealError, random_bytes};

const HEADER_LEN: usize = 2 + 32 + NONCE_LEN;

/// `version ‖ purpose ‖ ephemeral public ‖ nonce ‖ ciphertext`.
pub(crate) fn box_seal(
    purpose: Purpose,
    info: &[u8],
    sender: &AccountKeyPair,
    recipient: &PublicKey,
    context: &[&str],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let ephemeral = AccountKeyPair::from_seed(&Zeroizing::new(random_bytes::<32>()?));
    let nonce = random_bytes::<NONCE_LEN>()?;
    let dh_ephemeral = ephemeral.agree(recipient.as_bytes());
    let dh_sender = sender.agree(recipient.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_sender.was_contributory() {
        return Err(SealError::UnusableRecipientKey);
    }
    let ephemeral_public = ephemeral.public_key();
    let key = AuthenticatedBoxKeys::new(
        ephemeral_public.as_bytes(),
        sender.public_key().as_bytes(),
        recipient.as_bytes(),
    )
    .key(&dh_ephemeral, &dh_sender, info)?;
    let ciphertext = encrypt(&key, purpose, context, &nonce, plaintext)?;
    let mut sealed = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    sealed.push(FORMAT_VERSION);
    sealed.push(purpose as u8);
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

pub(crate) fn box_open(
    purpose: Purpose,
    info: &[u8],
    recipient: &AccountKeyPair,
    sender: &PublicKey,
    context: &[&str],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    if sealed.len() < HEADER_LEN || sealed[0] != FORMAT_VERSION || sealed[1] != purpose as u8 {
        return Err(OpenError::Malformed);
    }
    let ephemeral: [u8; 32] = sealed[2..34].try_into().map_err(|_| OpenError::Malformed)?;
    let nonce: [u8; NONCE_LEN] = sealed[34..HEADER_LEN]
        .try_into()
        .map_err(|_| OpenError::Malformed)?;
    let dh_ephemeral = recipient.agree(&ephemeral);
    let dh_sender = recipient.agree(sender.as_bytes());
    if !dh_ephemeral.was_contributory() || !dh_sender.was_contributory() {
        return Err(OpenError::Malformed);
    }
    let recipient_public = recipient.public_key();
    let key = AuthenticatedBoxKeys::new(&ephemeral, sender.as_bytes(), recipient_public.as_bytes())
        .key(&dh_ephemeral, &dh_sender, info)
        .map_err(|_| OpenError::Rejected)?;
    decrypt(&key, purpose, context, &nonce, &sealed[HEADER_LEN..])
}
