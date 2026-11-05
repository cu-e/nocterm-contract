//! `agent_ssh_trust`: the account's SSH CA document (`ca`) and one trust record per server
//! (`srv-<32 hex>`), defined by the native client (ADR 0119) and read here as they are stored
//! ([`nocterm_keys::agents::ssh_ca::CaDocument`], [`SshTrustRecord`]). The collection is
//! personal; every object is sealed by its collection key with its object id and the kind
//! `agent_ssh_trust`.
use super::{SEAL_OVERHEAD, StoredObject};
use crate::{CloudDeviceError, error::SshRefusal};
use nocterm_hub_model::cloud::ssh::SshServerId;
use nocterm_keys::{
    CollectionKey,
    agents::{
        MAX_RECORD_BYTES, SshTrustRecord,
        ssh_ca::{CA_OBJECT, CaDocument, MAX_CA_DOCUMENT_BYTES},
    },
};

/// The collection kind and the object kind of every object in it.
pub const SSH_TRUST_KIND: &str = "agent_ssh_trust";

fn plaintext(
    key: &CollectionKey,
    object: &StoredObject<'_>,
    object_id: &str,
    max_plaintext: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CloudDeviceError> {
    if object.object_id != object_id || object.kind != SSH_TRUST_KIND {
        return Err(CloudDeviceError::Binding);
    }
    if object.ciphertext.len() > max_plaintext + SEAL_OVERHEAD {
        return Err(CloudDeviceError::Capacity);
    }
    Ok(key.open_object(
        object.collection_id,
        object_id,
        SSH_TRUST_KIND,
        object.ciphertext,
    )?)
}

/// Opens the account's CA document; a deleted one means the account has no CA.
pub fn open_ca(
    key: &CollectionKey,
    object: &StoredObject<'_>,
) -> Result<CaDocument, CloudDeviceError> {
    if object.deleted {
        return Err(SshRefusal::NoCa.into());
    }
    let plain = plaintext(key, object, CA_OBJECT, MAX_CA_DOCUMENT_BYTES)?;
    Ok(CaDocument::decode(&plain)?)
}

/// Opens the trust record of `server`. A record that is deleted, or whose profile does not
/// derive this server id (a record moved to another object), is not a trusted server.
pub fn open_trust(
    key: &CollectionKey,
    server: &SshServerId,
    object: &StoredObject<'_>,
) -> Result<SshTrustRecord, CloudDeviceError> {
    if object.deleted {
        return Err(SshRefusal::UntrustedServer.into());
    }
    let plain = plaintext(key, object, &server.object_id(), MAX_RECORD_BYTES)?;
    let record = SshTrustRecord::decode(&plain)?;
    if &SshServerId::of_profile(&record.profile_id) != server {
        return Err(CloudDeviceError::Binding);
    }
    Ok(record)
}
