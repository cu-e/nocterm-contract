//! The seat account key a hub states in `ProvisionInstance.account_public_key` and
//! `ProbeProvider.account_public_key` (ADR 0005). It is a statement of the hub, not a pin: a
//! host decides by scope and its operator's setting whether to use it.

use crate::{WireError, v1};

/// Bytes of an X25519 keyset public key.
const KEY_BYTES: usize = 32;

fn stated(bytes: &[u8], field: &'static str) -> Result<Option<[u8; KEY_BYTES]>, WireError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    <[u8; KEY_BYTES]>::try_from(bytes)
        .map(Some)
        .map_err(|_| WireError::Field(field))
}

/// The account key the hub states for a seat: `None` when it states none (an older hub), an
/// error when the field is not 32 bytes.
pub fn provision_account_key_from_wire(
    wire: &v1::ProvisionInstance,
) -> Result<Option<[u8; KEY_BYTES]>, WireError> {
    stated(&wire.account_public_key, "account_public_key")
}

/// The account key the hub states for a probe's sealing account, as for
/// [`provision_account_key_from_wire`].
pub fn probe_account_key_from_wire(
    wire: &v1::ProbeProvider,
) -> Result<Option<[u8; KEY_BYTES]>, WireError> {
    stated(&wire.account_public_key, "account_public_key")
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    #[test]
    fn a_stated_key_survives_the_wire_and_its_absence_reads_as_none() {
        let provision = v1::ProvisionInstance {
            request_id: 2,
            account_public_key: vec![7; 32],
            ..v1::ProvisionInstance::default()
        };
        let decoded = v1::ProvisionInstance::decode(provision.encode_to_vec().as_slice()).unwrap();
        assert_eq!(provision_account_key_from_wire(&decoded), Ok(Some([7; 32])));
        assert_eq!(
            provision_account_key_from_wire(&v1::ProvisionInstance::default()),
            Ok(None)
        );

        let probe = v1::ProbeProvider {
            account_public_key: vec![9; 32],
            ..v1::ProbeProvider::default()
        };
        let decoded = v1::ProbeProvider::decode(probe.encode_to_vec().as_slice()).unwrap();
        assert_eq!(probe_account_key_from_wire(&decoded), Ok(Some([9; 32])));
    }

    #[test]
    fn a_key_of_another_length_is_refused() {
        for bytes in [vec![1; 31], vec![1; 33]] {
            let wire = v1::ProvisionInstance {
                account_public_key: bytes.clone(),
                ..v1::ProvisionInstance::default()
            };
            assert_eq!(
                provision_account_key_from_wire(&wire),
                Err(WireError::Field("account_public_key"))
            );
            let probe = v1::ProbeProvider {
                account_public_key: bytes,
                ..v1::ProbeProvider::default()
            };
            assert!(probe_account_key_from_wire(&probe).is_err());
        }
    }

    #[test]
    fn a_host_that_predates_the_key_still_reads_the_seat() {
        #[derive(Clone, PartialEq, prost::Message)]
        struct OldProvisionInstance {
            #[prost(uint64, tag = "1")]
            request_id: u64,
            #[prost(string, tag = "5")]
            account_id: String,
            #[prost(bytes = "vec", tag = "9")]
            sealed_definition: Vec<u8>,
        }
        let wire = v1::ProvisionInstance {
            request_id: 3,
            account_id: "acct".into(),
            sealed_definition: vec![2, 1],
            account_public_key: vec![7; 32],
            ..v1::ProvisionInstance::default()
        };
        let old = OldProvisionInstance::decode(wire.encode_to_vec().as_slice()).unwrap();
        assert_eq!(old.request_id, 3);
        assert_eq!(old.account_id, "acct");
        assert_eq!(old.sealed_definition, vec![2, 1]);
    }
}
