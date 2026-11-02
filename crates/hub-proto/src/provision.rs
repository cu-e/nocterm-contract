//! Provisioning failure codes on the wire: what a host reports in
//! `InstanceProvisioned.error_code` and what a hub stores in `Instance.failure_code`, read as
//! `nocterm_hub_model::agents::ProvisionFailure`.

use nocterm_hub_model::agents::ProvisionFailure;

use crate::v1;

/// The failure a host reported, as a hub stores it: `None` when `ok`; otherwise the named or
/// unknown well-formed code, and [`ProvisionFailure::Unknown`] for an empty code (a host that
/// predates the field) or a malformed one.
pub fn provisioned_failure_from_wire(wire: &v1::InstanceProvisioned) -> Option<ProvisionFailure> {
    if wire.ok {
        return None;
    }
    Some(ProvisionFailure::from_stored(&wire.error_code).unwrap_or(ProvisionFailure::Unknown))
}

/// Why an instance failed, as a client shows it: `None` unless the instance is
/// `INSTANCE_STATE_FAILED` with a non-empty `failure_code`; a malformed code reads as
/// [`ProvisionFailure::Unknown`].
pub fn instance_failure_from_wire(wire: &v1::Instance) -> Option<ProvisionFailure> {
    if wire.state != v1::InstanceState::Failed as i32 {
        return None;
    }
    ProvisionFailure::from_stored(&wire.failure_code)
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    fn failed_provision(code: &str) -> v1::InstanceProvisioned {
        v1::InstanceProvisioned {
            request_id: 4,
            ok: false,
            error: "host log text".into(),
            error_code: code.into(),
            ..v1::InstanceProvisioned::default()
        }
    }

    fn through_the_wire<M: Message + Default>(message: &M) -> M {
        M::decode(message.encode_to_vec().as_slice()).unwrap()
    }

    #[test]
    fn a_host_failure_code_survives_the_wire_to_the_hub() {
        for failure in [
            ProvisionFailure::OwnerUnpinned,
            ProvisionFailure::AccountKeyMismatch,
            ProvisionFailure::Other("gpu_missing".into()),
        ] {
            let decoded = through_the_wire(&failed_provision(failure.code()));
            assert_eq!(provisioned_failure_from_wire(&decoded), Some(failure));
        }
    }

    #[test]
    fn a_hub_stores_unknown_for_a_missing_or_malformed_host_code() {
        assert_eq!(
            provisioned_failure_from_wire(&failed_provision("")),
            Some(ProvisionFailure::Unknown)
        );
        assert_eq!(
            provisioned_failure_from_wire(&failed_provision("disk full at /srv")),
            Some(ProvisionFailure::Unknown)
        );
        let ok = v1::InstanceProvisioned {
            ok: true,
            ..v1::InstanceProvisioned::default()
        };
        assert_eq!(provisioned_failure_from_wire(&ok), None);
    }

    #[test]
    fn a_client_reads_the_failure_of_a_failed_instance_only() {
        let instance = |state: v1::InstanceState, code: &str| v1::Instance {
            state: state as i32,
            failure_code: code.into(),
            ..v1::Instance::default()
        };
        let failed = through_the_wire(&instance(v1::InstanceState::Failed, "no_capacity"));
        assert_eq!(
            instance_failure_from_wire(&failed),
            Some(ProvisionFailure::NoCapacity)
        );
        assert_eq!(
            instance_failure_from_wire(&instance(v1::InstanceState::Failed, "")),
            None
        );
        assert_eq!(
            instance_failure_from_wire(&instance(v1::InstanceState::Failed, "Bad Text")),
            Some(ProvisionFailure::Unknown)
        );
        assert_eq!(
            instance_failure_from_wire(&instance(v1::InstanceState::Ready, "no_capacity")),
            None
        );
    }

    #[test]
    fn an_old_reader_skips_the_new_fields() {
        #[derive(Clone, PartialEq, prost::Message)]
        struct OldInstanceProvisioned {
            #[prost(uint64, tag = "1")]
            request_id: u64,
            #[prost(bool, tag = "3")]
            ok: bool,
            #[prost(string, tag = "4")]
            error: String,
        }
        let bytes = failed_provision("owner_unpinned").encode_to_vec();
        let old = OldInstanceProvisioned::decode(bytes.as_slice()).unwrap();
        assert_eq!(old.request_id, 4);
        assert!(!old.ok);
        assert_eq!(old.error, "host log text");
    }
}
