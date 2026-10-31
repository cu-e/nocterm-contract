//! Conversions of provider probe results (`ProbeResult`) to and from
//! `nocterm_hub_model::agents::ProviderProbe`. Both directions enforce the same bounds, so a
//! host cannot make a hub forward an oversized result or provider text.

use nocterm_hub_model::agents::{ProbeError, ProbeFailure, ProbeOutcome, ProviderProbe};

use crate::{WireError, v1};

fn field(err: ProbeError) -> WireError {
    WireError::Field(match err {
        ProbeError::TooManyModels | ProbeError::ModelId => "probe.models",
        ProbeError::Code => "probe.error_code",
    })
}

impl TryFrom<&ProviderProbe> for v1::ProbeResult {
    type Error = WireError;

    fn try_from(probe: &ProviderProbe) -> Result<Self, WireError> {
        probe.validate().map_err(field)?;
        Ok(match &probe.outcome {
            ProbeOutcome::Ok { models } => Self {
                ok: true,
                latency_ms: probe.latency_ms,
                models: models.clone(),
                error_code: String::new(),
            },
            ProbeOutcome::Failed(failure) => Self {
                ok: false,
                latency_ms: probe.latency_ms,
                models: Vec::new(),
                error_code: failure.code().to_owned(),
            },
        })
    }
}

impl TryFrom<&v1::ProbeResult> for ProviderProbe {
    type Error = WireError;

    fn try_from(wire: &v1::ProbeResult) -> Result<Self, WireError> {
        let outcome = if wire.ok {
            if !wire.error_code.is_empty() {
                return Err(WireError::Field("probe.error_code"));
            }
            ProbeOutcome::Ok {
                models: wire.models.clone(),
            }
        } else {
            if !wire.models.is_empty() {
                return Err(WireError::Field("probe.models"));
            }
            ProbeOutcome::Failed(ProbeFailure::from_code(&wire.error_code).map_err(field)?)
        };
        let probe = Self {
            latency_ms: wire.latency_ms,
            outcome,
        };
        probe.validate().map_err(field)?;
        Ok(probe)
    }
}

#[cfg(test)]
mod tests {
    use nocterm_hub_model::agents::limits::MAX_PROBE_MODELS;
    use prost::Message;

    use super::*;

    fn through_the_wire(probe: &ProviderProbe) -> Result<ProviderProbe, WireError> {
        let bytes = v1::ProbeResult::try_from(probe)?.encode_to_vec();
        ProviderProbe::try_from(&v1::ProbeResult::decode(bytes.as_slice()).unwrap())
    }

    #[test]
    fn probe_results_survive_the_wire() {
        let ok = ProviderProbe {
            latency_ms: 230,
            outcome: ProbeOutcome::Ok {
                models: vec!["gpt-a".into(), "gpt-b".into()],
            },
        };
        assert_eq!(through_the_wire(&ok), Ok(ok));
        let failed = ProviderProbe {
            latency_ms: 90,
            outcome: ProbeOutcome::Failed(ProbeFailure::Unauthorized),
        };
        assert_eq!(through_the_wire(&failed), Ok(failed));
        let unknown = ProviderProbe::failed(ProbeFailure::Other("quota_exceeded".into()));
        assert_eq!(through_the_wire(&unknown), Ok(unknown));
    }

    #[test]
    fn probe_frames_travel_between_hub_and_host_under_one_request_id() {
        let down = v1::NodeDown {
            frame: Some(v1::node_down::Frame::ProbeProvider(v1::ProbeProvider {
                request_id: 7,
                agent_id: "a".into(),
                definition_version: 3,
                sealed_definition: vec![2, 19, 0],
                ..v1::ProbeProvider::default()
            })),
        };
        let decoded = v1::NodeDown::decode(down.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(
            decoded.frame,
            Some(v1::node_down::Frame::ProbeProvider(ref p))
                if p.request_id == 7 && p.definition_version == 3
        ));
        let probe = ProviderProbe::failed(ProbeFailure::NoApiKey);
        let up = v1::NodeUp {
            frame: Some(v1::node_up::Frame::ProbeResult(v1::ProviderProbeReport {
                request_id: 7,
                result: Some(v1::ProbeResult::try_from(&probe).unwrap()),
            })),
        };
        let decoded = v1::NodeUp::decode(up.encode_to_vec().as_slice()).unwrap();
        let Some(v1::node_up::Frame::ProbeResult(report)) = decoded.frame else {
            panic!("expected a probe result");
        };
        assert_eq!(report.request_id, 7);
        assert_eq!(ProviderProbe::try_from(&report.result.unwrap()), Ok(probe));
    }

    #[test]
    fn inconsistent_or_unbounded_wire_results_are_refused() {
        let wire = |ok: bool, models: Vec<String>, code: &str| v1::ProbeResult {
            ok,
            latency_ms: 1,
            models,
            error_code: code.into(),
        };
        let refused = |w: v1::ProbeResult| ProviderProbe::try_from(&w).unwrap_err();
        assert_eq!(
            refused(wire(true, vec![], "timeout")),
            WireError::Field("probe.error_code")
        );
        assert_eq!(
            refused(wire(false, vec!["m".into()], "timeout")),
            WireError::Field("probe.models")
        );
        assert_eq!(
            refused(wire(false, vec![], "")),
            WireError::Field("probe.error_code")
        );
        assert_eq!(
            refused(wire(false, vec![], "401: invalid key sk-abc")),
            WireError::Field("probe.error_code")
        );
        assert_eq!(
            refused(wire(true, vec!["m".into(); MAX_PROBE_MODELS + 1], "")),
            WireError::Field("probe.models")
        );
        let smuggled = ProviderProbe::failed(ProbeFailure::Other("Bad Key".into()));
        assert!(v1::ProbeResult::try_from(&smuggled).is_err());
    }
}
