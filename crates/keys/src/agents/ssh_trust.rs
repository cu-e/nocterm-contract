//! The `agent_ssh_trust` registry: which servers trust the user's SSH CA, and the pure rules
//! that move a record between states. No I/O: an adapter reads `authorized_keys` and calls
//! [`SshTrustRecord::reconcile`] with what it saw.
use nocterm_hub_model::DeviceId;
use serde::{Deserialize, Serialize};

/// Version of the stored record.
pub const SSH_TRUST_SCHEMA: u8 = 1;
/// Longest stored record.
pub const MAX_RECORD_BYTES: usize = 2048;
/// Longest host, user or profile text.
pub const MAX_FIELD_BYTES: usize = 255;

/// Where a server stands with the CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    /// The server trusts the current CA.
    Trusted,
    /// Removal was requested but the server was not reachable yet.
    RemovalPending,
    /// The CA line is gone, as requested.
    Removed,
    /// The line vanished or names an outdated CA without anyone asking for it.
    Drifted,
}

/// What a reconciliation found in `authorized_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// A line for the current CA is present.
    CurrentCaPresent,
    /// A line for an older CA of this user is present, none for the current one.
    StaleCaPresent,
    /// No Nocterm CA line.
    Absent,
}

/// What the adapter must do after a reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAction {
    /// Nothing.
    None,
    /// Delete the CA line from the server now.
    RemoveLine,
}

/// A rule of the state machine was broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// A field is empty or too long.
    #[error("a trust record field is empty or too long")]
    Field,
    /// The server no longer carries the line, so there is nothing to remove.
    #[error("the server has no CA line to remove")]
    NothingToRemove,
    /// The stored bytes are not a record of this schema.
    #[error("not an agent_ssh_trust record")]
    Malformed,
}

/// One server that trusts (or trusted) the CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTrustRecord {
    schema: u8,
    /// The connection profile the server was reached through.
    pub profile_id: String,
    /// Server host.
    pub host: String,
    /// User whose `authorized_keys` holds the line.
    pub user: String,
    /// SHA-256 fingerprint of the server's host key when the line was written.
    pub host_key_fingerprint: String,
    /// Fingerprint of the CA the line names.
    pub ca_fingerprint: String,
    /// When the line was added, Unix milliseconds.
    pub added_at_ms: i64,
    /// The device that added it.
    pub added_by_device: DeviceId,
    /// Last time `authorized_keys` was read, Unix milliseconds.
    pub last_verified_at_ms: Option<i64>,
    state: TrustState,
}

impl SshTrustRecord {
    /// A record for a line that was just written.
    #[allow(clippy::too_many_arguments)]
    pub fn installed(
        profile_id: String,
        host: String,
        user: String,
        host_key_fingerprint: String,
        ca_fingerprint: String,
        now_ms: i64,
        device: DeviceId,
    ) -> Result<Self, TrustError> {
        let record = Self {
            schema: SSH_TRUST_SCHEMA,
            profile_id,
            host,
            user,
            host_key_fingerprint,
            ca_fingerprint,
            added_at_ms: now_ms,
            added_by_device: device,
            last_verified_at_ms: Some(now_ms),
            state: TrustState::Trusted,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), TrustError> {
        let ok = [
            &self.profile_id,
            &self.host,
            &self.user,
            &self.host_key_fingerprint,
            &self.ca_fingerprint,
        ]
        .iter()
        .all(|f| !f.is_empty() && f.len() <= MAX_FIELD_BYTES);
        ok.then_some(()).ok_or(TrustError::Field)
    }

    /// The state.
    pub fn state(&self) -> TrustState {
        self.state
    }

    /// The owner asks to stop trusting the server. Idempotent while pending.
    pub fn request_removal(&mut self) -> Result<(), TrustError> {
        match self.state {
            TrustState::Trusted | TrustState::Drifted | TrustState::RemovalPending => {
                self.state = TrustState::RemovalPending;
                Ok(())
            }
            TrustState::Removed => Err(TrustError::NothingToRemove),
        }
    }

    /// The adapter deleted the line.
    pub fn removal_confirmed(&mut self, now_ms: i64) {
        self.state = TrustState::Removed;
        self.last_verified_at_ms = Some(now_ms);
    }

    /// A new line for `ca_fingerprint` was written over a drifted or removed record.
    pub fn reinstalled(
        &mut self,
        ca_fingerprint: String,
        now_ms: i64,
        device: DeviceId,
    ) -> Result<(), TrustError> {
        if matches!(self.state, TrustState::Trusted | TrustState::RemovalPending) {
            return Err(TrustError::Field);
        }
        self.ca_fingerprint = ca_fingerprint;
        self.validate()?;
        self.added_at_ms = now_ms;
        self.added_by_device = device;
        self.last_verified_at_ms = Some(now_ms);
        self.state = TrustState::Trusted;
        Ok(())
    }

    /// Applies what the adapter read from the server.
    pub fn reconcile(&mut self, seen: Observation, now_ms: i64) -> TrustAction {
        self.last_verified_at_ms = Some(now_ms);
        let (state, action) = match (self.state, seen) {
            (TrustState::Trusted | TrustState::Drifted, Observation::CurrentCaPresent) => {
                (TrustState::Trusted, TrustAction::None)
            }
            (TrustState::Trusted | TrustState::Drifted, _) => {
                (TrustState::Drifted, TrustAction::None)
            }
            (TrustState::RemovalPending, Observation::Absent) => {
                (TrustState::Removed, TrustAction::None)
            }
            (TrustState::RemovalPending, _) => {
                (TrustState::RemovalPending, TrustAction::RemoveLine)
            }
            (TrustState::Removed, Observation::Absent) => (TrustState::Removed, TrustAction::None),
            (TrustState::Removed, _) => (TrustState::Drifted, TrustAction::None),
        };
        self.state = state;
        action
    }

    /// The bytes stored in the E2E collection.
    pub fn encode(&self) -> Result<Vec<u8>, TrustError> {
        self.validate()?;
        let bytes = postcard::to_stdvec(self).map_err(|_| TrustError::Malformed)?;
        (bytes.len() <= MAX_RECORD_BYTES)
            .then_some(bytes)
            .ok_or(TrustError::Field)
    }

    /// Decodes a stored record; other schema versions are refused, not guessed.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(TrustError::Malformed);
        }
        let record: Self = postcard::from_bytes(bytes).map_err(|_| TrustError::Malformed)?;
        if record.schema != SSH_TRUST_SCHEMA {
            return Err(TrustError::Malformed);
        }
        record.validate()?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Observation::{Absent, CurrentCaPresent, StaleCaPresent};

    fn record() -> SshTrustRecord {
        SshTrustRecord::installed(
            "profile".into(),
            "prod-1".into(),
            "deploy".into(),
            "SHA256:host".into(),
            "SHA256:ca".into(),
            10,
            DeviceId::new(),
        )
        .unwrap()
    }

    #[test]
    fn a_vanished_or_stale_line_is_drift_and_recovers_when_the_current_line_returns() {
        let mut r = record();
        assert_eq!(r.reconcile(CurrentCaPresent, 20), TrustAction::None);
        assert_eq!(r.state(), TrustState::Trusted);
        r.reconcile(Absent, 30);
        assert_eq!(r.state(), TrustState::Drifted);
        r.reconcile(StaleCaPresent, 40);
        assert_eq!(r.state(), TrustState::Drifted);
        r.reconcile(CurrentCaPresent, 50);
        assert_eq!(r.state(), TrustState::Trusted);
        assert_eq!(r.last_verified_at_ms, Some(50));
    }

    #[test]
    fn a_pending_removal_waits_for_the_server_then_completes() {
        let mut r = record();
        r.request_removal().unwrap();
        assert_eq!(r.reconcile(CurrentCaPresent, 20), TrustAction::RemoveLine);
        assert_eq!(r.state(), TrustState::RemovalPending);
        assert_eq!(r.reconcile(StaleCaPresent, 21), TrustAction::RemoveLine);
        r.removal_confirmed(22);
        assert_eq!(r.state(), TrustState::Removed);
        assert_eq!(r.request_removal(), Err(TrustError::NothingToRemove));
        r.reconcile(Absent, 30);
        assert_eq!(r.state(), TrustState::Removed);
    }

    #[test]
    fn a_removed_server_that_regains_the_line_is_drift_and_can_be_reinstalled() {
        let mut r = record();
        r.request_removal().unwrap();
        r.reconcile(Absent, 20);
        assert_eq!(r.state(), TrustState::Removed);
        r.reconcile(CurrentCaPresent, 30);
        assert_eq!(r.state(), TrustState::Drifted);
        r.reinstalled("SHA256:new".into(), 40, DeviceId::new())
            .unwrap();
        assert_eq!(r.state(), TrustState::Trusted);
        assert_eq!(r.ca_fingerprint, "SHA256:new");
        assert!(r.reinstalled("x".into(), 50, DeviceId::new()).is_err());
    }

    #[test]
    fn a_record_round_trips_and_other_schemas_are_refused() {
        let r = record();
        let bytes = r.encode().unwrap();
        assert_eq!(SshTrustRecord::decode(&bytes).unwrap(), r);
        assert_eq!(bytes[0], SSH_TRUST_SCHEMA);
        let mut other = bytes.clone();
        other[0] = 2;
        assert_eq!(SshTrustRecord::decode(&other), Err(TrustError::Malformed));
        assert_eq!(
            SshTrustRecord::decode(&bytes[..3]),
            Err(TrustError::Malformed)
        );
        assert!(
            SshTrustRecord::installed(
                String::new(),
                "h".into(),
                "u".into(),
                "f".into(),
                "c".into(),
                0,
                DeviceId::new()
            )
            .is_err()
        );
    }
}
