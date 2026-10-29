//! Opaque credential messages deliberately omit bearer material from diagnostics.
use core::fmt;

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$ (
        impl fmt::Debug for crate::v1::$name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(…)"))
            }
        }
    )+};
}
redacted_debug!(
    CloudRunnerGrant,
    CloudRedeemRunnerGrant,
    CloudRefreshRunner,
    CloudRunnerTokens,
    CloudHeadProbe,
    CloudHeadProbeReply
);

#[cfg(test)]
mod tests {
    use crate::v1;
    #[test]
    fn runner_credential_messages_never_print_bearer_or_claim_bytes() {
        let grant = v1::CloudRunnerGrant {
            ticket: "private-grant-ticket".into(),
            expires_at_ms: 1,
        };
        let tokens = v1::CloudRunnerTokens {
            account_id: "account".into(),
            runner_id: vec![1; 16],
            access_token: "private-access-token".into(),
            access_expires_at_ms: 2,
            refresh_token: "private-refresh-token".into(),
            refresh_expires_at_ms: 3,
            capability_version: 1,
        };
        let redeem = v1::CloudRedeemRunnerGrant {
            claim: b"private-grant-ticket".to_vec(),
            signature: vec![0; 64],
        };
        assert_eq!(format!("{grant:?}"), "CloudRunnerGrant(…)");
        assert_eq!(format!("{tokens:?}"), "CloudRunnerTokens(…)");
        assert_eq!(format!("{redeem:?}"), "CloudRedeemRunnerGrant(…)");
    }
}
