use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn session(account: &str, token: &str) -> Session {
    Session {
        account_id: account.into(),
        device_id: "device".into(),
        access_token: token.into(),
        access_expires_at_ms: 1_000_000,
        refresh_token: format!("refresh-{token}"),
        refresh_expires_at_ms: 2_000_000,
    }
}
fn credentials() -> Credentials {
    Credentials::new(
        "hub".into(),
        DeviceKey::from_seed(&[7; 32]),
        Some(session("A", "first")),
    )
}

#[test]
fn ordinary_refresh_keeps_capture_but_never_rewrites_original_attribution() -> TestResult {
    let credentials = credentials();
    let original = credentials.capture().ok_or("capture unavailable")?;
    assert!(credentials.rotate_session(original.generation, session("A", "refreshed")));
    credentials.require_generation(original.generation)?;
    let (token, device, _, _, _) =
        credentials.sign_scoped("/cloud/publish", Some(original.generation))?;
    assert_eq!(token, "refreshed");
    assert_eq!(device, "device");
    let current = credentials.capture().ok_or("capture unavailable")?;
    assert_eq!(current.generation, original.generation);
    assert_eq!(
        original.access_digest,
        <[u8; 32]>::from(Sha256::digest(b"first"))
    );
    assert_ne!(current.access_digest, original.access_digest);
    assert_eq!(current.signing_key, original.signing_key);
    Ok(())
}

#[test]
fn logout_and_relogin_never_revive_an_old_cloud_capture() -> TestResult {
    let credentials = credentials();
    let old = credentials.capture().ok_or("capture unavailable")?;
    credentials.set_session(None);
    assert!(
        credentials
            .sign_scoped("/cloud/publish", Some(old.generation))
            .is_err()
    );
    credentials.set_session(Some(session("A", "new-login")));
    assert!(credentials.require_generation(old.generation).is_err());
    assert!(
        credentials
            .sign_scoped("/cloud/publish", Some(old.generation))
            .is_err()
    );
    assert!(!credentials.rotate_session(old.generation, session("A", "late-refresh")));
    assert_eq!(
        credentials
            .session()
            .ok_or("session unavailable")?
            .access_token,
        "new-login"
    );
    Ok(())
}

#[test]
fn account_round_trip_and_device_change_fence_old_requests_and_refresh_results() -> TestResult {
    let credentials = credentials();
    let old = credentials.capture().ok_or("capture unavailable")?;
    credentials.set_session(Some(session("B", "second")));
    assert!(!credentials.rotate_session(old.generation, session("A", "late-A")));
    assert_eq!(
        credentials
            .session()
            .ok_or("session unavailable")?
            .account_id,
        "B"
    );
    credentials.set_session(Some(session("A", "third")));
    assert!(
        credentials
            .sign_scoped("/cloud/publish", Some(old.generation))
            .is_err()
    );
    let current = credentials.capture().ok_or("capture unavailable")?;
    let mut another_device = session("A", "another-device");
    another_device.device_id = "other".into();
    assert!(!credentials.rotate_session(current.generation, another_device));
    assert_eq!(
        credentials
            .session()
            .ok_or("session unavailable")?
            .device_id,
        "device"
    );
    Ok(())
}

#[test]
fn conditional_refresh_does_not_sign_in_an_already_signed_out_client() -> TestResult {
    let credentials = credentials();
    let old = credentials.capture().ok_or("capture unavailable")?;
    credentials.set_session(None);
    assert!(!credentials.rotate_session(old.generation, session("A", "from-file")));
    assert!(credentials.session().is_none());
    assert!(credentials.capture().is_none());
    Ok(())
}
