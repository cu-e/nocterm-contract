use super::*;

#[test]
fn a_status_fails_the_effect_with_what_it_means_for_the_flow() {
    let failed = |code: tonic::Code, sent| {
        CloudCallError::status(tonic::Status::new(code, "x"), sent).failure()
    };
    assert_eq!(
        failed(tonic::Code::NotFound, false),
        EffectFailure::NotFound
    );
    assert_eq!(
        failed(tonic::Code::AlreadyExists, false),
        EffectFailure::AlreadyExists
    );
    assert_eq!(failed(tonic::Code::Aborted, false), EffectFailure::Conflict);
    assert_eq!(
        failed(tonic::Code::FailedPrecondition, true),
        EffectFailure::Conflict
    );
    assert_eq!(
        failed(tonic::Code::Unavailable, false),
        EffectFailure::Unavailable
    );
    // A publication that may have reached the hub is of unknown outcome, not unsent.
    assert_eq!(
        failed(tonic::Code::Unavailable, true),
        EffectFailure::Unknown
    );
    assert_eq!(
        failed(tonic::Code::PermissionDenied, true),
        EffectFailure::Refused
    );
    assert_eq!(
        failed(tonic::Code::Unimplemented, false),
        EffectFailure::Refused
    );
    assert_eq!(
        CloudCallError::Unanswered.failure(),
        EffectFailure::Unavailable
    );
    assert_eq!(
        CloudCallError::Session(ClientError::NotSignedIn).failure(),
        EffectFailure::Refused
    );
    assert!(matches!(
        Input::from(CloudCallError::Protocol),
        Input::Failed(EffectFailure::Refused)
    ));
}

#[test]
fn a_replay_header_keeps_the_runner_that_published_it_and_an_empty_frame_has_no_content() {
    let wire = v1::CloudReplayFrame {
        frame: Some(cloud_replay_frame::Frame::Header(
            v1::CloudDeliveredRecord {
                publication: Some(v1::CloudPublication {
                    publication_id: vec![1; 16],
                    binding: vec![2],
                    total_bytes: 3,
                    ciphertext_sha256: vec![4; 32],
                    retry_until_ms: 0,
                }),
                cursor: 9,
                origin: Some(v1::CloudPublicationOrigin {
                    account_id: "acct".into(),
                    signing_key: vec![5; 32],
                    issuer: Some(Issuer::RunnerId(vec![6; 16])),
                }),
            },
        )),
    };
    let Some(Frame::Header(header)) = replay_frame(wire) else {
        panic!("a header frame");
    };
    assert_eq!(header.cursor, 9);
    assert_eq!(header.origin_runner_id, Some(vec![6; 16]));
    assert_eq!(replay_frame(v1::CloudReplayFrame { frame: None }), None);
    let oversized = v1::CloudReplayFrame {
        frame: Some(cloud_replay_frame::Frame::Data(vec![
            0;
            MAX_RELAY_FRAME_BYTES
                + 1
        ])),
    };
    assert_eq!(replay_frame(oversized), None);
}

#[test]
fn a_selector_names_its_stream_and_refuses_key_epoch_zero() {
    let selector = StreamSelector {
        runner_id: [2; 16],
        runner_key_epoch: 3,
        stream: StreamKind::Directory,
    };
    let wire = wire_selector(&selector).unwrap_or_default();
    assert_eq!(wire.runner_key_epoch, 3);
    assert!(matches!(
        wire.stream,
        Some(v1::cloud_selector::Stream::Directory(_))
    ));
    let zero = StreamSelector {
        runner_key_epoch: 0,
        ..selector
    };
    assert!(matches!(
        wire_selector(&zero),
        Err(CloudCallError::Protocol)
    ));
}
