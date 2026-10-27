#![allow(clippy::expect_used)]

//! Relayed byte streams against a fake hub.

mod support;

use nocterm_hub_client::{MAX_FRAME, RelayError, RelayTarget};
use nocterm_hub_proto::v1::ErrorCode;
use support::FakeHub;

fn target(host: &str) -> RelayTarget {
    RelayTarget {
        host: host.into(),
        port: 22,
        node: None,
    }
}

#[tokio::test]
async fn bytes_go_to_the_target_and_come_back() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;

    let conn = client.relay(&target("echo.test")).await.unwrap();
    assert_eq!(conn.peer_ip().to_string(), "192.0.2.7");
    let (writer, mut reader) = conn.split();
    writer.send(b"SSH-2.0-test\r\n").await.unwrap();

    assert_eq!(reader.recv().await.unwrap().unwrap(), b"SSH-2.0-test\r\n");
}

#[tokio::test]
async fn a_half_close_lets_the_target_finish_and_ends_the_stream_cleanly() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (writer, mut reader) = client.relay(&target("echo.test")).await.unwrap().split();

    writer.send(b"last words").await.unwrap();
    writer.finish().await.unwrap();

    assert_eq!(reader.recv().await.unwrap().unwrap(), b"last words");
    assert_eq!(reader.recv().await.unwrap().unwrap(), b"bye");
    assert_eq!(reader.recv().await.unwrap(), None);
    assert_eq!(reader.recv().await.unwrap(), None);
}

#[tokio::test]
async fn large_writes_are_split_into_bounded_frames() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (writer, mut reader) = client.relay(&target("echo.test")).await.unwrap().split();
    let payload = vec![7u8; 3 * MAX_FRAME + 10];

    let sender = tokio::spawn(async move { writer.send(&payload).await });
    let mut received = 0;
    while received < 3 * MAX_FRAME + 10 {
        let chunk = reader.recv().await.unwrap().unwrap();
        assert!(chunk.len() <= MAX_FRAME);
        received += chunk.len();
    }
    sender.await.unwrap().unwrap();

    let sizes = hub.seen.relayed_frame_sizes();
    assert_eq!(sizes, [MAX_FRAME, MAX_FRAME, MAX_FRAME, 10]);
}

#[tokio::test]
async fn a_refused_target_is_a_typed_denial() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;

    let err = client.relay(&target("denied.test")).await.unwrap_err();

    assert!(matches!(
        err,
        RelayError::Closed {
            code: Some(ErrorCode::RelayDenied),
            ..
        }
    ));
}

#[tokio::test]
async fn a_hub_without_relays_is_reported_as_unsupported() {
    let hub = FakeHub::start(false).await;
    let client = hub.signed_in_client().await;

    let err = client.relay(&target("echo.test")).await.unwrap_err();

    assert!(matches!(err, RelayError::Unsupported));
}
