#![allow(clippy::expect_used)]

//! Relayed byte streams against a fake hub.

mod support;

use nocterm_hub_client::{MAX_FRAME, RelayError, RelayTarget};
use nocterm_hub_proto::v1::ErrorCode;
use support::{FakeHub, RelayEnd};

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
    let (mut writer, mut reader) = conn.split();
    writer.send(b"SSH-2.0-test\r\n").await.unwrap();

    assert_eq!(reader.recv().await.unwrap().unwrap(), b"SSH-2.0-test\r\n");
}

#[tokio::test]
async fn a_half_close_lets_the_target_finish_and_ends_the_stream_cleanly() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (mut writer, mut reader) = client.relay(&target("echo.test")).await.unwrap().split();

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
    let (mut writer, mut reader) = client.relay(&target("echo.test")).await.unwrap().split();
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

#[tokio::test]
async fn the_open_frame_names_the_target_and_the_node() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let target = RelayTarget {
        host: "db.internal".into(),
        port: 2222,
        node: Some("node-7".into()),
    };

    let _conn = client.relay(&target).await.unwrap();
    let _plain = client.relay(&self::target("echo.test")).await.unwrap();

    let opens = hub.seen.relay_opens();
    assert_eq!(opens.len(), 2);
    assert_eq!(opens[0].host, "db.internal");
    assert_eq!(opens[0].port, 2222);
    assert_eq!(opens[0].node, "node-7");
    assert_eq!(opens[1].node, "");
}

#[tokio::test]
async fn a_writer_waits_when_the_hub_does_not_read() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (mut writer, _reader) = client.relay(&target("stall.test")).await.unwrap().split();
    // Far more than the queue and the HTTP/2 window can hold.
    let payload = vec![9u8; 256 * MAX_FRAME];

    let sent =
        tokio::time::timeout(std::time::Duration::from_millis(500), writer.send(&payload)).await;

    assert!(
        sent.is_err(),
        "the sender must wait for a hub that reads nothing"
    );
    assert!(hub.seen.relayed_frame_sizes().is_empty());
}

#[tokio::test]
async fn dropping_the_writer_is_an_abort_and_finishing_it_is_a_half_close() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (mut writer, _reader) = client.relay(&target("echo.test")).await.unwrap().split();
    writer.send(b"partial").await.unwrap();
    drop(writer);
    assert_eq!(hub.seen.first_relay_end().await, RelayEnd::Aborted);

    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (writer, _reader) = client.relay(&target("echo.test")).await.unwrap().split();
    writer.finish().await.unwrap();
    assert_eq!(hub.seen.first_relay_end().await, RelayEnd::Closed);
}

#[tokio::test]
async fn an_empty_frame_from_the_hub_is_not_the_end_of_the_stream() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (_writer, mut reader) = client.relay(&target("empty.test")).await.unwrap().split();

    assert_eq!(reader.recv().await.unwrap().unwrap(), b"x");
    assert_eq!(reader.recv().await.unwrap(), None);
}

#[tokio::test]
async fn an_empty_write_sends_no_frame() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (mut echo, mut reply) = client.relay(&target("echo.test")).await.unwrap().split();
    echo.send(b"").await.unwrap();
    echo.send(b"a").await.unwrap();
    assert_eq!(reply.recv().await.unwrap().unwrap(), b"a");
    assert_eq!(hub.seen.relayed_frame_sizes(), [1]);
}

#[tokio::test]
async fn nothing_can_be_written_after_the_hub_closed_the_relay() {
    let hub = FakeHub::start(true).await;
    let client = hub.signed_in_client().await;
    let (mut writer, mut reader) = client.relay(&target("hangup.test")).await.unwrap().split();

    assert_eq!(reader.recv().await.unwrap(), None);

    assert!(matches!(
        writer.send(b"too late").await,
        Err(RelayError::AlreadyClosed)
    ));
    assert!(writer.finish().await.is_ok());
}
