//! The actual transferred HTTP body, rather than its response future, owns work.
use super::*;
use http_body::Body as _;

#[tokio::test]
async fn retained_unary_body_keeps_work_after_request_transfer_and_through_eof()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    // String's standard http_body implementation supplies a real nonempty body;
    // no alternate client, encoder, allocator hook or connection fixture is used.
    let request = http::Request::new(Body::new(String::from("queued unary data")));
    let request = retain_request(request, owner.clone());
    let mut body = request.into_body();
    drop(owner);
    assert!(weak.upgrade().is_some());
    let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
        .await
        .ok_or("missing queued frame")??;
    assert_eq!(
        frame.data_ref().map(|bytes| bytes.as_ref()),
        Some(b"queued unary data".as_slice())
    );
    drop(frame);
    assert!(
        std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .is_none()
    );
    assert!(weak.upgrade().is_some());
    drop(body);
    assert!(weak.upgrade().is_none());
    Ok(())
}
