//! A transferred request body retains its queued buffers' original allocation.
use super::*;
use tokio_stream::StreamExt;

#[tokio::test]
async fn runner_request_stream_keeps_residency_after_other_owners_drop_and_through_eof()
-> Result<(), Box<dyn std::error::Error>> {
    let residency = Arc::new(());
    let weak = Arc::downgrade(&residency);
    let (sender, receiver) = mpsc::channel(MAX_RELAY_QUEUE_FRAMES);
    let mut transferred_body = ResidentFrames::new(receiver, Some(residency.clone()));
    sender
        .send(v1::CloudPublishFrame {
            frame: Some(Frame::Data(vec![7; 1024])),
        })
        .await?;
    drop(sender);
    drop(residency);
    assert!(weak.upgrade().is_some());
    let frame = transferred_body
        .next()
        .await
        .ok_or("missing queued frame")?;
    assert!(matches!(&frame.frame, Some(Frame::Data(bytes)) if bytes.len() == 1024));
    drop(frame);
    assert!(transferred_body.next().await.is_none());
    assert!(weak.upgrade().is_some());
    drop(transferred_body);
    assert!(weak.upgrade().is_none());
    Ok(())
}

#[tokio::test]
async fn runner_receipt_output_keeps_residency_after_task_future_finishes()
-> Result<(), Box<dyn std::error::Error>> {
    for accepted in [true, false] {
        let residency = Arc::new(());
        let weak = Arc::downgrade(&residency);
        let task = tokio::spawn(async move {
            let receipt = if accepted {
                Ok(v1::CloudDeliveryReceipt {
                    publication_id: vec![3; 16],
                    cursor: 1,
                    ciphertext_sha256: vec![4; 32],
                })
            } else {
                Err(CloudError::Protocol)
            };
            ResidentReceipt::new(receipt, Some(residency))
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // The task's async future has finished, but its actual output still owns
        // the response allocation, including a queued error result.
        assert!(weak.upgrade().is_some());
        let output = task.await?;
        assert!(weak.upgrade().is_some());
        drop(output);
        assert!(weak.upgrade().is_none());
    }
    Ok(())
}
