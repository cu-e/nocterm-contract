//! A relayed byte stream: a TCP connection the hub (or one of its nodes) opens on the
//! caller's behalf, carried over one gRPC stream.
//!
//! Both directions are bounded: at most [`QUEUE_DEPTH`] frames of [`MAX_FRAME`] bytes wait
//! to be sent, and a slow reader stops the hub through the HTTP/2 window, so neither side
//! buffers without limit. Dropping a [`RelayWriter`] without [`RelayWriter::finish`] aborts
//! the stream; `finish` is the half-close that lets the target answer.
//!
//! The end of the bytes is explicit: an empty frame is never sent and is skipped when
//! received, so a chunk of zero bytes never reads as end-of-file. The hub's `closed` ends the
//! whole relay; once the reader has seen it, the writer refuses to send
//! ([`RelayError::AlreadyClosed`]).

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use nocterm_hub_grpc::relay_service_client::RelayServiceClient;
use nocterm_hub_proto::v1::{self, ErrorCode, relay_down, relay_up};
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

use crate::{ClientError, HubClient, StatusCode};

/// Largest payload of one data frame; larger writes are split.
pub const MAX_FRAME: usize = 32 * 1024;
/// Data frames that may wait to be sent before a write waits.
pub const QUEUE_DEPTH: usize = 16;

/// Where a relay should connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTarget {
    /// Host name or IP literal; the hub resolves it and applies its egress policy.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Node that dials from inside its network; `None` lets the hub dial.
    pub node: Option<String>,
}

/// A relay could not be opened or ended abnormally.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// The hub does not offer relays (it answered `UNIMPLEMENTED`).
    #[error("this hub does not offer relays")]
    Unsupported,
    /// The call failed.
    #[error(transparent)]
    Hub(ClientError),
    /// The hub ended the stream with a reason: the target was refused or a limit was reached.
    #[error("the hub closed the relay: {message}")]
    Closed {
        /// The hub's reason: `RELAY_DENIED`, `RELAY_LIMIT`, `NODE_UNAVAILABLE`, …
        code: Option<ErrorCode>,
        /// For display only.
        message: String,
    },
    /// The first frame was not `opened`, or a frame had no content.
    #[error("the hub broke the relay protocol")]
    UnexpectedFrame,
    /// The peer address of `opened` is not an IP literal.
    #[error("the hub reported an invalid peer address")]
    BadPeerAddress,
    /// The stream ended without a `closed` frame, or the writer lost its stream.
    #[error("the relay stream ended unexpectedly")]
    Interrupted,
    /// The relay has ended (the hub sent `closed` or the stream failed): nothing more can be
    /// written, and bytes sent after the end would be lost.
    #[error("the relay has ended; nothing more can be sent")]
    AlreadyClosed,
}

impl From<ClientError> for RelayError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::Status {
                code: StatusCode::Unimplemented,
                ..
            } => Self::Unsupported,
            other => Self::Hub(other),
        }
    }
}

impl From<tonic::Status> for RelayError {
    fn from(status: tonic::Status) -> Self {
        ClientError::from(status).into()
    }
}

/// An open relay: write bytes to the target and read what it sends back.
#[derive(Debug)]
pub struct RelayConn {
    peer_ip: IpAddr,
    writer: RelayWriter,
    reader: RelayReader,
}

impl RelayConn {
    /// The address the hub or node connected to.
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// Splits into the two directions, which may then live in different tasks.
    pub fn split(self) -> (RelayWriter, RelayReader) {
        (self.writer, self.reader)
    }
}

/// The sending half of a relay.
///
/// Writing takes `&mut self` and the half is neither `Clone` nor shareable behind `&`, so the
/// frames of two writes can never be interleaved in the byte stream. To write from several
/// tasks, put one task in front of the writer and send it the buffers through a channel.
#[derive(Debug)]
pub struct RelayWriter {
    up: mpsc::Sender<v1::RelayUp>,
    ended: Arc<AtomicBool>,
}

impl RelayWriter {
    fn new(up: mpsc::Sender<v1::RelayUp>, ended: Arc<AtomicBool>) -> Self {
        Self { up, ended }
    }

    /// Queues `data` for the target, split into frames of at most [`MAX_FRAME`] bytes. Waits
    /// while [`QUEUE_DEPTH`] frames are already waiting, which is how a slow target slows the
    /// sender down. Empty `data` sends nothing.
    ///
    /// If the future is dropped before it completes, an unknown prefix of `data` was queued:
    /// treat the stream as broken (drop the writer to abort it).
    pub async fn send(&mut self, data: &[u8]) -> Result<(), RelayError> {
        for chunk in data.chunks(MAX_FRAME) {
            if self.ended.load(Ordering::Acquire) {
                return Err(RelayError::AlreadyClosed);
            }
            self.up
                .send(frame(relay_up::Frame::Data(chunk.to_vec())))
                .await
                .map_err(|_| RelayError::Interrupted)?;
        }
        Ok(())
    }

    /// Half-closes: the target receives end-of-file but may still answer. After the relay has
    /// ended there is nothing to close and this does nothing.
    pub async fn finish(self) -> Result<(), RelayError> {
        if self.ended.load(Ordering::Acquire) {
            return Ok(());
        }
        self.up
            .send(frame(relay_up::Frame::Close(v1::RelayClose {})))
            .await
            .map_err(|_| RelayError::Interrupted)
    }
}

/// The receiving half of a relay: a stream of non-empty byte chunks that ends with `None` when
/// the target closed cleanly.
#[derive(Debug)]
pub struct RelayReader {
    down: Streaming<v1::RelayDown>,
    done: bool,
    ended: Arc<AtomicBool>,
}

impl RelayReader {
    /// The next chunk from the target; `Ok(None)` after a clean close. A chunk is never empty.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, RelayError> {
        tokio_stream::StreamExt::next(self).await.transpose()
    }

    /// The relay is over; tell the writer.
    fn end(&mut self) {
        self.done = true;
        self.ended.store(true, Ordering::Release);
    }
}

impl Stream for RelayReader {
    type Item = Result<Vec<u8>, RelayError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }
            let item = match Pin::new(&mut self.down).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(item) => item,
            };
            return match item {
                // An empty frame is not the end of the stream: skip it.
                Some(Ok(v1::RelayDown {
                    frame: Some(relay_down::Frame::Data(data)),
                })) if data.is_empty() => continue,
                Some(Ok(v1::RelayDown {
                    frame: Some(relay_down::Frame::Data(data)),
                })) => Poll::Ready(Some(Ok(data))),
                Some(Ok(v1::RelayDown {
                    frame: Some(relay_down::Frame::Closed(closed)),
                })) => {
                    self.end();
                    Poll::Ready(closed_error(&closed).map(Err))
                }
                Some(Ok(_)) => {
                    self.end();
                    Poll::Ready(Some(Err(RelayError::UnexpectedFrame)))
                }
                Some(Err(status)) => {
                    self.end();
                    Poll::Ready(Some(Err(status.into())))
                }
                None => {
                    self.end();
                    Poll::Ready(Some(Err(RelayError::Interrupted)))
                }
            };
        }
    }
}

fn frame(frame: relay_up::Frame) -> v1::RelayUp {
    v1::RelayUp { frame: Some(frame) }
}

/// `None` for a clean close, the reason otherwise.
fn closed_error(closed: &v1::RelayClosed) -> Option<RelayError> {
    if closed.code == ErrorCode::Unspecified as i32 {
        return None;
    }
    Some(RelayError::Closed {
        code: ErrorCode::try_from(closed.code).ok(),
        message: closed.message.clone(),
    })
}

impl HubClient {
    /// Opens a relay to `target` and waits until the hub or node has connected.
    ///
    /// A refusal arrives as [`RelayError::Closed`] with `RELAY_DENIED` or `RELAY_LIMIT`; a hub
    /// without relays as [`RelayError::Unsupported`].
    pub async fn relay(&self, target: &RelayTarget) -> Result<RelayConn, RelayError> {
        let mut client =
            RelayServiceClient::new(self.signed()).max_decoding_message_size(MAX_FRAME + 1024);
        let (up, rx) = mpsc::channel(QUEUE_DEPTH);
        up.send(frame(relay_up::Frame::Open(v1::RelayOpen {
            host: target.host.clone(),
            port: u32::from(target.port),
            node: target.node.clone().unwrap_or_default(),
        })))
        .await
        .map_err(|_| RelayError::Interrupted)?;
        let mut down = client.open(ReceiverStream::new(rx)).await?.into_inner();
        let peer_ip = match down.message().await? {
            Some(v1::RelayDown {
                frame: Some(relay_down::Frame::Opened(opened)),
            }) => opened
                .peer_ip
                .parse()
                .map_err(|_| RelayError::BadPeerAddress)?,
            Some(v1::RelayDown {
                frame: Some(relay_down::Frame::Closed(closed)),
            }) => {
                return Err(closed_error(&closed).unwrap_or(RelayError::Interrupted));
            }
            Some(_) => return Err(RelayError::UnexpectedFrame),
            None => return Err(RelayError::Interrupted),
        };
        let ended = Arc::new(AtomicBool::new(false));
        Ok(RelayConn {
            peer_ip,
            writer: RelayWriter::new(up, Arc::clone(&ended)),
            reader: RelayReader {
                down,
                done: false,
                ended,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn writer() -> (RelayWriter, mpsc::Receiver<v1::RelayUp>) {
        let (up, rx) = mpsc::channel(QUEUE_DEPTH);
        (RelayWriter::new(up, Arc::default()), rx)
    }

    #[tokio::test]
    async fn the_send_queue_is_bounded_and_resumes_when_the_hub_reads() {
        let (mut writer, mut hub) = writer();
        writer
            .send(&vec![1; QUEUE_DEPTH * MAX_FRAME])
            .await
            .expect("a full queue of frames fits");

        let blocked = tokio::time::timeout(Duration::from_millis(100), writer.send(b"x")).await;
        assert!(blocked.is_err(), "the 17th frame must wait for the reader");

        assert!(hub.recv().await.is_some());
        tokio::time::timeout(Duration::from_secs(5), writer.send(b"x"))
            .await
            .expect("room again")
            .expect("sent");
    }

    #[tokio::test]
    async fn dropping_the_writer_ends_the_stream_without_a_close_frame() {
        let (mut writer, mut hub) = writer();
        writer.send(b"partial").await.expect("sent");
        drop(writer);

        assert!(matches!(
            hub.recv().await,
            Some(v1::RelayUp {
                frame: Some(relay_up::Frame::Data(_))
            })
        ));
        assert!(hub.recv().await.is_none(), "no close frame, only the end");
    }

    #[tokio::test]
    async fn finishing_sends_the_close_frame_and_empty_writes_send_nothing() {
        let (mut writer, mut hub) = writer();
        writer.send(b"").await.expect("nothing to send");
        writer.finish().await.expect("closed");

        assert!(matches!(
            hub.recv().await,
            Some(v1::RelayUp {
                frame: Some(relay_up::Frame::Close(_))
            })
        ));
        assert!(hub.recv().await.is_none());
    }
}
