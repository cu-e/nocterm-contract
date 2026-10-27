//! A relayed byte stream: a TCP connection the hub (or one of its nodes) opens on the
//! caller's behalf, carried over one gRPC stream.
//!
//! Both directions are bounded: at most [`QUEUE_DEPTH`] frames of [`MAX_FRAME`] bytes wait
//! to be sent, and a slow reader stops the hub through the HTTP/2 window, so neither side
//! buffers without limit. Dropping a [`RelayWriter`] without [`RelayWriter::finish`] aborts
//! the stream; `finish` is the half-close that lets the target answer.

use std::net::IpAddr;
use std::pin::Pin;
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
#[derive(Debug)]
pub struct RelayWriter {
    up: mpsc::Sender<v1::RelayUp>,
}

impl RelayWriter {
    /// Queues `data` for the target, split into frames of at most [`MAX_FRAME`] bytes. Waits
    /// while [`QUEUE_DEPTH`] frames are already waiting, which is how a slow target slows the
    /// sender down.
    pub async fn send(&self, data: &[u8]) -> Result<(), RelayError> {
        for chunk in data.chunks(MAX_FRAME) {
            self.up
                .send(frame(relay_up::Frame::Data(chunk.to_vec())))
                .await
                .map_err(|_| RelayError::Interrupted)?;
        }
        Ok(())
    }

    /// Half-closes: the target receives end-of-file but may still answer.
    pub async fn finish(self) -> Result<(), RelayError> {
        self.up
            .send(frame(relay_up::Frame::Close(v1::RelayClose {})))
            .await
            .map_err(|_| RelayError::Interrupted)
    }
}

/// The receiving half of a relay: a stream of byte chunks that ends with `None` when the
/// target closed cleanly.
#[derive(Debug)]
pub struct RelayReader {
    down: Streaming<v1::RelayDown>,
    done: bool,
}

impl RelayReader {
    /// The next chunk from the target; `Ok(None)` after a clean close.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, RelayError> {
        tokio_stream::StreamExt::next(self).await.transpose()
    }
}

impl Stream for RelayReader {
    type Item = Result<Vec<u8>, RelayError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        let item = match Pin::new(&mut self.down).poll_next(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(item) => item,
        };
        self.done = true;
        match item {
            Some(Ok(v1::RelayDown {
                frame: Some(relay_down::Frame::Data(data)),
            })) => {
                self.done = false;
                Poll::Ready(Some(Ok(data)))
            }
            Some(Ok(v1::RelayDown {
                frame: Some(relay_down::Frame::Closed(closed)),
            })) => Poll::Ready(closed_error(&closed).map(Err)),
            Some(Ok(_)) => Poll::Ready(Some(Err(RelayError::UnexpectedFrame))),
            Some(Err(status)) => Poll::Ready(Some(Err(status.into()))),
            None => Poll::Ready(Some(Err(RelayError::Interrupted))),
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
        Ok(RelayConn {
            peer_ip,
            writer: RelayWriter { up },
            reader: RelayReader { down, done: false },
        })
    }
}
