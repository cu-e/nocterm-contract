//! A terminal attached to a hub session that survives dropped connections.
//!
//! The driver keeps the client half of the Link channel ([`ClientTerminal`]): after a drop
//! it reconnects, reopens the channel at the last rendered offset and resends input the
//! node has not confirmed, so nothing typed is lost or applied twice.

use std::time::Duration;

use nocterm_hub_proto::v1::{self, CloseReason, channel_opened, link_down, link_up};
use nocterm_link::{ClientTerminal, InputFrame, Restore};
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

use crate::{ClientError, HubClient, LinkError, StatusCode};

const CHANNEL: u32 = 1;
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// What the user does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalInput {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

/// What to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvent {
    /// Reset the emulator and draw this screen; it is not user-visible output.
    Snapshot(Vec<u8>),
    Output(Vec<u8>),
    /// The channel is open (again).
    Attached,
    /// The connection dropped; the driver retries.
    Reconnecting(String),
}

/// Why the terminal ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEnd {
    /// The process exited with this code.
    Exited(i32),
    /// The node lost the session.
    Lost(String),
    /// The hub refused the channel (not found, forbidden, protocol).
    Refused(String),
    /// The input side was closed (the user detached).
    Detached,
}

/// The session to attach to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalOptions {
    pub session_id: String,
    pub cols: u16,
    pub rows: u16,
    /// Whether this attachment may type and resize.
    pub write: bool,
}

enum Outcome {
    End(TerminalEnd),
    Retry(String),
}

struct Attachment<'a> {
    client: &'a HubClient,
    options: TerminalOptions,
    terminal: ClientTerminal,
    input: mpsc::Receiver<TerminalInput>,
    events: mpsc::Sender<TerminalEvent>,
}

fn up(frame: link_up::Frame) -> v1::LinkUp {
    v1::LinkUp { frame: Some(frame) }
}

fn input_frame(frame: InputFrame) -> v1::LinkUp {
    up(link_up::Frame::Input(v1::ChannelInput {
        channel: CHANNEL,
        seq: frame.seq,
        data: frame.data,
    }))
}

/// Runs until the session ends or `input` closes, reconnecting as needed.
pub async fn run_terminal(
    client: &HubClient,
    options: TerminalOptions,
    input: mpsc::Receiver<TerminalInput>,
    events: mpsc::Sender<TerminalEvent>,
) -> Result<TerminalEnd, ClientError> {
    let mut attachment = Attachment {
        client,
        options,
        terminal: ClientTerminal::new(),
        input,
        events,
    };
    let mut backoff = Duration::from_millis(250);
    loop {
        client.ensure_fresh().await?;
        let reason = match attachment.connect().await {
            Ok((outcome, attached)) => {
                if attached {
                    backoff = Duration::from_millis(250);
                }
                match outcome {
                    Outcome::End(end) => return Ok(end),
                    Outcome::Retry(reason) => reason,
                }
            }
            Err(
                err @ (ClientError::Revoked
                | ClientError::Status {
                    code: StatusCode::Unauthenticated,
                    ..
                }),
            ) => return Err(err),
            Err(err) => err.to_string(),
        };
        if attachment
            .events
            .send(TerminalEvent::Reconnecting(reason))
            .await
            .is_err()
        {
            return Ok(TerminalEnd::Detached);
        }
        sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

impl Attachment<'_> {
    /// One Link connection; returns what ended it and whether the channel opened.
    async fn connect(&mut self) -> Result<(Outcome, bool), ClientError> {
        let (tx, rx) = mpsc::channel(256);
        tx.try_send(up(link_up::Frame::Hello(self.client.link_hello()?)))
            .map_err(|_| LinkError::Closed)?;
        let mut down = self
            .client
            .link()
            .open(ReceiverStream::new(rx))
            .await?
            .into_inner();
        let heartbeat = match down.message().await? {
            Some(v1::LinkDown {
                frame: Some(link_down::Frame::Ready(ready)),
            }) => ready.heartbeat_ms,
            Some(v1::LinkDown {
                frame: Some(link_down::Frame::Error(error)),
            }) => return Err(LinkError::from_frame(&error)),
            _ => return Err(LinkError::NotAccepted.into()),
        };
        let params = self.terminal.open_params();
        let open = v1::ChannelOpen {
            channel: CHANNEL,
            session_id: self.options.session_id.clone(),
            attach_id: params.attach.unwrap_or_default(),
            resume_from: params.resume_from,
            cols: self.options.cols.into(),
            rows: self.options.rows.into(),
            write: self.options.write,
        };
        let _ = tx.send(up(link_up::Frame::Open(open))).await;
        self.pump(
            &tx,
            &mut down,
            Duration::from_millis(u64::from(heartbeat.max(1000))),
        )
        .await
    }

    async fn pump(
        &mut self,
        tx: &mpsc::Sender<v1::LinkUp>,
        down: &mut Streaming<v1::LinkDown>,
        heartbeat: Duration,
    ) -> Result<(Outcome, bool), ClientError> {
        let mut opened = false;
        let mut ping = interval(heartbeat);
        let mut ping_id = 0;
        loop {
            let step = tokio::select! {
                frame = down.message() => match frame {
                    Ok(Some(frame)) => self.on_frame(tx, frame, &mut opened).await?,
                    Ok(None) => Some(Outcome::Retry("the hub closed the link".into())),
                    Err(status) => Some(Outcome::Retry(status.message().to_owned())),
                },
                typed = self.input.recv() => self.on_input(tx, typed, opened).await,
                _ = ping.tick() => {
                    ping_id += 1;
                    let _ = tx.send(up(link_up::Frame::Ping(v1::Ping { id: ping_id }))).await;
                    None
                }
            };
            if let Some(outcome) = step {
                return Ok((outcome, opened));
            }
        }
    }

    async fn emit(&self, event: TerminalEvent) -> Option<Outcome> {
        self.events
            .send(event)
            .await
            .err()
            .map(|_| Outcome::End(TerminalEnd::Detached))
    }

    async fn on_input(
        &mut self,
        tx: &mpsc::Sender<v1::LinkUp>,
        typed: Option<TerminalInput>,
        opened: bool,
    ) -> Option<Outcome> {
        match typed {
            None => {
                let _ = tx
                    .send(up(link_up::Frame::Close(v1::ChannelClose {
                        channel: CHANNEL,
                    })))
                    .await;
                Some(Outcome::End(TerminalEnd::Detached))
            }
            Some(TerminalInput::Data(data)) => {
                let frame = self.terminal.send_input(data);
                if opened {
                    let _ = tx.send(input_frame(frame)).await;
                }
                None
            }
            Some(TerminalInput::Resize { cols, rows }) => {
                self.options.cols = cols;
                self.options.rows = rows;
                if opened {
                    let resize = v1::ChannelResize {
                        channel: CHANNEL,
                        cols: cols.into(),
                        rows: rows.into(),
                    };
                    let _ = tx.send(up(link_up::Frame::Resize(resize))).await;
                }
                None
            }
        }
    }

    async fn on_frame(
        &mut self,
        tx: &mpsc::Sender<v1::LinkUp>,
        frame: v1::LinkDown,
        opened: &mut bool,
    ) -> Result<Option<Outcome>, ClientError> {
        let outcome = match frame.frame {
            Some(link_down::Frame::Opened(open)) => {
                *opened = true;
                self.on_opened(tx, open).await
            }
            Some(link_down::Frame::Output(output)) => {
                match self.terminal.on_output(output.offset, &output.data) {
                    Ok([]) => None,
                    Ok(bytes) => self.emit(TerminalEvent::Output(bytes.to_vec())).await,
                    Err(gap) => Some(Outcome::Retry(gap.to_string())),
                }
            }
            Some(link_down::Frame::Applied(applied)) => {
                self.terminal.on_applied(applied.seq);
                None
            }
            Some(link_down::Frame::Closed(closed)) => Some(closed_outcome(&closed)),
            Some(link_down::Frame::Error(error)) => return Err(LinkError::from_frame(&error)),
            Some(link_down::Frame::Ready(_) | link_down::Frame::Pong(_)) | None => None,
        };
        Ok(outcome)
    }

    async fn on_opened(
        &mut self,
        tx: &mpsc::Sender<v1::LinkUp>,
        open: v1::ChannelOpened,
    ) -> Option<Outcome> {
        let (restore, screen) = match open.restore {
            Some(channel_opened::Restore::Snapshot(s)) => {
                (Restore::Snapshot { at: s.at }, Some(s.screen))
            }
            Some(channel_opened::Restore::Tail(t)) => (Restore::Tail { from: t.from }, None),
            None => return Some(Outcome::Retry("the node sent no restore point".into())),
        };
        for frame in self
            .terminal
            .on_opened(&open.attach_id, open.last_applied_input_seq, restore)
        {
            let _ = tx.send(input_frame(frame)).await;
        }
        if let Some(screen) = screen
            && let Some(outcome) = self.emit(TerminalEvent::Snapshot(screen)).await
        {
            return Some(outcome);
        }
        self.emit(TerminalEvent::Attached).await
    }
}

fn closed_outcome(closed: &v1::ChannelClosed) -> Outcome {
    let reason = CloseReason::try_from(closed.reason).unwrap_or(CloseReason::Unspecified);
    match reason {
        CloseReason::Exited => Outcome::End(TerminalEnd::Exited(closed.exit_code)),
        CloseReason::Lost => Outcome::End(TerminalEnd::Lost(closed.message.clone())),
        CloseReason::Client => Outcome::End(TerminalEnd::Detached),
        CloseReason::NodeOffline | CloseReason::Lagging | CloseReason::Unspecified => {
            Outcome::Retry(closed.message.clone())
        }
        CloseReason::Forbidden | CloseReason::NotFound | CloseReason::Protocol => {
            Outcome::End(TerminalEnd::Refused(closed.message.clone()))
        }
    }
}
