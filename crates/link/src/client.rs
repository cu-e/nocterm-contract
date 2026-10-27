use std::collections::VecDeque;

/// Client-side state of one terminal channel that survives reconnects.
///
/// The client remembers the attachment the owner assigned, the output offset it has
/// rendered, and every input frame the owner has not yet confirmed as applied.
#[derive(Debug, Clone, Default)]
pub struct ClientTerminal {
    attach: Option<String>,
    next_output: Option<u64>,
    next_seq: u64,
    pending: VecDeque<InputFrame>,
}

/// Parameters for (re)opening the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenParams {
    /// Attachment to continue; `None` asks the owner for a new one.
    pub attach: Option<String>,
    /// Next output offset the client expects; `None` asks for a snapshot.
    pub resume_from: Option<u64>,
}

/// How the owner restored the client's view when the channel opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restore {
    /// Missed output follows as ordinary output frames starting at `from`.
    Tail {
        /// First offset that will be delivered.
        from: u64,
    },
    /// The client resets its screen from a snapshot; output continues at `at`.
    Snapshot {
        /// Offset at which the snapshot was taken.
        at: u64,
    },
}

/// One input frame and its sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFrame {
    /// Monotonic per attachment, starting at 1.
    pub seq: u64,
    /// Bytes typed by the user.
    pub data: Vec<u8>,
}

/// Output that does not continue the stream the client has rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OutputError {
    /// Output arrived before the channel opened.
    #[error("output before the channel opened")]
    NotOpen,
    /// Output starts after the expected offset: bytes are missing.
    #[error("output gap: expected offset {expected}, got {got}")]
    Gap {
        /// Offset the client expected.
        expected: u64,
        /// Offset the frame starts at.
        got: u64,
    },
}

impl ClientTerminal {
    /// A channel that has never been opened.
    pub fn new() -> Self {
        Self::default()
    }

    /// What to send when opening or reopening the channel.
    pub fn open_params(&self) -> OpenParams {
        OpenParams {
            attach: self.attach.clone(),
            resume_from: self.next_output,
        }
    }

    /// Attachment assigned by the owner, if the channel was opened before.
    pub fn attach(&self) -> Option<&str> {
        self.attach.as_deref()
    }

    /// Records the owner's answer to an open and returns the input frames to resend.
    ///
    /// Frames up to `last_applied` were applied before the connection dropped and are
    /// discarded; the rest are resent in order. A new attachment id (the owner lost the old
    /// one) restarts numbering, so pending frames are renumbered from 1.
    pub fn on_opened(
        &mut self,
        attach: &str,
        last_applied: u64,
        restore: Restore,
    ) -> Vec<InputFrame> {
        if self.attach.as_deref() == Some(attach) {
            self.on_applied(last_applied);
        } else {
            self.attach = Some(attach.to_owned());
            self.next_seq = last_applied;
            let mut renumbered = VecDeque::with_capacity(self.pending.len());
            for frame in self.pending.drain(..) {
                self.next_seq += 1;
                renumbered.push_back(InputFrame {
                    seq: self.next_seq,
                    data: frame.data,
                });
            }
            self.pending = renumbered;
        }
        self.next_output = Some(match restore {
            Restore::Tail { from } => from,
            Restore::Snapshot { at } => at,
        });
        self.pending.iter().cloned().collect()
    }

    /// Accepts an output frame and returns the bytes to render (possibly empty when the
    /// frame repeats output the client already has).
    pub fn on_output<'a>(&mut self, offset: u64, data: &'a [u8]) -> Result<&'a [u8], OutputError> {
        let expected = self.next_output.ok_or(OutputError::NotOpen)?;
        if offset > expected {
            return Err(OutputError::Gap {
                expected,
                got: offset,
            });
        }
        let end = offset + data.len() as u64;
        if end <= expected {
            return Ok(&[]);
        }
        let skip = usize::try_from(expected - offset).unwrap_or(usize::MAX);
        self.next_output = Some(end);
        Ok(&data[skip..])
    }

    /// Queues typed bytes and returns the frame to send now.
    pub fn send_input(&mut self, data: Vec<u8>) -> InputFrame {
        self.next_seq += 1;
        let frame = InputFrame {
            seq: self.next_seq,
            data,
        };
        self.pending.push_back(frame.clone());
        frame
    }

    /// Drops frames the owner confirmed as applied.
    pub fn on_applied(&mut self, seq: u64) {
        while self.pending.front().is_some_and(|frame| frame.seq <= seq) {
            self.pending.pop_front();
        }
    }

    /// Input frames not yet confirmed.
    pub fn pending_input(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_open_asks_for_a_snapshot() {
        let terminal = ClientTerminal::new();
        assert_eq!(
            terminal.open_params(),
            OpenParams {
                attach: None,
                resume_from: None
            }
        );
    }

    #[test]
    fn reopen_continues_from_the_rendered_offset() {
        let mut terminal = ClientTerminal::new();
        terminal.on_opened("a1", 0, Restore::Snapshot { at: 10 });
        assert_eq!(terminal.on_output(10, b"abc").unwrap(), b"abc");
        assert_eq!(
            terminal.open_params(),
            OpenParams {
                attach: Some("a1".into()),
                resume_from: Some(13)
            }
        );
    }

    #[test]
    fn overlapping_output_is_trimmed_and_gaps_are_errors() {
        let mut terminal = ClientTerminal::new();
        terminal.on_opened("a1", 0, Restore::Tail { from: 0 });
        assert_eq!(terminal.on_output(0, b"hello").unwrap(), b"hello");
        assert_eq!(terminal.on_output(3, b"lo world").unwrap(), b" world");
        assert_eq!(terminal.on_output(2, b"ll").unwrap(), b"");
        assert_eq!(
            terminal.on_output(20, b"x"),
            Err(OutputError::Gap {
                expected: 11,
                got: 20
            })
        );
    }

    #[test]
    fn unconfirmed_input_is_resent_after_reopen() {
        let mut terminal = ClientTerminal::new();
        terminal.on_opened("a1", 0, Restore::Snapshot { at: 0 });
        terminal.send_input(b"l".to_vec());
        terminal.send_input(b"s".to_vec());
        terminal.send_input(b"\r".to_vec());
        terminal.on_applied(1);
        let resend = terminal.on_opened("a1", 2, Restore::Tail { from: 0 });
        assert_eq!(
            resend,
            vec![InputFrame {
                seq: 3,
                data: b"\r".to_vec()
            }]
        );
    }

    #[test]
    fn a_new_attachment_renumbers_pending_input() {
        let mut terminal = ClientTerminal::new();
        terminal.on_opened("a1", 0, Restore::Snapshot { at: 0 });
        terminal.send_input(b"x".to_vec());
        terminal.send_input(b"y".to_vec());
        let resend = terminal.on_opened("a2", 0, Restore::Snapshot { at: 5 });
        assert_eq!(resend.iter().map(|f| f.seq).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(terminal.send_input(b"z".to_vec()).seq, 3);
    }
}
