/// Owner-side record of the last input frame applied for one attachment.
///
/// Sequence numbers start at 1 and are monotonic per attachment across every reconnect;
/// the connection epoch only fences stale streams and is not part of the key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputDedup {
    last_applied: u64,
}

/// What the owner does with an incoming input frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputVerdict {
    /// Next in sequence: apply it, then acknowledge it as applied.
    Apply,
    /// Already applied (a resend after a reconnect): acknowledge without applying.
    Duplicate,
    /// Skips a sequence number: a protocol violation, the channel must be reset.
    OutOfOrder,
}

impl InputDedup {
    /// Restores a record, for example after the attachment moved to a new connection.
    pub fn with_last_applied(last_applied: u64) -> Self {
        Self { last_applied }
    }

    /// Sequence number of the last applied frame (`0` if none).
    pub fn last_applied(&self) -> u64 {
        self.last_applied
    }

    /// Classifies frame `seq` and records it when it is applied.
    pub fn accept(&mut self, seq: u64) -> InputVerdict {
        if seq <= self.last_applied {
            InputVerdict::Duplicate
        } else if seq == self.last_applied + 1 {
            self.last_applied = seq;
            InputVerdict::Apply
        } else {
            InputVerdict::OutOfOrder
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_apply_once_and_in_order() {
        let mut dedup = InputDedup::default();
        assert_eq!(dedup.accept(1), InputVerdict::Apply);
        assert_eq!(dedup.accept(1), InputVerdict::Duplicate);
        assert_eq!(dedup.accept(3), InputVerdict::OutOfOrder);
        assert_eq!(dedup.accept(2), InputVerdict::Apply);
        assert_eq!(dedup.last_applied(), 2);
    }
}
