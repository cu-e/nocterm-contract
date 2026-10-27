use std::collections::VecDeque;

/// Bounded buffer of the most recent session output, addressed by absolute byte offsets.
#[derive(Debug, Clone)]
pub struct OutputRing {
    bytes: VecDeque<u8>,
    capacity: usize,
    /// Offset of the first byte still held (`bytes[0]`).
    start: u64,
}

/// Where a reattaching client continues from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumePoint {
    /// The ring still holds everything after the client's offset: replay these bytes.
    Tail {
        /// Offset of the first replayed byte; equals the client's offset.
        from: u64,
        /// Output the client missed.
        bytes: Vec<u8>,
    },
    /// The client must reset its screen from a snapshot taken at the ring's head.
    Snapshot {
        /// Offset at which the snapshot was taken; output continues from here.
        at: u64,
    },
}

impl OutputRing {
    /// An empty ring that keeps at most `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::with_capacity(capacity.min(64 * 1024)),
            capacity: capacity.max(1),
            start: 0,
        }
    }

    /// Appends output and returns the offset of its first byte.
    pub fn push(&mut self, data: &[u8]) -> u64 {
        let offset = self.head();
        if data.len() >= self.capacity {
            let skip = data.len() - self.capacity;
            self.start = offset + skip as u64;
            self.bytes.clear();
            self.bytes.extend(&data[skip..]);
            return offset;
        }
        let overflow = (self.bytes.len() + data.len()).saturating_sub(self.capacity);
        self.bytes.drain(..overflow);
        self.start += overflow as u64;
        self.bytes.extend(data);
        offset
    }

    /// Offset of the next byte to be written (total bytes ever written).
    pub fn head(&self) -> u64 {
        self.start + self.bytes.len() as u64
    }

    /// Offset of the oldest byte still held.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Bytes currently held.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the ring holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Decides how a client that has seen output up to `client_offset` continues.
    ///
    /// `None` means a new attachment: it always starts from a snapshot so that it does not
    /// replay up to the whole ring. An offset the ring no longer holds, or one beyond the
    /// head (the client saw a different incarnation of the session), also yields a snapshot.
    pub fn resume(&self, client_offset: Option<u64>) -> ResumePoint {
        match client_offset {
            Some(from) if from >= self.start && from <= self.head() => {
                let skip = usize::try_from(from - self.start).unwrap_or(usize::MAX);
                ResumePoint::Tail {
                    from,
                    bytes: self.bytes.iter().skip(skip).copied().collect(),
                }
            }
            _ => ResumePoint::Snapshot { at: self.head() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_keep_growing_after_eviction() {
        let mut ring = OutputRing::new(4);
        assert_eq!(ring.push(b"abc"), 0);
        assert_eq!(ring.push(b"def"), 3);
        assert_eq!(ring.head(), 6);
        assert_eq!(ring.start(), 2);
        assert_eq!(ring.len(), 4);
    }

    #[test]
    fn resume_within_the_ring_replays_the_tail() {
        let mut ring = OutputRing::new(8);
        ring.push(b"hello world");
        assert_eq!(
            ring.resume(Some(8)),
            ResumePoint::Tail {
                from: 8,
                bytes: b"rld".to_vec()
            }
        );
        assert_eq!(
            ring.resume(Some(11)),
            ResumePoint::Tail {
                from: 11,
                bytes: Vec::new()
            }
        );
    }

    #[test]
    fn evicted_or_foreign_offsets_need_a_snapshot() {
        let mut ring = OutputRing::new(4);
        ring.push(b"0123456789");
        assert_eq!(ring.resume(Some(1)), ResumePoint::Snapshot { at: 10 });
        assert_eq!(ring.resume(Some(99)), ResumePoint::Snapshot { at: 10 });
        assert_eq!(ring.resume(None), ResumePoint::Snapshot { at: 10 });
    }

    #[test]
    fn oversized_writes_keep_the_newest_bytes() {
        let mut ring = OutputRing::new(3);
        ring.push(b"ab");
        assert_eq!(ring.push(b"cdefg"), 2);
        assert_eq!(ring.head(), 7);
        assert_eq!(
            ring.resume(Some(4)),
            ResumePoint::Tail {
                from: 4,
                bytes: b"efg".to_vec()
            }
        );
    }
}
