//! Deterministic simulation: a session owner and a client exchange frames over a link that
//! drops at random points. Whatever the drop pattern, every typed byte is applied exactly
//! once and in order, and the client renders exactly the session's output.

use std::collections::{HashMap, VecDeque};

use crate::{ClientTerminal, InputDedup, InputVerdict, OutputRing, Restore, ResumePoint};

/// Small linear congruential generator: deterministic and dependency free.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

enum Down {
    Output { offset: u64, data: Vec<u8> },
    Applied(u64),
}

struct Owner {
    ring: OutputRing,
    attaches: HashMap<String, InputDedup>,
    applied: Vec<u8>,
    next_attach: u32,
}

impl Owner {
    fn open(
        &mut self,
        attach: Option<String>,
        resume_from: Option<u64>,
    ) -> (String, u64, ResumePoint) {
        let attach = attach
            .filter(|id| self.attaches.contains_key(id))
            .unwrap_or_else(|| {
                self.next_attach += 1;
                let id = format!("a{}", self.next_attach);
                self.attaches.insert(id.clone(), InputDedup::default());
                id
            });
        let last = self.attaches[&attach].last_applied();
        (attach, last, self.ring.resume(resume_from))
    }

    fn input(&mut self, attach: &str, seq: u64, data: &[u8]) -> Option<u64> {
        let dedup = self.attaches.get_mut(attach)?;
        match dedup.accept(seq) {
            InputVerdict::Apply => {
                self.applied.extend_from_slice(data);
                Some(seq)
            }
            InputVerdict::Duplicate => Some(seq),
            InputVerdict::OutOfOrder => None,
        }
    }
}

fn run(seed: u64, ring_capacity: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool) {
    let mut rng = Lcg(seed);
    let mut owner = Owner {
        ring: OutputRing::new(ring_capacity),
        attaches: HashMap::new(),
        applied: Vec::new(),
        next_attach: 0,
    };
    let mut client = ClientTerminal::new();
    let mut rendered = Vec::new();
    let mut produced = Vec::new();
    let mut typed = Vec::new();
    let mut downlink: VecDeque<Down> = VecDeque::new();
    let mut uplink: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
    let mut connected = false;
    let mut attach = String::new();
    let mut snapshot_seen = false;

    for step in 0..4_000u32 {
        if !connected {
            let params = client.open_params();
            let (id, last, point) = owner.open(params.attach, params.resume_from);
            attach = id;
            let restore = match point {
                ResumePoint::Tail { from, bytes } => {
                    downlink.push_back(Down::Output {
                        offset: from,
                        data: bytes,
                    });
                    Restore::Tail { from }
                }
                ResumePoint::Snapshot { at } => {
                    // A snapshot replaces the screen: model it as "everything so far".
                    // The very first open always starts from a snapshot.
                    snapshot_seen |= step > 0;
                    rendered.clone_from(&produced);
                    Restore::Snapshot { at }
                }
            };
            for frame in client.on_opened(&attach, last, restore) {
                uplink.push_back((frame.seq, frame.data));
            }
            connected = true;
        }

        if rng.chance(30) {
            let data = format!("out{step};").into_bytes();
            let offset = owner.ring.push(&data);
            produced.extend_from_slice(&data);
            downlink.push_back(Down::Output { offset, data });
        }
        if rng.chance(20) && typed.len() < 1_500 {
            let byte = b'a' + u8::try_from(step % 26).unwrap_or(0);
            typed.push(byte);
            let frame = client.send_input(vec![byte]);
            uplink.push_back((frame.seq, frame.data));
        }
        if let Some((seq, data)) = uplink.pop_front()
            && let Some(applied) = owner.input(&attach, seq, &data)
        {
            downlink.push_back(Down::Applied(applied));
        }
        if let Some(frame) = downlink.pop_front() {
            match frame {
                Down::Output { offset, data } => {
                    let fresh = client
                        .on_output(offset, &data)
                        .expect("no gaps on one connection");
                    rendered.extend_from_slice(fresh);
                }
                Down::Applied(seq) => client.on_applied(seq),
            }
        }
        if rng.chance(3) {
            // The link drops: frames in flight are lost in both directions.
            downlink.clear();
            uplink.clear();
            connected = false;
        }
    }

    // Final quiet reconnects flush everything still pending.
    for _ in 0..3 {
        let params = client.open_params();
        let (id, last, point) = owner.open(params.attach, params.resume_from);
        let (restore, tail) = match point {
            ResumePoint::Tail { from, bytes } => (Restore::Tail { from }, Some((from, bytes))),
            ResumePoint::Snapshot { at } => {
                snapshot_seen = true;
                rendered.clone_from(&produced);
                (Restore::Snapshot { at }, None)
            }
        };
        for frame in client.on_opened(&id, last, restore) {
            if let Some(seq) = owner.input(&id, frame.seq, &frame.data) {
                client.on_applied(seq);
            }
        }
        if let Some((from, bytes)) = tail {
            let fresh = client
                .on_output(from, &bytes)
                .expect("tail continues the stream");
            rendered.extend_from_slice(fresh);
        }
    }
    (produced, rendered, typed, owner.applied, snapshot_seen)
}

#[test]
fn input_is_applied_exactly_once_whatever_the_drops() {
    for seed in 1..40 {
        let (_, _, typed, applied, _) = run(seed, 1 << 20);
        assert_eq!(typed, applied, "seed {seed}");
    }
}

#[test]
fn a_large_ring_resumes_with_tails_only() {
    for seed in 1..40 {
        let (produced, rendered, _, _, snapshot) = run(seed, 1 << 20);
        assert!(
            !snapshot,
            "seed {seed} needed a snapshot after the first open"
        );
        assert_eq!(rendered, produced, "seed {seed}");
    }
}

#[test]
fn a_small_ring_falls_back_to_snapshots_without_losing_input() {
    let (produced, rendered, typed, applied, snapshot) = run(7, 4);
    assert!(snapshot);
    assert_eq!(typed, applied);
    assert_eq!(rendered, produced);
}
