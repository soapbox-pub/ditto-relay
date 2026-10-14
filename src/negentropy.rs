//! Negentropy, the range-based set reconciliation NIP-77 syncs with:
//! protocol V1, as its appendix specifies.
//!
//! Each side has a set of items, each an event's `created_at` and id,
//! sorted. A message is a version byte and a list of ranges covering every
//! item there could be, each sent as its upper bound and either nothing (a
//! skip), a fingerprint of the items within it, or their ids. The relay
//! answers each range whose fingerprint differs from its own by splitting
//! it into fingerprinted buckets, or by listing its ids once it's small,
//! until the client knows which ids each side has that the other doesn't.
//!
//! Ported from the `negentropy` crate, which ported it from the reference
//! implementation, and owned here. Unlike the crate, a message that claims
//! more than it holds is refused rather than believed: a list of ids is
//! checked against the bytes left before room is made for them, where the
//! crate would try to reserve a terabyte for a list of a few bytes and
//! abort the relay.
//!
//! Copyright (c) 2023 Doug Hoyte
//! Copyright (c) 2023 Yuki Kishimoto
//!
//! Permission is hereby granted, free of charge, to any person obtaining a
//! copy of this software and associated documentation files (the
//! "Software"), to deal in the Software without restriction, including
//! without limitation the rights to use, copy, modify, merge, publish,
//! distribute, sublicense, and/or sell copies of the Software, and to permit
//! persons to whom the Software is furnished to do so, subject to the
//! following conditions:
//!
//! The above copyright notice and this permission notice shall be included
//! in all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//! OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//! MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
//! NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//! DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
//! OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
//! USE OR OTHER DEALINGS IN THE SOFTWARE.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

/// Protocol V1.
pub const VERSION: u8 = 0x61;

const ID_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 16;

/// A range needing nothing more.
const SKIP: u64 = 0;
const FINGERPRINT: u64 = 1;
const ID_LIST: u64 = 2;

/// How many buckets a range is split into, and below twice as many items,
/// it's listed instead.
const BUCKETS: usize = 16;

/// The timestamp no item may have, which bounds the last range.
const INFINITY: u64 = u64::MAX;

/// What a message can't be read for.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// It ends partway through what it says it holds.
    Truncated,
    /// A number too big for 64 bits.
    Overflow,
    /// A version of another protocol than negentropy's.
    NotNegentropy,
    /// A bound with more of an id than an id has.
    BadBound,
    BadMode(u64),
    /// The relay's answer is in a version it doesn't speak.
    #[cfg(test)]
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("message ends early"),
            Error::Overflow => f.write_str("number too big"),
            Error::NotNegentropy => f.write_str("not a negentropy message"),
            Error::BadBound => f.write_str("bound longer than an id"),
            Error::BadMode(mode) => write!(f, "unknown mode {mode}"),
            #[cfg(test)]
            Error::Unsupported => f.write_str("unsupported protocol version"),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

/// An event, as negentropy sees it. Ordered by timestamp, then id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Item {
    pub timestamp: u64,
    pub id: [u8; ID_LEN],
}

/// A set of items, sorted, without repeats.
pub struct Items(Vec<Item>);

impl Items {
    pub fn new(mut items: Vec<Item>) -> Items {
        items.sort_unstable();
        items.dedup();
        Items(items)
    }
}

/// Where a range ends, short of it: an item, of which only the first
/// `id_len` bytes of the id are sent, the rest taken to be zeros.
#[derive(Clone, Copy, Debug, Default)]
struct Bound {
    item: Item,
    id_len: usize,
}

impl Bound {
    fn at(timestamp: u64) -> Bound {
        Bound {
            item: Item {
                timestamp,
                id: [0; ID_LEN],
            },
            id_len: 0,
        }
    }

    fn of(item: Item) -> Bound {
        Bound {
            item,
            id_len: ID_LEN,
        }
    }

    /// The shortest bound between two neighboring items: after `prev`, up
    /// to and including `next`.
    fn between(prev: &Item, next: &Item) -> Bound {
        if prev.timestamp != next.timestamp {
            return Bound::at(next.timestamp);
        }
        let shared = prev.id.iter().zip(&next.id).take_while(|(a, b)| a == b);
        let id_len = (shared.count() + 1).min(ID_LEN);
        let mut id = [0; ID_LEN];
        id[..id_len].copy_from_slice(&next.id[..id_len]);
        Bound {
            item: Item {
                timestamp: next.timestamp,
                id,
            },
            id_len,
        }
    }
}

/// One side of a sync, answering or asking with a message at a time.
pub struct Negentropy<'a> {
    items: &'a [Item],
    /// The most bytes a message it makes may take, or 0 for no limit.
    frame_limit: usize,
    /// Whether this is the side that started the sync.
    initiator: bool,
    /// Timestamps are sent as the difference from the last one in their
    /// message, each way.
    last_in: u64,
    last_out: u64,
}

impl<'a> Negentropy<'a> {
    /// A frame limit of 0 is none. Any other is at least 4096 bytes, and
    /// is kept to only roughly: within 200 bytes, and a fingerprint.
    pub fn new(items: &'a Items, frame_limit: usize) -> Negentropy<'a> {
        assert!(
            frame_limit == 0 || frame_limit >= 4096,
            "frame limit too small"
        );
        Negentropy {
            items: &items.0,
            frame_limit,
            initiator: false,
            last_in: 0,
            last_out: 0,
        }
    }

    /// The relay's answer to a client's message. A message in another
    /// version of the protocol is answered with only this one's version
    /// byte, which tells the client which it speaks.
    pub fn reconcile(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        self.reconcile_with(msg, &mut Vec::new(), &mut Vec::new())
    }

    /// The client's first message, of every item it has.
    #[cfg(test)]
    pub fn initiate(&mut self) -> Vec<u8> {
        self.initiator = true;
        let mut out = vec![VERSION];
        self.split(0, self.items.len(), Bound::at(INFINITY), &mut out);
        out
    }

    /// The client's next message, if it isn't done, having added to `have`
    /// the ids it has and the relay doesn't, and to `need` the reverse.
    /// With a frame limit, an id can be added again in a later round.
    #[cfg(test)]
    pub fn reconcile_with_ids(
        &mut self,
        msg: &[u8],
        have: &mut Vec<[u8; ID_LEN]>,
        need: &mut Vec<[u8; ID_LEN]>,
    ) -> Result<Option<Vec<u8>>> {
        let out = self.reconcile_with(msg, have, need)?;
        Ok((out.len() > 1).then_some(out))
    }

    fn reconcile_with(
        &mut self,
        mut msg: &[u8],
        have: &mut Vec<[u8; ID_LEN]>,
        need: &mut Vec<[u8; ID_LEN]>,
    ) -> Result<Vec<u8>> {
        self.last_in = 0;
        self.last_out = 0;
        let mut out = vec![VERSION];

        let version = *take(&mut msg, 1)?.first().expect("one byte");
        if !(0x60..=0x6f).contains(&version) {
            return Err(Error::NotNegentropy);
        }
        if version != VERSION {
            #[cfg(test)]
            if self.initiator {
                return Err(Error::Unsupported);
            }
            return Ok(out);
        }

        let mut prev_bound = Bound::default();
        let mut prev_index = 0;
        let mut skip = false;
        while !msg.is_empty() {
            let mut o = Vec::new();
            let bound = self.read_bound(&mut msg)?;
            let lower = prev_index;
            let mut upper = lower + self.items[lower..].partition_point(|item| *item < bound.item);
            match read_varint(&mut msg)? {
                SKIP => skip = true,
                FINGERPRINT => {
                    let theirs = take(&mut msg, FINGERPRINT_LEN)?;
                    if theirs == fingerprint(&self.items[lower..upper]) {
                        skip = true;
                    } else {
                        self.unskip(&mut skip, &prev_bound, &mut o);
                        self.split(lower, upper, bound, &mut o);
                    }
                }
                ID_LIST => {
                    let count = read_varint(&mut msg)?;
                    if count > (msg.len() / ID_LEN) as u64 {
                        return Err(Error::Truncated);
                    }
                    let mut theirs = HashSet::with_capacity(count as usize);
                    for _ in 0..count {
                        let id: [u8; ID_LEN] = take(&mut msg, ID_LEN)?.try_into().expect("an id");
                        theirs.insert(id);
                    }
                    for item in &self.items[lower..upper] {
                        if !theirs.remove(&item.id) && self.initiator {
                            have.push(item.id);
                        }
                    }
                    if self.initiator {
                        skip = true;
                        need.extend(theirs);
                    } else {
                        // Every id of the range, or as many as fit, then
                        // the rest's fingerprint below.
                        self.unskip(&mut skip, &prev_bound, &mut o);
                        let mut ids = Vec::new();
                        let mut end = bound;
                        for (i, item) in self.items[lower..upper].iter().enumerate() {
                            if self.exceeds(out.len() + ids.len()) {
                                end = Bound::of(*item);
                                upper = lower + i;
                                break;
                            }
                            ids.extend(item.id);
                        }
                        self.write_bound(&end, &mut o);
                        write_varint(ID_LIST, &mut o);
                        write_varint((ids.len() / ID_LEN) as u64, &mut o);
                        o.extend(ids);
                        out.append(&mut o);
                    }
                }
                mode => return Err(Error::BadMode(mode)),
            }

            if self.exceeds(out.len() + o.len()) {
                // Out of room: the rest, from here on, as one fingerprint.
                let rest = fingerprint(&self.items[upper..]);
                self.write_bound(&Bound::at(INFINITY), &mut out);
                write_varint(FINGERPRINT, &mut out);
                out.extend(rest);
                break;
            }
            out.append(&mut o);
            prev_index = upper;
            prev_bound = bound;
        }
        Ok(out)
    }

    /// Ranges skipped since the last answered are sent as one skip before
    /// the next that isn't.
    fn unskip(&mut self, skip: &mut bool, prev_bound: &Bound, out: &mut Vec<u8>) {
        if std::mem::take(skip) {
            self.write_bound(prev_bound, out);
            write_varint(SKIP, out);
        }
    }

    /// The items from `lower` to `upper`, which end at `bound`: listed if
    /// they're few, or else split into buckets and fingerprinted.
    fn split(&mut self, lower: usize, upper: usize, bound: Bound, out: &mut Vec<u8>) {
        let items = &self.items[lower..upper];
        if items.len() < 2 * BUCKETS {
            self.write_bound(&bound, out);
            write_varint(ID_LIST, out);
            write_varint(items.len() as u64, out);
            for item in items {
                out.extend(item.id);
            }
            return;
        }
        let (per, extra) = (items.len() / BUCKETS, items.len() % BUCKETS);
        let mut start = 0;
        for i in 0..BUCKETS {
            let end = start + per + usize::from(i < extra);
            let next = match end == items.len() {
                true => bound,
                false => Bound::between(&items[end - 1], &items[end]),
            };
            self.write_bound(&next, out);
            write_varint(FINGERPRINT, out);
            out.extend(fingerprint(&items[start..end]));
            start = end;
        }
    }

    fn exceeds(&self, len: usize) -> bool {
        self.frame_limit != 0 && len > self.frame_limit - 200
    }

    fn read_bound(&mut self, msg: &mut &[u8]) -> Result<Bound> {
        let timestamp = match read_varint(msg)? {
            0 => INFINITY,
            n => (n - 1).saturating_add(self.last_in),
        };
        self.last_in = timestamp;
        let id_len = usize::try_from(read_varint(msg)?).map_err(|_| Error::BadBound)?;
        if id_len > ID_LEN {
            return Err(Error::BadBound);
        }
        let mut id = [0; ID_LEN];
        id[..id_len].copy_from_slice(take(msg, id_len)?);
        Ok(Bound {
            item: Item { timestamp, id },
            id_len,
        })
    }

    fn write_bound(&mut self, bound: &Bound, out: &mut Vec<u8>) {
        let timestamp = bound.item.timestamp;
        match timestamp {
            INFINITY => write_varint(0, out),
            _ => write_varint(timestamp.saturating_sub(self.last_out) + 1, out),
        }
        self.last_out = timestamp;
        write_varint(bound.id_len as u64, out);
        out.extend(&bound.item.id[..bound.id_len]);
    }
}

/// The first `n` bytes of a message, which are then past.
fn take<'m>(msg: &mut &'m [u8], n: usize) -> Result<&'m [u8]> {
    if msg.len() < n {
        return Err(Error::Truncated);
    }
    let (taken, rest) = msg.split_at(n);
    *msg = rest;
    Ok(taken)
}

/// Base 128, most significant digit first, the high bit set on every byte
/// but the last.
fn read_varint(msg: &mut &[u8]) -> Result<u64> {
    let mut n = 0u64;
    loop {
        let byte = take(msg, 1)?[0];
        if n >> 57 != 0 {
            return Err(Error::Overflow);
        }
        n = (n << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok(n);
        }
    }
}

fn write_varint(mut n: u64, out: &mut Vec<u8>) {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = (n & 0x7f) as u8 | if i == digits.len() - 1 { 0 } else { 0x80 };
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    out.extend(&digits[i..]);
}

/// The sum of the items' ids as 256-bit little-endian numbers, wrapping,
/// then their count, hashed, and the first 16 bytes of that.
fn fingerprint(items: &[Item]) -> [u8; FINGERPRINT_LEN] {
    let mut sum = [0u64; 4];
    for item in items {
        let mut carry = false;
        for (lane, bytes) in sum.iter_mut().zip(item.id.as_chunks::<8>().0) {
            let (added, over) = lane.overflowing_add(u64::from_le_bytes(*bytes));
            let (added, over_carry) = added.overflowing_add(u64::from(carry));
            *lane = added;
            carry = over || over_carry;
        }
    }
    let mut hasher = Sha256::new();
    for lane in sum {
        hasher.update(lane.to_le_bytes());
    }
    let mut count = Vec::new();
    write_varint(items.len() as u64, &mut count);
    hasher.update(count);
    hasher.finalize()[..FINGERPRINT_LEN]
        .try_into()
        .expect("a hash is longer")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(i: u64) -> [u8; 32] {
        Sha256::digest(i.to_be_bytes()).into()
    }

    /// What a whole sync came to: the messages both ways, hashed in
    /// order, how many rounds it took, and what the client found it has
    /// and needs, sorted.
    type Synced = ([u8; 32], usize, Vec<[u8; 32]>, Vec<[u8; 32]>);

    /// A whole sync, both sides limited to `frame_limit`.
    fn sync(client: &Items, server: &Items, frame_limit: usize) -> Synced {
        let mut ours = Negentropy::new(client, frame_limit);
        let mut transcript = Sha256::new();
        let mut msg = ours.initiate();
        let (mut have, mut need) = (vec![], vec![]);
        let mut rounds = 0;
        loop {
            transcript.update(&msg);
            let answer = Negentropy::new(server, frame_limit)
                .reconcile(&msg)
                .unwrap();
            transcript.update(&answer);
            rounds += 1;
            match ours
                .reconcile_with_ids(&answer, &mut have, &mut need)
                .unwrap()
            {
                Some(next) => msg = next,
                None => break,
            }
        }
        // A range cut short by the frame limit can be listed again.
        have.sort();
        have.dedup();
        need.sort();
        need.dedup();
        (transcript.finalize().into(), rounds, have, need)
    }

    /// Byte for byte what the `negentropy` crate, 0.5.1, sends.
    #[test]
    fn speaks_as_the_crate_did() {
        let (mut client, mut server) = (vec![], vec![]);
        for i in 0..3000u64 {
            let item = Item {
                timestamp: 1_000 + i / 3,
                id: id(i),
            };
            if i % 5 != 0 {
                server.push(item);
            }
            if i % 7 != 0 {
                client.push(item);
            }
        }
        let (transcript, rounds, have, need) = sync(&Items::new(client), &Items::new(server), 4096);
        assert_eq!(
            hex::encode(transcript),
            "13ea0e468809da2b8ecfcc37c420908b8cfe2a0341b0f331ff90fa596d7cdf5b"
        );
        assert_eq!((rounds, have.len(), need.len()), (29, 514, 343));
    }

    #[test]
    fn finds_what_each_side_lacks() {
        use rand::rngs::StdRng;
        use rand::{RngExt, SeedableRng};
        let mut rng = StdRng::seed_from_u64(77);
        for round in 0..20 {
            let n = rng.random_range(0..5000);
            let (mut client, mut server) = (vec![], vec![]);
            let (mut have_want, mut need_want) = (vec![], vec![]);
            for i in 0..n {
                let item = Item {
                    // Ties, and timestamps far apart.
                    timestamp: rng.random_range(0..[10, 1 << 40][round % 2]),
                    id: id(i),
                };
                match rng.random_range(0..4) {
                    0 => {
                        client.push(item);
                        have_want.push(item.id);
                    }
                    1 => {
                        server.push(item);
                        need_want.push(item.id);
                    }
                    _ => {
                        client.push(item);
                        server.push(item);
                    }
                }
            }
            have_want.sort();
            need_want.sort();
            let (client, server) = (Items::new(client), Items::new(server));
            for frame_limit in [0, 4096, 50_000] {
                let (_, _, have, need) = sync(&client, &server, frame_limit);
                assert_eq!(
                    (&have, &need),
                    (&have_want, &need_want),
                    "{round} {frame_limit}"
                );
            }
        }
    }

    #[test]
    fn refuses_what_isnt_there() {
        let items = Items::new(vec![Item {
            timestamp: 0,
            id: [0xaa; 32],
        }]);
        let answer = |hex: &str| Negentropy::new(&items, 0).reconcile(&hex::decode(hex).unwrap());
        // A list of 2^34 ids with none there, which the crate tried to
        // reserve a terabyte for, then one id short.
        assert_eq!(answer("61000002c080808000"), Err(Error::Truncated));
        assert_eq!(
            answer(&format!("6100000202{}", "bb".repeat(32))),
            Err(Error::Truncated)
        );
        // Numbers that end early or don't fit, and a bound longer than an id.
        assert_eq!(answer("6100"), Err(Error::Truncated));
        assert_eq!(answer("61ff"), Err(Error::Truncated));
        assert_eq!(
            answer(&format!("61{}00", "ff".repeat(10))),
            Err(Error::Overflow)
        );
        assert_eq!(answer("610021"), Err(Error::BadBound));
        assert_eq!(answer("61000005"), Err(Error::BadMode(5)));
        assert_eq!(answer("7f"), Err(Error::NotNegentropy));
        assert_eq!(answer(""), Err(Error::Truncated));
        // Another version is told this one.
        assert_eq!(answer("62"), Ok(vec![VERSION]));
        // A list with every id there is answered.
        assert!(answer(&format!("6100000201{}", "bb".repeat(32))).is_ok());
    }

    #[test]
    fn varints() {
        for (n, bytes) in [
            (0, &[0x00][..]),
            (127, &[0x7f]),
            (128, &[0x81, 0x00]),
            (
                u64::MAX,
                &[0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            ),
        ] {
            let mut out = Vec::new();
            write_varint(n, &mut out);
            assert_eq!(out, bytes);
            assert_eq!(read_varint(&mut &out[..]), Ok(n));
        }
    }

    /// Ids add as 256-bit numbers, carrying from one 64-bit lane to the
    /// next and out of the top.
    #[test]
    fn fingerprints_carry() {
        let item = |id| Item { timestamp: 0, id };
        let mut low = [0; 32];
        low[..16].copy_from_slice(&[0xff; 16]);
        let mut one = [0; 32];
        one[0] = 1;
        let mut carried = [0; 32];
        carried[16] = 1;
        // Same count, same sum, same fingerprint.
        assert_eq!(
            fingerprint(&[item(low), item(one)]),
            fingerprint(&[item(carried), item([0; 32])])
        );
        assert_eq!(
            fingerprint(&[item([0xff; 32]), item(one)]),
            fingerprint(&[item([0; 32]), item([0; 32])])
        );
    }
}
