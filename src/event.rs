use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

/// A NIP-01 event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// Storage semantics of a kind, per NIP-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindClass {
    Regular,
    Replaceable,
    Ephemeral,
    Addressable,
}

impl KindClass {
    pub fn of(kind: u16) -> Self {
        match kind {
            0 | 3 | 10000..20000 => Self::Replaceable,
            20000..30000 => Self::Ephemeral,
            30000..40000 => Self::Addressable,
            _ => Self::Regular,
        }
    }
}

/// Kinds of signed artifacts that aren't for publishing to relays on their
/// own. Some look alike but are relayed: NIP-47 and NIP-46 use relays as
/// transport, and 9735 zap receipts and 1059 gift wraps are published.
pub const NOT_RELAYED: [u16; 7] = [
    13,    // NIP-59 seal, only valid inside a gift wrap
    9734,  // NIP-57 zap request, sent to the LNURL callback
    20013, // Concord encrypted seal, only valid inside a gift wrap
    20014, // Concord plaintext seal, only valid inside a gift wrap
    22242, // NIP-42 auth, only in AUTH messages
    24242, // Blossom auth, an HTTP Authorization header
    27235, // NIP-98 HTTP auth, an HTTP Authorization header
];

/// Whether events of a kind are published to relays.
pub fn is_relayed(kind: u16) -> bool {
    !NOT_RELAYED.contains(&kind)
}

impl Event {
    pub fn kind_class(&self) -> KindClass {
        KindClass::of(self.kind)
    }

    /// The first value of the first tag named `name`.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == name)
            .map(|t| t[1].as_str())
    }

    /// The sha256 of the NIP-01 serialization.
    pub fn compute_id(&self) -> [u8; 32] {
        // Hashed as it's serialized, rather than serialized, then hashed.
        // By ring, whose assembly is about twice as quick as the sha2
        // crate's Rust on processors without SHA instructions, and every
        // stored event's id is hashed.
        struct Hashing(ring::digest::Context);
        impl std::io::Write for Hashing {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut hashing = Hashing(ring::digest::Context::new(&ring::digest::SHA256));
        serde_json::to_writer(
            &mut hashing,
            &(
                0,
                &self.pubkey,
                self.created_at,
                self.kind,
                &self.tags,
                &self.content,
            ),
        )
        .expect("event serialization cannot fail");
        hashing.0.finish().as_ref().try_into().expect("32 bytes")
    }

    /// An event signed by `keypair`.
    pub fn sign(
        keypair: &Keypair,
        created_at: u64,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Event {
        let mut ev = Event {
            id: String::new(),
            pubkey: hex::encode(keypair.x_only_public_key().0.to_byte_array()),
            created_at,
            kind,
            tags,
            content,
            sig: String::new(),
        };
        let id = ev.compute_id();
        let mut aux = [0; 32];
        let sig = match getrandom::fill(&mut aux) {
            Ok(()) => secp256k1::schnorr::sign_with_aux_rand(&id, keypair, &aux),
            Err(_) => keypair.sign_schnorr_no_aux_rand(&id),
        };
        ev.id = hex::encode(id);
        ev.sig = hex::encode(sig.to_byte_array());
        ev
    }

    /// Check the id and signature. The returned error is suitable for an `OK` message.
    pub fn verify(&self) -> Result<(), String> {
        self.signed()?.check()
    }

    /// Check everything but the signature itself, as [`verify`](Self::verify)
    /// does, and what checking it takes.
    pub fn signed(&self) -> Result<Signed, String> {
        let id = decode_hex::<32>(&self.id).ok_or("invalid: id must be 64 lowercase hex chars")?;
        let x = decode_hex::<32>(&self.pubkey)
            .ok_or("invalid: pubkey must be 64 lowercase hex chars")?;
        let sig =
            decode_hex::<64>(&self.sig).ok_or("invalid: sig must be 128 lowercase hex chars")?;
        // Stored as a u32, which lasts until 2106.
        if u32::try_from(self.created_at).is_err() {
            return Err("invalid: created_at is out of range".into());
        }

        if self.compute_id() != id {
            return Err("invalid: event id does not match".into());
        }

        let pubkey = parsed(x).ok_or("invalid: bad pubkey")?;
        Ok(Signed { id, x, pubkey, sig })
    }
}

/// An event's id, which matches it, its pubkey, which is one, and its
/// signature, which is to be checked: see [`crate::batch`] for many.
#[derive(Debug, Clone)]
pub struct Signed {
    pub id: [u8; 32],
    /// The pubkey as the event has it.
    pub x: [u8; 32],
    pub pubkey: XOnlyPublicKey,
    pub sig: [u8; 64],
}

impl Signed {
    /// Whether the signature is good, as an `OK` message's error if not.
    pub fn check(&self) -> Result<(), String> {
        Signature::from_byte_array(self.sig)
            .verify(&self.id, &self.pubkey)
            .map_err(|_| "invalid: bad signature".to_string())
    }
}

/// Pubkeys parsed lately, as parsing one finds its point, which takes a
/// tenth of checking a signature, and some sign event after event: the
/// keys of Concord's planes sign most of its gift wraps. Split by the first
/// byte, each part forgotten whole once it's full.
static PARSED: LazyLock<Box<[Parsed]>> =
    LazyLock::new(|| (0..PARSED_SHARDS).map(|_| Mutex::default()).collect());

type Parsed = Mutex<HashMap<[u8; 32], XOnlyPublicKey>>;

const PARSED_SHARDS: usize = 16;
const PARSED_PER_SHARD: usize = 1024;

/// The point of an x-only pubkey, or None if it isn't one.
fn parsed(pubkey: [u8; 32]) -> Option<XOnlyPublicKey> {
    let shard = &PARSED[usize::from(pubkey[0]) % PARSED_SHARDS];
    if let Some(parsed) = shard.lock().expect("unpoisoned").get(&pubkey) {
        return Some(*parsed);
    }
    let parsed = XOnlyPublicKey::from_byte_array(pubkey).ok()?;
    let mut shard = shard.lock().expect("unpoisoned");
    if shard.len() >= PARSED_PER_SHARD {
        shard.clear();
    }
    shard.insert(pubkey, parsed);
    Some(parsed)
}

/// The current Unix time, as event timestamps are stored.
pub fn now() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    u32::try_from(secs).unwrap_or(u32::MAX)
}

/// Decode a lowercase hex string of exactly `N` bytes.
pub fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let (pairs, []) = s.as_bytes().as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    let mut bad = 0;
    for (byte, &[high, low]) in out.iter_mut().zip(pairs) {
        let (high, low) = (LOWER_HEX[usize::from(high)], LOWER_HEX[usize::from(low)]);
        bad |= high | low;
        *byte = high << 4 | low & 0xf;
    }
    (bad & 0xf0 == 0).then_some(out)
}

/// Each byte's value as a lowercase hex digit, or 0xff if it isn't one.
const LOWER_HEX: [u8; 256] = {
    let mut values = [0xff; 256];
    let mut i = 0;
    while i < 10 {
        values[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 6 {
        values[b'a' as usize + i] = 10 + i as u8;
        i += 1;
    }
    values
};

/// Hex digits, of either case, as the bytes they spell, if they do.
pub fn decode_hex_vec(s: &str) -> Option<Vec<u8>> {
    const BAD: u8 = 0xff;
    const VALUES: [u8; 256] = {
        let mut values = [BAD; 256];
        let mut i = 0;
        while i < 10 {
            values[b'0' as usize + i] = i as u8;
            i += 1;
        }
        let mut i = 0;
        while i < 6 {
            values[b'a' as usize + i] = 10 + i as u8;
            values[b'A' as usize + i] = 10 + i as u8;
            i += 1;
        }
        values
    };
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(pairs.len());
    let mut bad = 0;
    for &[high, low] in pairs {
        let (high, low) = (VALUES[usize::from(high)], VALUES[usize::from(low)]);
        bad |= high | low;
        out.push(high << 4 | low & 0xf);
    }
    (bad & 0xf0 == 0).then_some(out)
}

/// Whether `s` is exactly 64 lowercase hex digits: an id or a pubkey.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && is_lower_hex(s)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use secp256k1::Keypair;

    #[test]
    fn decodes_hex_as_the_hex_crate_does() {
        for s in [
            "",
            "00",
            "0aFf",
            "abc",
            "zz",
            "0g",
            "ÿÿ",
            "0123456789abcdefABCDEF",
        ] {
            assert_eq!(decode_hex_vec(s), hex::decode(s).ok(), "{s:?}");
        }
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(decode_hex_vec(&hex::encode(&bytes)), Some(bytes.clone()));
        assert_eq!(
            decode_hex_vec(&hex::encode_upper(&bytes)),
            Some(bytes.clone())
        );
        // Fixed lengths are lowercase only, as ids, pubkeys and sigs are.
        assert_eq!(decode_hex::<2>("0aff"), Some([0x0a, 0xff]));
        for s in ["0AFF", "0aff00", "0af", "0agf", "", "ÿÿ"] {
            assert_eq!(decode_hex::<2>(s), None, "{s:?}");
        }
        let encoded = hex::encode(&bytes[..32]);
        assert_eq!(
            decode_hex::<32>(&encoded).map(|b| b.to_vec()),
            Some(bytes[..32].to_vec())
        );
    }

    /// Build a signed event with a deterministic key derived from `seed`.
    pub fn signed(
        seed: u8,
        created_at: u64,
        kind: u16,
        tags: Vec<Vec<&str>>,
        content: &str,
    ) -> Event {
        let tags = tags
            .into_iter()
            .map(|t| t.into_iter().map(String::from).collect())
            .collect();
        sign([seed.max(1); 32], created_at, kind, tags, content)
    }

    /// Build an event signed by `secret`.
    pub fn sign(
        secret: [u8; 32],
        created_at: u64,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> Event {
        let keypair = Keypair::from_secret_bytes(secret).unwrap();
        Event::sign(&keypair, created_at, kind, tags, content.into())
    }

    /// A typical feed of `n` events from 500 people: notes, replies, and
    /// reactions, mentioning each other. Deterministic.
    pub fn feed(n: u32) -> Vec<Event> {
        use rand::rngs::StdRng;
        use rand::{RngExt, SeedableRng};

        let mut rng = StdRng::seed_from_u64(1);
        let secrets: Vec<[u8; 32]> = (1..=500u32)
            .map(|n| {
                let mut secret = [0; 32];
                secret[28..].copy_from_slice(&n.to_be_bytes());
                secret
            })
            .collect();
        let people: Vec<String> = secrets
            .iter()
            .map(|s| sign(*s, 0, 0, vec![], "").pubkey)
            .collect();
        let mut events: Vec<Event> = Vec::new();
        for i in 0..n {
            let mut tags = Vec::new();
            let kind = if i % 3 == 0 && !events.is_empty() {
                7
            } else {
                1
            };
            if !events.is_empty() && (kind == 7 || rng.random_bool(0.4)) {
                let target = &events[rng.random_range(0..events.len())];
                tags.push(vec!["e".into(), target.id.clone()]);
            }
            for _ in 0..rng.random_range(0..3) {
                tags.push(vec![
                    "p".into(),
                    people[rng.random_range(0..people.len())].clone(),
                ]);
            }
            let content: String = if kind == 7 {
                "+".into()
            } else {
                (0..rng.random_range(20..280))
                    .map(|_| rng.random_range('a'..='z'))
                    .collect()
            };
            let secret = secrets[rng.random_range(0..secrets.len())];
            events.push(sign(
                secret,
                1_700_000_000 + u64::from(i),
                kind,
                tags,
                &content,
            ));
        }
        events
    }

    #[test]
    fn verifies_signed_event() {
        let ev = signed(
            1,
            1700000000,
            1,
            vec![vec!["t", "nostr"]],
            "hello\n\"world\"",
        );
        assert_eq!(ev.verify(), Ok(()));
    }

    /// A pubkey parsed before checks signatures as one parsed anew; one
    /// that isn't a point is refused every time.
    #[test]
    fn checks_alike_with_pubkeys_parsed_before() {
        let ev = signed(1, 1700000000, 1, vec![], "hello");
        assert_eq!(ev.verify(), Ok(()));
        assert_eq!(ev.verify(), Ok(()));
        let mut forged = signed(1, 1700000001, 1, vec![], "hello");
        forged.sig = ev.sig.clone();
        assert_eq!(forged.verify(), Err("invalid: bad signature".into()));

        let x = (1..=255u8)
            .map(|b| {
                let mut x = [0; 32];
                x[31] = b;
                x
            })
            .find(|x| XOnlyPublicKey::from_byte_array(*x).is_err())
            .unwrap();
        let mut off = ev.clone();
        off.pubkey = hex::encode(x);
        off.id = hex::encode(off.compute_id());
        for _ in 0..2 {
            assert_eq!(off.verify(), Err("invalid: bad pubkey".into()));
        }
    }

    #[test]
    fn rejects_tampered_event() {
        let mut ev = signed(1, 1700000000, 1, vec![], "hello");
        ev.content = "goodbye".into();
        assert_eq!(ev.verify(), Err("invalid: event id does not match".into()));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let mut ev = signed(1, 1700000000, 1, vec![], "hello");
        ev.id = ev.id.to_uppercase();
        assert!(ev.verify().is_err());
    }

    #[test]
    fn kind_classes() {
        assert_eq!(KindClass::of(1), KindClass::Regular);
        assert_eq!(KindClass::of(0), KindClass::Replaceable);
        assert_eq!(KindClass::of(10002), KindClass::Replaceable);
        assert_eq!(KindClass::of(20001), KindClass::Ephemeral);
        assert_eq!(KindClass::of(30023), KindClass::Addressable);
        assert_eq!(KindClass::of(40000), KindClass::Regular);
    }

    #[test]
    fn relayed_kinds() {
        for kind in [0, 1, 1059, 9735, 23194, 24133] {
            assert!(is_relayed(kind), "{kind}");
        }
        for kind in [13, 9734, 20013, 20014, 22242, 24242, 27235] {
            assert!(!is_relayed(kind), "{kind}");
        }
    }
}
