use std::time::{SystemTime, UNIX_EPOCH};

use secp256k1::XOnlyPublicKey;
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
        let serialized = serde_json::to_vec(&(
            0,
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ))
        .expect("event serialization cannot fail");
        Sha256::digest(&serialized).into()
    }

    /// Check the id and signature. The returned error is suitable for an `OK` message.
    pub fn verify(&self) -> Result<(), String> {
        let id = decode_hex::<32>(&self.id).ok_or("invalid: id must be 64 lowercase hex chars")?;
        let pubkey = decode_hex::<32>(&self.pubkey)
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

        let pubkey = XOnlyPublicKey::from_byte_array(pubkey)
            .map_err(|_| "invalid: bad pubkey".to_string())?;
        Signature::from_byte_array(sig)
            .verify(&id, &pubkey)
            .map_err(|_| "invalid: bad signature".to_string())
    }
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
    if s.len() != N * 2 || !is_lower_hex(s) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
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
        let mut ev = Event {
            id: String::new(),
            pubkey: hex::encode(keypair.x_only_public_key().0.to_byte_array()),
            created_at,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        let id = ev.compute_id();
        ev.id = hex::encode(id);
        ev.sig = hex::encode(keypair.sign_schnorr_no_aux_rand(&id).to_byte_array());
        ev
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
