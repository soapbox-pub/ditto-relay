//! NIP-42 authentication, only so an author may publish their own NIP-70
//! protected events. Reads never need it: proving who's on the other end
//! of a connection ties their IP to their pubkey, where a plain query is
//! deniable, since anyone may ask for anything. A connection is only
//! challenged once it publishes a protected event.

use crate::event::{Event, decode_hex};

/// NIP-42 client authentication.
pub const AUTH: u16 = 22242;

/// How far an AUTH event's `created_at` may be from now, in seconds.
const MAX_AUTH_SKEW: u64 = 600;

/// Whether two relay URLs are the same, as far as clients are concerned.
pub fn same_relay(a: &str, b: &str) -> bool {
    let normalize = |url: &str| url.trim().trim_end_matches('/').to_ascii_lowercase();
    normalize(a) == normalize(b)
}

/// Check an AUTH event, for a connection given `challenge` by the relay at
/// `url`. Returns the pubkey authenticated, or a NIP-01 error message.
pub fn verify(ev: &Event, challenge: &str, url: &str, now: u32) -> Result<[u8; 32], String> {
    if ev.kind != AUTH {
        return Err(format!("invalid: AUTH event must be kind {AUTH}"));
    }
    ev.verify()?;
    if ev.created_at.abs_diff(now.into()) > MAX_AUTH_SKEW {
        return Err("invalid: created_at is too far from now".into());
    }
    if ev.tag("challenge") != Some(challenge) {
        return Err("invalid: wrong challenge".into());
    }
    if !ev.tag("relay").is_some_and(|relay| same_relay(relay, url)) {
        return Err("invalid: wrong relay".into());
    }
    Ok(decode_hex(&ev.pubkey).expect("verified"))
}

/// A new challenge for a connection to sign.
pub fn challenge() -> String {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).expect("the OS has randomness");
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;

    const URL: &str = "wss://relay.example.com";

    fn pubkey(seed: u8) -> [u8; 32] {
        decode_hex(&signed(seed, 0, 1, vec![], "").pubkey).unwrap()
    }

    #[test]
    fn verifies_auth_events() {
        let now = 1_700_000_000;
        let auth = |kind, created_at, challenge, relay| {
            let tags = vec![vec!["challenge", challenge], vec!["relay", relay]];
            signed(1, created_at, kind, tags, "")
        };
        let ok = auth(AUTH, now, "abc", "wss://Relay.Example.com/");
        assert_eq!(verify(&ok, "abc", URL, now as u32), Ok(pubkey(1)));
        for (ev, why) in [
            (auth(1, now, "abc", URL), "kind"),
            (auth(AUTH, now - 601, "abc", URL), "created_at"),
            (auth(AUTH, now + 601, "abc", URL), "created_at"),
            (auth(AUTH, now, "xyz", URL), "challenge"),
            (auth(AUTH, now, "abc", "wss://other.example.com"), "relay"),
        ] {
            let err = verify(&ev, "abc", URL, now as u32).unwrap_err();
            assert!(err.starts_with("invalid:"), "{why}: {err}");
        }
        let mut tampered = ok.clone();
        tampered.created_at += 1;
        assert!(verify(&tampered, "abc", URL, now as u32).is_err());
    }
}
