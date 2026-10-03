//! NIP-42 authentication, and who may read what.
//!
//! Some kinds — DMs, app data, gift wraps — are only for the parties to an
//! event: its author, and the pubkeys it tags. A filter naming one of them
//! must list only authenticated pubkeys as its authors or its `#p`, and a
//! filter naming no kinds doesn't see them at all. Events looked up by id
//! are checked one by one. Master pubkeys may read everything.

use std::collections::HashSet;

use crate::config::Config;
use crate::event::{Event, decode_hex};
use crate::filter::Filter;
use crate::record::{Element, EventView};

/// NIP-42 client authentication.
pub const AUTH: u16 = 22242;

/// How far an AUTH event's `created_at` may be from now, in seconds.
const MAX_AUTH_SKEW: u64 = 600;

/// The pubkeys a connection has authenticated as.
pub type Authed = HashSet<[u8; 32]>;

/// Why a read is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The filter has no authors or `#p` to authenticate as.
    NoParties,
    /// Not every author or `#p` of the filter has authenticated.
    NotAuthed,
    /// Some results are for others.
    Results,
}

impl Refusal {
    /// A NIP-01 machine-readable message, given whether the connection has
    /// authenticated at all.
    pub fn message(self, authed: &Authed) -> &'static str {
        match (self, authed.is_empty()) {
            (Refusal::NoParties, true) => {
                "auth-required: auth-protected kinds require an authors or #p filter"
            }
            (Refusal::NoParties, false) => {
                "restricted: auth-protected kinds require an authors or #p filter"
            }
            (Refusal::NotAuthed, _) => {
                "auth-required: all authors or all #p tags must be authenticated"
            }
            (Refusal::Results, true) => "auth-required: some results require authentication",
            (Refusal::Results, false) => "restricted: some results are not for you",
        }
    }
}

/// Who may read what.
#[derive(Debug, Clone)]
pub struct Access {
    /// Sorted.
    kinds: Vec<u16>,
    /// Sorted.
    author_exempt_kinds: Vec<u16>,
    masters: Vec<[u8; 32]>,
}

impl Access {
    pub fn new(config: &Config) -> Self {
        Self::with(
            &config.auth_kinds,
            &config.auth_author_exempt_kinds,
            &config.master_pubkeys,
        )
    }

    fn with(kinds: &[u16], author_exempt_kinds: &[u16], masters: &[[u8; 32]]) -> Self {
        let sorted = |kinds: &[u16]| {
            let mut kinds = kinds.to_vec();
            kinds.sort_unstable();
            kinds.dedup();
            kinds
        };
        Self {
            kinds: sorted(kinds),
            author_exempt_kinds: sorted(author_exempt_kinds),
            masters: masters.to_vec(),
        }
    }

    /// As configured by default, with `masters`.
    #[cfg(test)]
    pub fn default_with(masters: &[[u8; 32]]) -> Self {
        Self::with(&[4, 78, 1059, 30078], &[1059], masters)
    }

    fn is_auth_kind(&self, kind: u16) -> bool {
        self.kinds.binary_search(&kind).is_ok()
    }

    fn is_master(&self, authed: &Authed) -> bool {
        self.masters.iter().any(|master| authed.contains(master))
    }

    /// Hide auth kinds from a filter that doesn't name its kinds, unless
    /// it looks events up by id, which are checked as they're found.
    pub fn hide(&self, filter: &mut Filter, authed: &Authed) {
        if filter.kinds.is_none() && filter.ids.is_none() && !self.is_master(authed) {
            filter.hidden_kinds = self.kinds.clone();
        }
    }

    /// Whether a filter may be run.
    pub fn check(&self, filter: &Filter, authed: &Authed) -> Result<(), Refusal> {
        let Some(kinds) = &filter.kinds else {
            return Ok(());
        };
        let mut named = kinds.iter().filter(|&&kind| self.is_auth_kind(kind));
        if named.clone().next().is_none() || self.is_master(authed) {
            return Ok(());
        }

        let authors = filter.authors.as_deref().filter(|a| !a.is_empty());
        let exempt = named.all(|kind| self.author_exempt_kinds.binary_search(kind).is_ok());
        if exempt && authors.is_some() {
            return Ok(());
        }
        let p = filter
            .tags
            .iter()
            .find(|(name, _)| name == "p")
            .map(|(_, values)| values.as_slice())
            .filter(|values| !values.is_empty());
        if authors.is_none() && p.is_none() {
            return Err(Refusal::NoParties);
        }
        let authors_authed = authors.is_some_and(|a| a.iter().all(|a| authed.contains(a)));
        let p_authed = p.is_some_and(|values| {
            values.iter().all(|value| {
                // A pubkey, in tag value form.
                value.len() == 33 && value[0] == 1 && authed.contains(&value[1..])
            })
        });
        match authors_authed || p_authed {
            true => Ok(()),
            false => Err(Refusal::NotAuthed),
        }
    }

    /// Whether an event may be sent to a connection.
    pub fn may_see(&self, event: &EventView, authed: &Authed) -> bool {
        !self.is_auth_kind(event.kind())
            || authed.contains(event.pubkey())
            || event.tag_values().any(|(name, value)| match value {
                Element::Hex(pubkey) => name == "p" && authed.contains(pubkey),
                Element::Text(_) => false,
            })
            || self.is_master(authed)
    }
}

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
    use crate::record::encode;
    use crate::store::tests::{MAX_VALUES, test_tags};
    use serde_json::{Value, json};

    const URL: &str = "wss://relay.example.com";

    fn pubkey(seed: u8) -> [u8; 32] {
        decode_hex(&signed(seed, 0, 1, vec![], "").pubkey).unwrap()
    }

    fn hex(seed: u8) -> String {
        hex::encode(pubkey(seed))
    }

    fn authed(seeds: &[u8]) -> Authed {
        seeds.iter().map(|&seed| pubkey(seed)).collect()
    }

    fn parse(filter: Value) -> Filter {
        Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap()
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

    #[test]
    fn checks_filters_for_auth_kinds() {
        let access = Access::default_with(&[pubkey(9)]);
        let check = |filter, seeds: &[u8]| access.check(&parse(filter), &authed(seeds));

        // Kinds anyone may read, or none named.
        assert_eq!(check(json!({"kinds": [1]}), &[]), Ok(()));
        assert_eq!(check(json!({}), &[]), Ok(()));
        // No parties to authenticate as.
        assert_eq!(check(json!({"kinds": [4]}), &[]), Err(Refusal::NoParties));
        assert_eq!(
            check(json!({"kinds": [1, 4]}), &[1]),
            Err(Refusal::NoParties)
        );
        // Every author, or every #p, authenticated.
        assert_eq!(
            check(json!({"kinds": [4], "authors": [hex(1)]}), &[1]),
            Ok(())
        );
        assert_eq!(check(json!({"kinds": [4], "#p": [hex(1)]}), &[1]), Ok(()));
        assert_eq!(
            check(
                json!({"kinds": [4], "authors": [hex(2)], "#p": [hex(1)]}),
                &[1]
            ),
            Ok(())
        );
        assert_eq!(
            check(json!({"kinds": [4], "authors": [hex(1), hex(2)]}), &[1]),
            Err(Refusal::NotAuthed)
        );
        assert_eq!(
            check(json!({"kinds": [4], "#p": [hex(1)]}), &[]),
            Err(Refusal::NotAuthed)
        );
        assert_eq!(
            check(json!({"kinds": [4], "#p": ["not a pubkey"]}), &[1]),
            Err(Refusal::NotAuthed)
        );
        // Gift wraps by their throwaway authors, but not by recipient.
        assert_eq!(
            check(json!({"kinds": [1059], "authors": [hex(2)]}), &[]),
            Ok(())
        );
        assert_eq!(
            check(json!({"kinds": [1059, 4], "authors": [hex(2)]}), &[]),
            Err(Refusal::NotAuthed)
        );
        assert_eq!(
            check(json!({"kinds": [1059], "#p": [hex(2)]}), &[]),
            Err(Refusal::NotAuthed)
        );
        // Masters read anything.
        assert_eq!(check(json!({"kinds": [4]}), &[9]), Ok(()));
    }

    #[test]
    fn hides_auth_kinds_from_filters_not_naming_kinds() {
        let access = Access::default_with(&[pubkey(9)]);
        let hidden = |filter, seeds: &[u8]| {
            let mut filter = parse(filter);
            access.hide(&mut filter, &authed(seeds));
            filter.hidden_kinds
        };
        assert_eq!(hidden(json!({}), &[1]), [4, 78, 1059, 30078]);
        assert_eq!(
            hidden(json!({"authors": [hex(1)]}), &[1]),
            [4, 78, 1059, 30078]
        );
        assert!(hidden(json!({"kinds": [1]}), &[]).is_empty());
        assert!(hidden(json!({"ids": [hex(1)]}), &[]).is_empty());
        assert!(hidden(json!({}), &[9]).is_empty());
    }

    #[test]
    fn shows_auth_kinds_to_their_parties() {
        let access = Access::default_with(&[pubkey(9)]);
        let to_2 = hex(2);
        let dm = encode(&signed(1, 100, 4, vec![vec!["p", &to_2]], ""));
        let dm = EventView::new(&dm).unwrap();
        let note = encode(&signed(1, 100, 1, vec![], ""));
        let note = EventView::new(&note).unwrap();

        assert!(access.may_see(&note, &authed(&[])));
        assert!(!access.may_see(&dm, &authed(&[])));
        assert!(!access.may_see(&dm, &authed(&[3])));
        assert!(access.may_see(&dm, &authed(&[1])));
        assert!(access.may_see(&dm, &authed(&[3, 2])));
        assert!(access.may_see(&dm, &authed(&[9])));
    }
}
