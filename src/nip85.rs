//! NIP-85 trusted assertions, made when asked for rather than kept.
//!
//! A filter for kinds 30382 to 30385 by the relay's own key, naming `d`
//! tags, gets an assertion for each: counted from the indexes as it's
//! asked, signed, and dated now. Nothing is stored, so nothing goes stale
//! and nothing is recomputed in the background.
//!
//! The counts are raw, trust aside, and nearly all are LMDB's counts of a
//! tag key's stamps: a tag key is per kind, so how many kind 7s tag `#e`
//! with an id is one lookup. Notes tagging an event count as comments on it
//! whether they reply or mention. Only zaps need more than the indexes: what
//! each receipt is for and how much it paid are in its zap request, so they
//! are [tallied](crate::rank::zaps) as they arrive.
//!
//! | kind  | `d`                  | counts                                       |
//! |-------|----------------------|----------------------------------------------|
//! | 30382 | pubkey               | followers, trust, posts                      |
//! | 30383 | event id             | comments, quotes, reposts, reactions, zaps   |
//! | 30384 | `kind:pubkey:d`      | the same, by `a` tags                        |
//! | 30385 | NIP-73 identifier    | comments, reactions, reposts, by `i` and `I` |
//!
//! With a [web of trust](crate::wot), a user's `rank` is their weight in it
//! out of 100, and at least 1 if they have any: what their engagement
//! counts for, so 100 for
//! anyone trusted as much as one of the `full_trust` most trusted people,
//! and 0 for anyone trusted less than the least weight counted. Unlike a
//! count, a rank of 0 says something, so it's kept.
//!
//! A count of 0 is left out, and an assertion with nothing in it isn't made.

use secp256k1::Keypair;

use crate::event::{Event, is_hex64};
use crate::filter::Filter;
use crate::lmdb::{Db, Result, Txn};
use crate::rank::{self, Zapped};
use crate::record::{self, EventView};
use crate::store::{Store, tag_key};

const USER: u16 = 30382;
const EVENT: u16 = 30383;
const ADDRESS: u16 = 30384;
const IDENTIFIER: u16 = 30385;

/// The assertions a filter asks the relay for, at most `limit`, dated
/// `created_at`, as their ids and JSON.
pub fn run(
    store: &Store,
    txn: &Txn,
    keypair: &Keypair,
    filter: &Filter,
    limit: usize,
    created_at: u32,
) -> Result<Vec<([u8; 32], String)>> {
    let pubkey = keypair.x_only_public_key().0.to_byte_array();
    let mut out = Vec::new();
    if filter.never || filter.ids.is_some() || filter.search.is_some() {
        return Ok(out);
    }
    let (Some(authors), Some(kinds)) = (&filter.authors, &filter.kinds) else {
        return Ok(out);
    };
    if authors.binary_search(&pubkey).is_err() {
        return Ok(out);
    }
    let Some((_, ds)) = filter.tags.iter().find(|(name, _)| name == "d") else {
        return Ok(out);
    };
    if !filter.matches_time(created_at) {
        return Ok(out);
    }
    for &kind in kinds.iter().filter(|&&k| (USER..=IDENTIFIER).contains(&k)) {
        for d in ds {
            if out.len() >= limit {
                return Ok(out);
            }
            let Some(text) = d_text(d) else {
                continue;
            };
            let stats = match kind {
                USER => user(store, txn, d)?,
                EVENT => event(store, txn, d)?,
                ADDRESS => address(store, txn, d, &text)?,
                _ => identifier(store, txn, d)?,
            };
            let stats: Vec<_> = stats
                .into_iter()
                .filter(|&(name, n)| n > 0 || name == "rank")
                .collect();
            if stats.is_empty() {
                continue;
            }
            let mut tags = vec![vec!["d".to_string(), text]];
            tags.extend(
                stats
                    .into_iter()
                    .map(|(name, n)| vec![name.to_string(), n.to_string()]),
            );
            let event = Event::sign(keypair, created_at.into(), kind, tags, String::new());
            let record = record::encode(&event);
            let view = EventView::new(&record).expect("an encoded record");
            if filter.matches(&view) {
                out.push((*view.id(), view.to_json()));
            }
        }
    }
    Ok(out)
}

/// A `d` value, in [`record::tag_value`] form, as text.
fn d_text(value: &[u8]) -> Option<String> {
    let text = record::tag_value_element(value)?.to_text();
    (!text.is_empty()).then(|| text.into_owned())
}

/// Whether a `d` value is an id or a pubkey.
fn is_hex(value: &[u8]) -> bool {
    value.first() == Some(&1)
}

type Stats = Vec<(&'static str, u64)>;

fn user(store: &Store, txn: &Txn, pubkey: &[u8]) -> Result<Stats> {
    if !is_hex(pubkey) {
        return Ok(Vec::new());
    }
    let key: &[u8; 32] = pubkey[1..].try_into().unwrap();
    let posts = [key, &1u16.to_be_bytes()[..]].concat();
    let mut stats = vec![("followers", tagged(store, txn, "p", pubkey, &[3])?)];
    if let Some(wot) = store.wot() {
        let weight = f64::from(wot.weight(store, txn, key)?);
        let trust = ((weight * 100.0).round() as u64).max(u64::from(weight > 0.0));
        stats.push(("rank", trust));
    }
    stats.push(("post_cnt", count(txn, store.tables.author_kinds, &posts)?));
    Ok(stats)
}

fn event(store: &Store, txn: &Txn, id: &[u8]) -> Result<Stats> {
    if !is_hex(id) {
        return Ok(Vec::new());
    }
    let zapped = Zapped::Event(id[1..].try_into().unwrap());
    engagement(store, txn, "e", id, zapped)
}

fn address(store: &Store, txn: &Txn, value: &[u8], text: &str) -> Result<Stats> {
    let mut parts = text.splitn(3, ':');
    let (Some(kind), Some(pubkey), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(Vec::new());
    };
    if kind.parse::<u16>().is_err() || !is_hex64(pubkey) {
        return Ok(Vec::new());
    }
    engagement(store, txn, "a", value, Zapped::Address(text))
}

/// What's engaged with an event or address that tags name by `tag`.
fn engagement(store: &Store, txn: &Txn, tag: &str, value: &[u8], zapped: Zapped) -> Result<Stats> {
    let (zaps, msats) = rank::zaps(store, txn, zapped)?;
    Ok(vec![
        ("comment_cnt", tagged(store, txn, tag, value, &[1, 1111])?),
        ("quote_cnt", tagged(store, txn, "q", value, &[1])?),
        ("repost_cnt", tagged(store, txn, tag, value, &[6, 16])?),
        ("reaction_cnt", tagged(store, txn, tag, value, &[7])?),
        ("zap_cnt", zaps),
        (
            "zap_amount",
            u64::try_from(msats / 1000).unwrap_or(u64::MAX),
        ),
    ])
}

/// NIP-22 comments name what they're on, at the root, by `I`; notes,
/// reactions, and reposts by `i`.
fn identifier(store: &Store, txn: &Txn, value: &[u8]) -> Result<Stats> {
    Ok(vec![
        (
            "comment_cnt",
            tagged(store, txn, "I", value, &[1111])? + tagged(store, txn, "i", value, &[1])?,
        ),
        ("reaction_cnt", tagged(store, txn, "i", value, &[7, 17])?),
        ("repost_cnt", tagged(store, txn, "i", value, &[16])?),
    ])
}

/// How many events of `kinds` have a `name` tag of `value`.
pub fn tagged(store: &Store, txn: &Txn, name: &str, value: &[u8], kinds: &[u16]) -> Result<u64> {
    let mut total = 0;
    for &kind in kinds {
        total += count(txn, store.tables.tags, &tag_key(name, value, Some(kind)))?;
    }
    Ok(total)
}

/// How many stamps an index has under a key.
fn count(txn: &Txn, db: Db, key: &[u8]) -> Result<u64> {
    let mut cursor = txn.cursor(db)?;
    Ok(match cursor.set(key)? {
        Some(_) => cursor.count()? as u64,
        None => 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::store::tests::{MAX_VALUES, open, put};
    use serde_json::{Value, json};

    /// The relay's key.
    fn relay() -> Keypair {
        Keypair::from_secret_bytes([42; 32]).unwrap()
    }

    fn relay_pubkey() -> String {
        hex::encode(relay().x_only_public_key().0.to_byte_array())
    }

    /// The assertions a filter gets, each checked.
    fn ask(store: &Store, filter: Value) -> Vec<Event> {
        let filter = Filter::parse(&filter, &store.indexed_tags, MAX_VALUES).unwrap();
        let results = crate::query::run(
            store,
            None,
            Some(&relay()),
            &[filter],
            100,
            500,
            &Default::default(),
        )
        .unwrap();
        results
            .events
            .iter()
            .map(|json| {
                let event: Event = serde_json::from_str(json).unwrap();
                assert_eq!(event.verify(), Ok(()));
                assert_eq!(event.pubkey, relay_pubkey());
                event
            })
            .collect()
    }

    /// The one assertion a filter gets, as its tags, `d` aside.
    fn stats(store: &Store, kind: u16, d: &str) -> Vec<(String, String)> {
        let found = ask(
            store,
            json!({"kinds": [kind], "authors": [relay_pubkey()], "#d": [d]}),
        );
        match found.as_slice() {
            [] => Vec::new(),
            [event] => {
                assert_eq!(event.kind, kind);
                assert_eq!(event.tags[0], ["d", d]);
                let tags = event.tags[1..].iter();
                tags.map(|t| (t[0].clone(), t[1].clone())).collect()
            }
            _ => panic!("more than one assertion: {found:?}"),
        }
    }

    fn of(pairs: &[(&str, u64)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, n)| (name.to_string(), n.to_string()))
            .collect()
    }

    /// Who signs zap receipts.
    const WALLET: u8 = 99;

    /// A receipt for `seed` zapping what `tags` name, `msats` (a multiple
    /// of 100).
    fn zap(seed: u8, at: u64, tags: Vec<Vec<&str>>, msats: u64) -> Event {
        let request = signed(seed, at, 9734, tags.clone(), "");
        let invoice = format!("lnbc{}n1pfake", msats / 100);
        let description = serde_json::to_string(&request).unwrap();
        let mut tags = tags;
        tags.extend([vec!["bolt11", &invoice], vec!["description", &description]]);
        signed(WALLET, at, 9735, tags, "")
    }

    #[test]
    fn counts_followers_and_posts() {
        let (_dir, store) = open();
        let alice = signed(1, 100, 1, vec![], "hi");
        let pk = alice.pubkey.clone();
        put(&store, &alice);
        put(&store, &signed(1, 101, 1, vec![], "again"));
        put(&store, &signed(1, 102, 7, vec![], "+"));
        assert_eq!(stats(&store, USER, &pk), of(&[("post_cnt", 2)]));

        put(&store, &signed(2, 100, 3, vec![vec!["p", &pk]], ""));
        put(&store, &signed(3, 100, 3, vec![vec!["p", &pk]], ""));
        assert_eq!(
            stats(&store, USER, &pk),
            of(&[("followers", 2), ("post_cnt", 2)])
        );

        // An unfollow replaces the list that followed.
        put(&store, &signed(3, 200, 3, vec![], ""));
        assert_eq!(
            stats(&store, USER, &pk),
            of(&[("followers", 1), ("post_cnt", 2)])
        );
    }

    #[test]
    fn ranks_users_by_trust() {
        use crate::rank::Rank;
        use crate::store::History;
        use crate::store::tests::test_tags;
        use crate::wot::Wot;

        let pubkey = |seed| signed(seed, 0, 0, vec![], "").pubkey;
        let seed: [u8; 32] = hex::decode(pubkey(1)).unwrap().try_into().unwrap();
        // One person's worth of trust weighs fully, so few have it all.
        let wot = Wot::new(vec![seed], 0.85, 1, 0.01, 10_000).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(true, vec![], 20);
        let store = Store::open(
            dir.path(),
            1 << 26,
            true,
            test_tags(),
            history,
            Some(wot),
            Rank::default(),
        )
        .unwrap();
        put(&store, &signed(1, 100, 3, vec![vec!["p", &pubkey(2)]], ""));
        while store.turn().unwrap() {}

        let rank = |seed| {
            let found = stats(&store, USER, &pubkey(seed));
            let rank = found.iter().find(|(name, _)| name == "rank").unwrap();
            rank.1.parse::<u64>().unwrap()
        };
        assert_eq!(rank(1), 100);
        // The seed's follow has some of its trust, not all.
        let followed = rank(2);
        assert!(0 < followed && followed < 100, "{followed}");
        // Nobody trusts a stranger, and the assertion says so.
        assert_eq!(stats(&store, USER, &pubkey(3)), of(&[("rank", 0)]));
    }

    #[test]
    fn counts_engagement_with_an_event() {
        let (_dir, store) = open();
        let note = signed(1, 100, 1, vec![], "hi");
        let (id, author) = (note.id.as_str(), note.pubkey.as_str());
        put(&store, &note);
        put(&store, &signed(2, 101, 1, vec![vec!["e", id]], "reply"));
        put(
            &store,
            &signed(3, 101, 1111, vec![vec!["e", id]], "comment"),
        );
        put(&store, &signed(4, 101, 1, vec![vec!["q", id]], "quote"));
        put(&store, &signed(5, 101, 6, vec![vec!["e", id]], ""));
        put(&store, &signed(6, 101, 16, vec![vec!["e", id]], ""));
        put(&store, &signed(7, 101, 7, vec![vec!["e", id]], "+"));
        let first = zap(8, 102, vec![vec!["e", id], vec!["p", author]], 21_000);
        put(&store, &first);
        put(
            &store,
            &zap(9, 103, vec![vec!["e", id], vec!["p", author]], 5_000),
        );
        // Paying yourself is free.
        put(
            &store,
            &zap(1, 104, vec![vec!["e", id], vec!["p", author]], 1_000_000),
        );
        assert_eq!(
            stats(&store, EVENT, id),
            of(&[
                ("comment_cnt", 2),
                ("quote_cnt", 1),
                ("repost_cnt", 2),
                ("reaction_cnt", 1),
                ("zap_cnt", 2),
                ("zap_amount", 26),
            ])
        );

        // A deleted receipt is taken back.
        put(
            &store,
            &signed(WALLET, 105, 5, vec![vec!["e", &first.id]], ""),
        );
        let found = stats(&store, EVENT, id);
        assert!(found.contains(&("zap_cnt".into(), "1".into())), "{found:?}");
        assert!(
            found.contains(&("zap_amount".into(), "5".into())),
            "{found:?}"
        );
    }

    #[test]
    fn counts_engagement_with_an_address() {
        let (_dir, store) = open();
        let article = signed(1, 100, 30023, vec![vec!["d", "post"]], "words");
        let addr = format!("30023:{}:post", article.pubkey);
        let author = article.pubkey.as_str();
        put(&store, &article);
        put(
            &store,
            &signed(2, 101, 1111, vec![vec!["a", &addr]], "comment"),
        );
        put(&store, &signed(3, 101, 7, vec![vec!["a", &addr]], "+"));
        put(&store, &signed(4, 101, 16, vec![vec!["a", &addr]], ""));
        put(
            &store,
            &zap(5, 102, vec![vec!["a", &addr], vec!["p", author]], 3_000),
        );
        assert_eq!(
            stats(&store, ADDRESS, &addr),
            of(&[
                ("comment_cnt", 1),
                ("repost_cnt", 1),
                ("reaction_cnt", 1),
                ("zap_cnt", 1),
                ("zap_amount", 3),
            ])
        );
        assert_eq!(stats(&store, ADDRESS, "30023:nope:post"), of(&[]));
    }

    #[test]
    fn counts_engagement_with_an_identifier() {
        let (_dir, store) = open();
        let url = "https://example.com/";
        put(
            &store,
            &signed(1, 100, 1111, vec![vec!["I", url], vec!["i", url]], "c"),
        );
        put(&store, &signed(2, 100, 1, vec![vec!["i", url]], "note"));
        put(&store, &signed(3, 100, 17, vec![vec!["i", url]], "+"));
        put(&store, &signed(4, 100, 16, vec![vec!["i", url]], ""));
        assert_eq!(
            stats(&store, IDENTIFIER, url),
            of(&[("comment_cnt", 2), ("reaction_cnt", 1), ("repost_cnt", 1)])
        );
    }

    #[test]
    fn asserts_only_what_is_asked_of_it() {
        let (_dir, store) = open();
        let notes: Vec<Event> = (1..=3).map(|n| signed(n, 100, 1, vec![], "hi")).collect();
        for note in &notes {
            put(&store, note);
            put(&store, &signed(9, 101, 7, vec![vec!["e", &note.id]], "+"));
        }
        let ids: Vec<&str> = notes.iter().map(|n| n.id.as_str()).collect();
        let me = relay_pubkey();

        let found = ask(
            &store,
            json!({"kinds": [EVENT], "authors": [me], "#d": ids}),
        );
        assert_eq!(found.len(), 3);
        let limited = json!({"kinds": [EVENT], "authors": [me], "#d": ids, "limit": 2});
        assert_eq!(ask(&store, limited).len(), 2);

        // Nothing to say, or nothing it can.
        let unknown = "f".repeat(64);
        assert!(stats(&store, EVENT, &unknown).is_empty());
        assert!(stats(&store, EVENT, "not an id").is_empty());
        // Not of it, not dated then, or not named.
        let other = signed(5, 0, 0, vec![], "").pubkey;
        assert!(
            ask(
                &store,
                json!({"kinds": [EVENT], "authors": [other], "#d": ids})
            )
            .is_empty()
        );
        let past = json!({"kinds": [EVENT], "authors": [me], "#d": ids, "until": 1000});
        assert!(ask(&store, past).is_empty());
        assert!(ask(&store, json!({"kinds": [EVENT], "authors": [me]})).is_empty());
        // Other tags still have to match.
        let tagged = json!({"kinds": [EVENT], "authors": [me], "#d": ids, "#t": ["x"]});
        assert!(ask(&store, tagged).is_empty());
        // Two filters asking the same get it once.
        let filter = json!({"kinds": [EVENT], "authors": [me], "#d": [ids[0]]});
        let filters: Vec<Filter> = [&filter, &filter]
            .iter()
            .map(|f| Filter::parse(f, &store.indexed_tags, MAX_VALUES).unwrap())
            .collect();
        let results = crate::query::run(
            &store,
            None,
            Some(&relay()),
            &filters,
            100,
            500,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(results.events.len(), 1);
    }
}
