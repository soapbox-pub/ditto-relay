//! Trends, labeled as Ditto reads them: every so often, a NIP-32 kind 1985
//! label by the relay's own key for each of what's trending, under the
//! `pub.ditto.trends` namespace, listing it best first.
//!
//! | `l`  | rows                                    | from                     |
//! |------|-----------------------------------------|--------------------------|
//! | `#t` | `["t", hashtag, "", authors, uses]`     | the past day's notes     |
//! | `#e` | `["e", id, relay URL, engagers, uses]`  | [`sort:hot`](crate::rank) |
//!
//! Hashtags are counted in one walk over the past day of notes, each
//! author once per hashtag, at their weight in the [web of
//! trust](crate::wot): a hashtag trends by how trusted, not how many, its
//! users are. The rows say how many authors used it, and how often.
//!
//! Posts are the best of `sort:hot`, which is kept as engagement arrives,
//! so they cost a few reads: weighted by trust the same way, with negative
//! reactions left out and zaps counted for their senders. A row's engagers
//! are its score in whole engagers, and its uses everything tagging it.
//!
//! Bridged events are left out of both, as Ditto's own feeds leave them
//! out. Labels are regular events, kept so that Ditto can chart a
//! hashtag's past week from them, and expire after a while.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use secp256k1::Keypair;
use serde_json::json;

use crate::event::{self, Event};
use crate::facets;
use crate::filter::Filter;
use crate::lmdb::Txn;
use crate::nip85::tagged;
use crate::rank;
use crate::relay::AppState;
use crate::store::{MAX_INDEXED_TAG, Store, each_stamp, stamp_seq};

const LABEL: u16 = 1985;
const NAMESPACE: &str = "pub.ditto.trends";

/// How far back hashtags are counted, in seconds.
const WINDOW: u32 = 86_400;
/// The kinds whose hashtags are counted.
const HASHTAG_KINDS: &[u16] = &[1];
/// How many of each are labeled.
const HASHTAGS: usize = 20;
const POSTS: usize = 40;

/// Something trending.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub value: String,
    /// What it's ranked by: its users' weights, summed.
    pub weight: f64,
    pub authors: u64,
    pub uses: u64,
}

/// A hashtag's users so far.
#[derive(Default)]
struct Tally {
    authors: HashSet<[u8; 32]>,
    weight: f64,
    uses: u64,
}

/// The hashtags most used, by trust, from a day before `now` to `now`.
pub fn hashtags(store: &Store, txn: &Txn, now: u32) -> anyhow::Result<Vec<Row>> {
    let mut weights: HashMap<[u8; 32], f64> = HashMap::new();
    let mut tallies: HashMap<String, Tally> = HashMap::new();
    let mut tally = |seq| -> anyhow::Result<()> {
        let Some(view) = store.load(txn, seq)? else {
            return Ok(());
        };
        let mut tags: Vec<String> = view
            .tag_values()
            .filter_map(|(name, value)| match (name, value) {
                ("t", value) => Some(value.to_text().to_lowercase()),
                _ => None,
            })
            .filter(|tag| !tag.is_empty() && tag.len() <= MAX_INDEXED_TAG)
            .collect();
        // Most notes have none, so that's asked first.
        if tags.is_empty() || facets::protocol(&view).is_some() {
            return Ok(());
        }
        let author = *view.pubkey();
        let weight = match weights.get(&author) {
            Some(&weight) => weight,
            None => {
                let weight = match store.wot() {
                    Some(wot) => f64::from(wot.weight(store, txn, &author)?),
                    None => 1.0,
                };
                *weights.entry(author).or_insert(weight)
            }
        };
        if weight <= 0.0 {
            return Ok(());
        }
        tags.sort_unstable();
        tags.dedup();
        for tag in tags {
            let tally = tallies.entry(tag).or_default();
            tally.uses += 1;
            if tally.authors.insert(author) {
                tally.weight += weight;
            }
        }
        Ok(())
    };
    let since = now.saturating_sub(WINDOW);
    let mut failed = None;
    for kind in HASHTAG_KINDS {
        each_stamp(
            txn,
            store.tables.kinds,
            &kind.to_be_bytes(),
            since,
            now,
            |stamp| match tally(stamp_seq(stamp)) {
                Ok(()) => true,
                Err(err) => {
                    failed = Some(err);
                    false
                }
            },
        )?;
        if let Some(err) = failed.take() {
            return Err(err);
        }
    }
    let mut rows: Vec<Row> = tallies
        .into_iter()
        .map(|(value, tally)| Row {
            value,
            weight: tally.weight,
            authors: tally.authors.len() as u64,
            uses: tally.uses,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.weight
            .total_cmp(&a.weight)
            .then(b.uses.cmp(&a.uses))
            .then_with(|| a.value.cmp(&b.value))
    });
    rows.truncate(HASHTAGS);
    Ok(rows)
}

/// The hottest notes anyone has engaged with, each author's best.
pub fn posts(store: &Store, txn: &Txn) -> anyhow::Result<Vec<Row>> {
    let filter = json!({
        "kinds": [1],
        "search": "sort:hot protocol:nostr distinct:author",
        "limit": POSTS,
    });
    let filter = Filter::parse(&filter, &store.indexed_tags, POSTS).map_err(anyhow::Error::msg)?;
    let mut rows = Vec::new();
    // Too few ranked are made up with the newest, which aren't trending.
    for (_, view) in rank::run(store, txn, &filter, POSTS, &Default::default())? {
        let id = view.id();
        let weight = rank::score(store, txn, id)?;
        if weight <= 0.0 {
            continue;
        }
        let value = [&[1], &id[..]].concat();
        let uses = tagged(store, txn, "e", &value, &[1, 6, 7, 16, 1111])?
            + tagged(store, txn, "q", &value, &[1])?;
        rows.push(Row {
            value: hex::encode(id),
            weight,
            authors: (weight.round() as u64).max(1),
            uses,
        });
    }
    Ok(rows)
}

/// A label of `rows` as `l`, each a `name` tag with `extra` after its
/// value, dated `created_at` and, unless `expiration` is 0, expiring that
/// many seconds later.
pub fn label(
    keypair: &Keypair,
    l: &str,
    name: &str,
    extra: &str,
    rows: &[Row],
    created_at: u32,
    expiration: u32,
) -> Event {
    let mut tags = vec![
        vec!["L".to_string(), NAMESPACE.to_string()],
        vec!["l".to_string(), l.to_string(), NAMESPACE.to_string()],
    ];
    tags.extend(rows.iter().map(|row| {
        vec![
            name.to_string(),
            row.value.clone(),
            extra.to_string(),
            row.authors.to_string(),
            row.uses.to_string(),
        ]
    }));
    if expiration > 0 {
        let at = created_at.saturating_add(expiration);
        tags.push(vec!["expiration".to_string(), at.to_string()]);
    }
    Event::sign(keypair, created_at.into(), LABEL, tags, String::new())
}

/// Every label of what's trending at `now` that has anything in it.
pub fn labels(
    store: &Store,
    keypair: &Keypair,
    url: &str,
    expiration: u32,
    now: u32,
) -> anyhow::Result<Vec<Event>> {
    let txn = store.read()?;
    let found = [
        ("#t", "t", "", hashtags(store, &txn, now)?),
        ("#e", "e", url, posts(store, &txn)?),
    ];
    Ok(found
        .into_iter()
        .filter(|(_, _, _, rows)| !rows.is_empty())
        .map(|(l, name, extra, rows)| label(keypair, l, name, extra, &rows, now, expiration))
        .collect())
}

/// Label trends now and every configured interval after, unless that's 0.
pub fn spawn(state: AppState) {
    let keypair = state.keypair;
    if state.config.trends_interval == 0 {
        return;
    }
    let period = Duration::from_secs(state.config.trends_interval);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let start = Instant::now();
            let store = state.store.clone();
            let url = state.config.url.clone();
            let expiration = state.config.trends_expiration;
            let found = tokio::task::spawn_blocking(move || {
                labels(&store, &keypair, &url, expiration, event::now())
            })
            .await;
            let labels = match found {
                Ok(Ok(labels)) => labels,
                Ok(Err(err)) => {
                    tracing::error!("finding trends failed: {err:#}");
                    continue;
                }
                Err(err) => {
                    tracing::error!("finding trends panicked: {err}");
                    continue;
                }
            };
            for label in labels {
                if let Err(err) = state.publish(label).await {
                    tracing::error!("publishing a trend label failed: {err:#}");
                }
            }
            tracing::debug!("labeled trends in {:?}", start.elapsed());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use crate::rank::Rank;
    use crate::store::History;
    use crate::store::tests::{MAX_VALUES, open, put, test_tags};
    use crate::wot::Wot;
    use serde_json::Value;

    fn relay() -> Keypair {
        Keypair::from_secret_bytes([42; 32]).unwrap()
    }

    fn relay_pubkey() -> String {
        hex::encode(relay().x_only_public_key().0.to_byte_array())
    }

    fn pubkey(seed: u8) -> String {
        signed(seed, 0, 0, vec![], "").pubkey
    }

    /// A note by `seed`, `ago` seconds before `now`, with `tags`.
    fn note(seed: u8, now: u32, ago: u32, tags: Vec<Vec<&str>>) -> Event {
        signed(seed, (now - ago).into(), 1, tags, "a note")
    }

    fn summary(rows: &[Row]) -> Vec<(&str, u64, u64)> {
        rows.iter()
            .map(|row| (row.value.as_str(), row.authors, row.uses))
            .collect()
    }

    fn found(store: &Store, now: u32) -> Vec<Row> {
        hashtags(store, &store.read().unwrap(), now).unwrap()
    }

    #[test]
    fn counts_hashtags_by_author() {
        let (_dir, store) = open();
        let now = event::now();
        for seed in 1..=3 {
            put(&store, &note(seed, now, 60, vec![vec!["t", "Nostr"]]));
        }
        put(&store, &note(1, now, 50, vec![vec!["t", "nostr"]]));
        for seed in 4..=5 {
            put(&store, &note(seed, now, 60, vec![vec!["t", "bitcoin"]]));
        }
        // One author, however often, and twice in one note is once.
        for ago in 0..5 {
            let tags = vec![vec!["t", "spam"], vec!["t", "SPAM"]];
            put(&store, &note(6, now, 100 + ago, tags));
        }
        // Too old, bridged, or not a note.
        put(&store, &note(7, now, WINDOW + 1, vec![vec!["t", "old"]]));
        let bridged = vec![
            vec!["t", "bridged"],
            vec!["proxy", "https://x.example/1", "activitypub"],
        ];
        put(&store, &note(8, now, 60, bridged));
        let reaction = signed(9, (now - 60).into(), 7, vec![vec!["t", "nope"]], "+");
        put(&store, &reaction);

        assert_eq!(
            summary(&found(&store, now)),
            [("nostr", 3, 4), ("bitcoin", 2, 2), ("spam", 1, 5)]
        );
        // Only the day before the moment asked about.
        assert_eq!(summary(&found(&store, now - 3600)), [("old", 1, 1)]);
    }

    #[test]
    fn keeps_the_most_used() {
        let (_dir, store) = open();
        let now = event::now();
        for n in 0..30u8 {
            let tag = format!("tag{n:02}");
            // Each tag has one more user than the last.
            for seed in 1..=n + 1 {
                put(&store, &note(seed, now, 60, vec![vec!["t", &tag]]));
            }
        }
        let rows = found(&store, now);
        assert_eq!(rows.len(), HASHTAGS);
        assert_eq!(rows[0].value, "tag29");
        assert_eq!(rows[HASHTAGS - 1].value, "tag10");
    }

    #[test]
    fn weighs_hashtags_by_trust() {
        let seed: [u8; 32] = hex::decode(pubkey(1)).unwrap().try_into().unwrap();
        let wot = Wot::new(vec![seed], 0.85, 1, 0.01, 10_000).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(true, vec![], 20);
        let store = Store::open(
            dir.path(),
            1 << 26,
            test_tags(),
            history,
            Some(wot),
            Rank::default(),
        )
        .unwrap();
        put(&store, &signed(1, 100, 3, vec![vec!["p", &pubkey(2)]], ""));
        while store.turn().unwrap() {}

        let now = event::now();
        put(&store, &note(1, now, 60, vec![vec!["t", "trusted"]]));
        put(&store, &note(2, now, 60, vec![vec!["t", "followed"]]));
        // Many strangers count for nothing.
        for seed in 10..20 {
            put(&store, &note(seed, now, 60, vec![vec!["t", "spam"]]));
        }
        let rows = found(&store, now);
        assert_eq!(summary(&rows), [("trusted", 1, 1), ("followed", 1, 1)]);
        assert!(rows[0].weight > rows[1].weight && rows[1].weight > 0.0);
    }

    #[test]
    fn trends_the_hottest_posts() {
        let (_dir, store) = open();
        let now = event::now();
        let quiet = note(1, now, 60, vec![]);
        let liked = note(2, now, 60, vec![]);
        let loved = note(3, now, 60, vec![]);
        for ev in [&quiet, &liked, &loved] {
            put(&store, ev);
        }
        put(
            &store,
            &signed(10, now.into(), 7, vec![vec!["e", &liked.id]], "+"),
        );
        for seed in 10..13 {
            put(
                &store,
                &signed(seed, now.into(), 7, vec![vec!["e", &loved.id]], "+"),
            );
        }
        // Reacting twice is engaging once, but tags it twice.
        put(
            &store,
            &signed(10, now.into(), 6, vec![vec!["e", &loved.id]], ""),
        );
        let rows = posts(&store, &store.read().unwrap()).unwrap();
        assert_eq!(
            summary(&rows),
            [(loved.id.as_str(), 3, 4), (liked.id.as_str(), 1, 1)]
        );
    }

    /// The events a filter finds.
    fn query(store: &Store, filter: Value) -> Vec<Event> {
        let filter = Filter::parse(&filter, &store.indexed_tags, MAX_VALUES).unwrap();
        let results = crate::query::run(
            store,
            None,
            None,
            &[filter],
            100,
            500,
            |_| true,
            &Default::default(),
        )
        .unwrap();
        results
            .events
            .iter()
            .map(|json| serde_json::from_str(json).unwrap())
            .collect()
    }

    #[test]
    fn labels_as_ditto_reads_them() {
        let (_dir, store) = open();
        let now = event::now();
        let post = note(1, now, 60, vec![vec!["t", "Nostr"]]);
        put(&store, &post);
        put(
            &store,
            &signed(2, now.into(), 7, vec![vec!["e", &post.id]], "+"),
        );

        let url = "wss://relay.example/";
        let labels = labels(&store, &relay(), url, 3600, now).unwrap();
        assert_eq!(labels.len(), 2);
        for label in &labels {
            assert_eq!(label.verify(), Ok(()));
            assert_eq!(label.pubkey, relay_pubkey());
            assert_eq!(label.kind, LABEL);
            assert_eq!(label.content, "");
            assert_eq!(label.tags[0], ["L", NAMESPACE]);
            assert_eq!(
                label.tag("expiration"),
                Some((now + 3600).to_string().as_str())
            );
            put(&store, label);
        }
        assert_eq!(labels[0].tags[1], ["l", "#t", NAMESPACE]);
        assert_eq!(labels[0].tags[2], ["t", "nostr", "", "1", "1"]);
        assert_eq!(labels[1].tags[1], ["l", "#e", NAMESPACE]);
        assert_eq!(labels[1].tags[2], ["e", &post.id, url, "1", "1"]);

        // The latest of each, and a day of a hashtag's.
        let latest = |l: &str| {
            query(
                &store,
                json!({"kinds": [LABEL], "authors": [relay_pubkey()],
                       "#L": [NAMESPACE], "#l": [l], "limit": 1}),
            )
        };
        assert_eq!(latest("#t"), [labels[0].clone()]);
        assert_eq!(latest("#e"), [labels[1].clone()]);
        let day = |tag: &str| {
            query(
                &store,
                json!({"kinds": [LABEL], "authors": [relay_pubkey()],
                       "#L": [NAMESPACE], "#l": ["#t"], "#t": [tag],
                       "since": now - 60, "until": now + 60, "limit": 1}),
            )
        };
        assert_eq!(day("nostr"), [labels[0].clone()]);
        assert!(day("bitcoin").is_empty());
    }

    #[test]
    fn labels_nothing_when_nothing_trends() {
        let (_dir, store) = open();
        put(&store, &note(1, event::now(), 60, vec![]));
        let labels = labels(&store, &relay(), "wss://relay.example/", 0, event::now()).unwrap();
        assert!(labels.is_empty());
        let label = label(&relay(), "#t", "t", "", &[], 100, 0);
        assert_eq!(label.tag("expiration"), None);
    }
}
