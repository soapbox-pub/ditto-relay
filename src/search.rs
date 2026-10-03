//! NIP-50 search, in a tantivy index kept beside the LMDB.
//!
//! The LMDB stays the source of truth. The index holds, for each event of a
//! searchable kind, its sequence number, kind, author, `created_at`, and
//! text; a search finds sequence numbers there and loads the events from
//! the LMDB. Sequence numbers are never reused, so a hit whose event is no
//! longer stored is simply skipped: deleting replaced events from the index
//! keeps it small, but nothing depends on it.
//!
//! One thread, the [`Indexer`], writes the index. It reads what's been
//! stored since it last looked straight from the LMDB, so catching up after
//! a restart — or rebuilding from nothing — is the same as keeping up. The
//! writer tells it when there's something new and what was removed, and it
//! commits at most every so often, recording in the commit how far it got.
//!
//! Events stored since the last commit aren't searchable yet, so a search
//! also checks the newest of them by hand. Everything a search's LMDB
//! snapshot holds is therefore visible to it, as with any other query.
//!
//! Text is split on anything not alphanumeric, lowercased, and folded to
//! ASCII, both when indexing and searching, and in [`matches`], which checks
//! live events against a search. A search matches events with every term,
//! and none it excludes with `-word`. One that only excludes has nothing to
//! look up, so it's no use here: it's answered like any other filter, from
//! the LMDB's indexes newest first, with the exclusions checked by hand.
//!
//! With `autocomplete:true`, a search looks instead at the names people
//! look things up by — a profile's name, display name, and NIP-05, and any
//! event's title — and its terms are prefixes. Those are indexed in a field
//! of their own as every prefix of every word, up to [`MAX_PREFIX`]
//! characters, so a prefix is looked up like any term. Names are indexed
//! whatever the kind: the searchable kinds only limit ordinary search.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tantivy::collector::TopDocs;
use tantivy::columnar::Column;
use tantivy::query::{BooleanQuery, Occur, Query, RangeQuery, TermQuery, TermSetQuery};
use tantivy::schema::{
    FAST, Field, INDEXED, IndexRecordOption, Schema, TextFieldIndexing, TextOptions,
};
use tantivy::tokenizer::{
    AsciiFoldingFilter, LowerCaser, PreTokenizedString, RemoveLongFilter, SimpleTokenizer,
    TextAnalyzer, Token,
};
use tantivy::{
    DocAddress, Index, IndexReader, IndexWriter, Order, ReloadPolicy, TantivyDocument, Term,
};

use crate::filter::{Filter, Search};
use crate::lmdb::Txn;
use crate::record::{Content, Element, EventView};
use crate::store::Store;

/// Bumped when what's indexed, or how, changes. The index is then rebuilt.
const VERSION: u32 = 3;

/// The name the analyzer is registered under.
const ANALYZER: &str = "nostr";

/// Longer tokens aren't words anyone searches for.
const MAX_TOKEN: usize = 40;

/// Tags whose values are searchable text.
const TEXT_TAGS: &[&str] = &["title", "summary", "subject", "alt"];

/// The kind 0 fields that are searchable.
const PROFILE_FIELDS: &[&str] = &["name", "display_name", "about", "nip05", "website"];

/// The kind 0 fields autocomplete matches.
const NAME_FIELDS: &[&str] = &["name", "display_name", "nip05"];

/// The longest prefix of a word indexed for autocomplete. Longer search
/// terms are looked up by their first this many characters, then checked.
const MAX_PREFIX: usize = 20;

/// The indexer's memory, split between its threads.
const WRITER_MEMORY: usize = 64 << 20;

/// The most events indexed per LMDB read transaction and commit.
const CATCH_UP_CHUNK: usize = 50_000;

/// The most sequence numbers past the last commit a search checks by hand.
const MAX_UNINDEXED: u64 = 10_000;

/// The most hits one filter may examine, to fill its limit after the
/// fields the index doesn't hold (tags) are checked.
const MAX_HITS: usize = 10_000;

thread_local! {
    static TOKENIZER: RefCell<TextAnalyzer> = RefCell::new(analyzer());
}

fn analyzer() -> TextAnalyzer {
    TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(RemoveLongFilter::limit(MAX_TOKEN))
        .filter(LowerCaser)
        .filter(AsciiFoldingFilter)
        .build()
}

/// The terms text is indexed and searched by.
pub fn tokens(text: &str) -> Vec<String> {
    TOKENIZER.with_borrow_mut(|analyzer| {
        let mut stream = analyzer.token_stream(text);
        let mut out = Vec::new();
        while stream.advance() {
            out.push(stream.token().text.clone());
        }
        out
    })
}

/// An event's searchable text: its content (for a profile, the fields
/// people search by) and its text tags.
pub fn text(view: &EventView) -> String {
    let mut out = String::new();
    let mut push = |text: &str| {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(text);
    };
    // Short words can be base64 too, and kept as the bytes they spell.
    let content = match view.content() {
        Content::Text(text) => Cow::Borrowed(text),
        Content::Base64(bytes) => Cow::Owned(STANDARD.encode(bytes)),
    };
    if view.kind() == 0 {
        if let Ok(Value::Object(profile)) = serde_json::from_str(&content) {
            for field in PROFILE_FIELDS {
                if let Some(Value::String(value)) = profile.get(*field) {
                    push(value);
                }
            }
        }
    } else {
        push(&content);
    }
    for mut tag in view.tags() {
        if let (Some(Element::Text(name)), Some(Element::Text(value))) = (tag.next(), tag.next())
            && TEXT_TAGS.contains(&name)
        {
            push(value);
        }
    }
    out
}

/// Whether an event has every term of a search, and not every term of any
/// group it excludes.
pub fn matches(terms: &[String], excluded: &[Vec<String>], view: &EventView) -> bool {
    if terms.is_empty() && excluded.is_empty() {
        return true;
    }
    let have: HashSet<String> = tokens(&text(view)).into_iter().collect();
    terms.iter().all(|term| have.contains(term))
        && !excluded
            .iter()
            .any(|group| group.iter().all(|term| have.contains(term)))
}

/// What autocomplete matches: a profile's names and any event's title.
pub fn names(view: &EventView) -> String {
    let mut out = String::new();
    let mut push = |text: &str| {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(text);
    };
    if view.kind() == 0
        && let Content::Text(content) = view.content()
        && let Ok(Value::Object(profile)) = serde_json::from_str(content)
    {
        for field in NAME_FIELDS {
            if let Some(Value::String(value)) = profile.get(*field) {
                push(value);
            }
        }
    }
    if let Some(Element::Text(title)) = view.tag("title") {
        push(title);
    }
    out
}

/// Whether every term of an autocomplete search begins a word of an
/// event's names.
pub fn matches_prefixes(terms: &[String], view: &EventView) -> bool {
    if terms.is_empty() {
        return true;
    }
    let have = tokens(&names(view));
    terms
        .iter()
        .all(|term| have.iter().any(|word| word.starts_with(term.as_str())))
}

/// Every prefix of every word of `text`, up to [`MAX_PREFIX`] characters,
/// as autocomplete indexes it.
fn prefixes(text: &str) -> PreTokenizedString {
    let mut out = Vec::new();
    for (position, word) in tokens(text).into_iter().enumerate() {
        let ends = word.char_indices().skip(1).map(|(i, _)| i);
        for end in ends.chain([word.len()]).take(MAX_PREFIX) {
            out.push(Token {
                position,
                text: word[..end].to_string(),
                ..Token::default()
            });
        }
    }
    PreTokenizedString {
        text: text.to_string(),
        tokens: out,
    }
}

/// A search term as autocomplete looks it up.
fn prefix(term: &str) -> &str {
    term.char_indices()
        .nth(MAX_PREFIX)
        .map_or(term, |(end, _)| &term[..end])
}

/// What a commit records.
#[derive(Serialize, Deserialize)]
struct Payload {
    version: u32,
    /// Every event stored below this sequence number has been indexed.
    next_seq: u64,
}

#[derive(Clone, Copy)]
struct Fields {
    seq: Field,
    kind: Field,
    pubkey: Field,
    created_at: Field,
    text: Field,
    names: Field,
}

fn schema() -> Schema {
    let mut builder = Schema::builder();
    builder.add_u64_field("seq", INDEXED | FAST);
    builder.add_u64_field("kind", INDEXED);
    builder.add_bytes_field("pubkey", INDEXED);
    builder.add_u64_field("created_at", FAST);
    let indexing = TextFieldIndexing::default()
        .set_tokenizer(ANALYZER)
        .set_index_option(IndexRecordOption::WithFreqs);
    let options = TextOptions::default().set_indexing_options(indexing);
    builder.add_text_field("text", options.clone());
    // Pre-tokenized, as prefixes.
    builder.add_text_field("names", options);
    builder.build()
}

pub struct SearchIndex {
    reader: IndexReader,
    fields: Fields,
    /// The kinds indexed. Sorted.
    kinds: Vec<u16>,
    /// Every event stored below this sequence number is visible to the
    /// reader (or no longer stored).
    indexed: AtomicU64,
}

impl SearchIndex {
    /// Open the index at `dir`, or create it, rebuilding it if it's from an
    /// older version or doesn't belong with `store`. The indexer catches it
    /// up once spawned.
    pub fn open(
        dir: &Path,
        mut kinds: Vec<u16>,
        store: &Store,
    ) -> anyhow::Result<(Arc<SearchIndex>, Indexer)> {
        kinds.sort_unstable();
        kinds.dedup();
        let schema = schema();
        let store_next_seq = store.next_seq(&*store.read()?)?;

        let mut opened = None;
        if dir.join("meta.json").exists() {
            let index = Index::open_in_dir(dir)
                .with_context(|| format!("Could not open the search index at {}", dir.display()))?;
            let payload = index
                .load_metas()?
                .payload
                .and_then(|payload| serde_json::from_str::<Payload>(&payload).ok());
            match payload {
                // Further along than the LMDB means it's another LMDB's.
                Some(p)
                    if p.version == VERSION
                        && p.next_seq <= store_next_seq
                        && index.schema() == schema =>
                {
                    opened = Some((index, p.next_seq));
                }
                _ => {
                    tracing::warn!("rebuilding the search index at {}", dir.display());
                    drop(index);
                    std::fs::remove_dir_all(dir)?;
                }
            }
        }
        let (index, next_seq) = match opened {
            Some(opened) => opened,
            None => {
                std::fs::create_dir_all(dir).with_context(|| {
                    format!("Could not create the search index at {}", dir.display())
                })?;
                (Index::create_in_dir(dir, schema.clone())?, 0)
            }
        };
        index.tokenizers().register(ANALYZER, analyzer());

        let field = |name| schema.get_field(name).expect("a field of the schema");
        let fields = Fields {
            seq: field("seq"),
            kind: field("kind"),
            pubkey: field("pubkey"),
            created_at: field("created_at"),
            text: field("text"),
            names: field("names"),
        };
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;
        let search = Arc::new(SearchIndex {
            reader,
            fields,
            kinds,
            indexed: AtomicU64::new(next_seq),
        });
        let indexer = Indexer {
            writer: index.writer(WRITER_MEMORY)?,
            search: search.clone(),
            next_seq,
            dirty: false,
        };
        Ok((search, indexer))
    }

    /// Limit a search filter to the kinds indexed, so it matches the same
    /// events live as it finds stored. Autocomplete has every kind.
    pub fn restrict(&self, filter: &mut Filter) {
        if filter
            .search
            .as_ref()
            .is_none_or(|search| search.autocomplete)
        {
            return;
        }
        let kinds: Vec<u16> = match filter.kinds.take() {
            Some(kinds) => kinds
                .into_iter()
                .filter(|kind| self.kinds.binary_search(kind).is_ok())
                .collect(),
            None => self.kinds.clone(),
        };
        filter.never |= kinds.is_empty();
        filter.kinds = Some(kinds);
    }

    fn document(&self, seq: u64, view: &EventView) -> Option<TantivyDocument> {
        let text = match self.kinds.binary_search(&view.kind()) {
            Ok(_) => text(view),
            Err(_) => String::new(),
        };
        let names = names(view);
        if text.is_empty() && names.is_empty() {
            return None;
        }
        let f = self.fields;
        let mut doc = TantivyDocument::new();
        doc.add_u64(f.seq, seq);
        doc.add_u64(f.kind, view.kind().into());
        doc.add_bytes(f.pubkey, view.pubkey());
        doc.add_u64(f.created_at, view.created_at().into());
        doc.add_text(f.text, text);
        if !names.is_empty() {
            doc.add_pre_tokenized_text(f.names, prefixes(&names));
        }
        Some(doc)
    }

    fn query(&self, filter: &Filter, search: &Search) -> BooleanQuery {
        let f = self.fields;
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = search
            .terms
            .iter()
            .map(|term| {
                let term = if search.autocomplete {
                    Term::from_field_text(f.names, prefix(term))
                } else {
                    Term::from_field_text(f.text, term)
                };
                let query: Box<dyn Query> =
                    Box::new(TermQuery::new(term, IndexRecordOption::WithFreqs));
                (Occur::Must, query)
            })
            .collect();
        for group in &search.excluded {
            let mut terms = group.iter().map(|term| {
                let term = Term::from_field_text(f.text, term);
                Box::new(TermQuery::new(term, IndexRecordOption::Basic)) as Box<dyn Query>
            });
            let query = match group.len() {
                1 => terms.next().expect("one term"),
                _ => Box::new(BooleanQuery::new(
                    terms.map(|query| (Occur::Must, query)).collect(),
                )),
            };
            clauses.push((Occur::MustNot, query));
        }
        // Only indexed kinds are in the index, so asking for all is moot.
        if let Some(kinds) = filter.kinds.as_ref().filter(|&kinds| *kinds != self.kinds) {
            let terms = kinds
                .iter()
                .map(|&k| Term::from_field_u64(f.kind, k.into()));
            clauses.push((Occur::Must, Box::new(TermSetQuery::new(terms))));
        }
        if let Some(authors) = &filter.authors {
            let terms = authors.iter().map(|a| Term::from_field_bytes(f.pubkey, a));
            clauses.push((Occur::Must, Box::new(TermSetQuery::new(terms))));
        }
        if filter.since > 0 || filter.until < u32::MAX {
            let bound = |t: u32| Bound::Included(Term::from_field_u64(f.created_at, t.into()));
            clauses.push((
                Occur::Must,
                Box::new(RangeQuery::new(bound(filter.since), bound(filter.until))),
            ));
        }
        BooleanQuery::new(clauses)
    }

    /// Run a search filter: the best matches by relevance, or with
    /// `sort:new`, the newest.
    pub fn run<'t>(
        &self,
        store: &Store,
        txn: &'t Txn,
        filter: &Filter,
        search: &Search,
        limit: usize,
    ) -> anyhow::Result<Vec<(u64, EventView<'t>)>> {
        // In this order, so the searcher has everything below `indexed`.
        let indexed = self.indexed.load(Ordering::Acquire);
        let searcher = self.reader.searcher();
        let next_seq = store.next_seq(txn)?;

        // Stored since the last commit: checked by hand. The searcher may
        // have some of them too, so hits are deduplicated.
        let mut seen = HashSet::new();
        let mut unindexed = Vec::new();
        let mut cursor = txn.cursor(store.tables.events)?;
        let start = indexed.max(next_seq.saturating_sub(MAX_UNINDEXED));
        let mut entry = cursor.set_range(&start.to_ne_bytes())?;
        while let Some((key, record)) = entry {
            let seq = u64::from_ne_bytes(key.try_into()?);
            if let Some(view) = EventView::new(record).filter(|view| filter.matches(view)) {
                seen.insert(seq);
                unindexed.push((seq, view));
            }
            entry = cursor.next()?;
        }
        unindexed.sort_unstable_by(|(_, a), (_, b)| newest_first(a, b));

        let query = self.query(filter, search);
        let mut columns: HashMap<u32, Column<u64>> = HashMap::new();
        let mut hits = Vec::new();
        let mut offset = 0;
        let mut page = (limit * 2).max(32);
        loop {
            let top = TopDocs::with_limit(page).and_offset(offset);
            let page_hits: Vec<(f32, DocAddress)> = if search.sort_new {
                let collector = top.order_by_fast_field::<u64>("created_at", Order::Desc);
                let found = searcher.search(&query, &collector)?;
                found
                    .into_iter()
                    .map(|(_, address)| (0.0, address))
                    .collect()
            } else {
                searcher.search(&query, &top.order_by_score())?
            };
            let count = page_hits.len();
            for (score, address) in page_hits {
                let column = match columns.entry(address.segment_ord) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => e.insert(
                        searcher
                            .segment_reader(address.segment_ord)
                            .fast_fields()
                            .u64("seq")?,
                    ),
                };
                let Some(seq) = column.first(address.doc_id) else {
                    continue;
                };
                if !seen.insert(seq) {
                    continue;
                }
                // Gone since, or stored after this snapshot.
                let Some(view) = store.load(txn, seq)? else {
                    continue;
                };
                // Autocomplete terms may be longer than what's indexed.
                let matches = if search.autocomplete {
                    filter.matches(&view)
                } else {
                    filter.matches_fields(&view)
                };
                if matches {
                    hits.push((score, seq, view));
                }
            }
            offset += count;
            if hits.len() + unindexed.len() >= limit || count < page || offset >= MAX_HITS {
                break;
            }
            page = (page * 2).min(MAX_HITS - offset);
        }

        let mut found = unindexed;
        if search.sort_new {
            found.extend(hits.into_iter().map(|(_, seq, view)| (seq, view)));
            found.sort_unstable_by(|(_, a), (_, b)| newest_first(a, b));
        } else {
            // Not yet indexed means new, and they have every term: first.
            hits.sort_by(|(x, _, a), (y, _, b)| y.total_cmp(x).then_with(|| newest_first(a, b)));
            found.extend(hits.into_iter().map(|(_, seq, view)| (seq, view)));
        }
        found.truncate(limit);
        Ok(found)
    }
}

/// Newest first; on a tie, the lowest id first (NIP-01).
fn newest_first(a: &EventView, b: &EventView) -> std::cmp::Ordering {
    b.created_at()
        .cmp(&a.created_at())
        .then_with(|| a.id().cmp(b.id()))
}

/// Writes the index. See the [module docs](self).
pub struct Indexer {
    writer: IndexWriter,
    search: Arc<SearchIndex>,
    /// The sequence number to index from next.
    next_seq: u64,
    /// Whether anything's changed since the last commit.
    dirty: bool,
}

impl Indexer {
    /// Index what's been stored since last time, up to `max` events.
    /// Returns whether there's more.
    pub fn catch_up(&mut self, store: &Store, max: usize) -> anyhow::Result<bool> {
        let txn = store.read()?;
        let end = store.next_seq(&txn)?;
        let mut cursor = txn.cursor(store.tables.events)?;
        let mut entry = cursor.set_range(&self.next_seq.to_ne_bytes())?;
        let mut count = 0;
        while let Some((key, record)) = entry {
            let seq = u64::from_ne_bytes(key.try_into()?);
            if count == max {
                self.next_seq = seq;
                return Ok(true);
            }
            if let Some(doc) = EventView::new(record).and_then(|v| self.search.document(seq, &v)) {
                self.writer.add_document(doc)?;
            }
            count += 1;
            entry = cursor.next()?;
        }
        self.dirty |= end != self.next_seq;
        self.next_seq = end;
        Ok(false)
    }

    /// Drop removed events from the index. Any not yet indexed are no
    /// longer stored, so won't be.
    pub fn remove(&mut self, seqs: &[u64]) {
        for &seq in seqs {
            self.writer
                .delete_term(Term::from_field_u64(self.search.fields.seq, seq));
            self.dirty = true;
        }
    }

    /// Make what's been indexed searchable.
    pub fn commit(&mut self) -> anyhow::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let payload = Payload {
            version: VERSION,
            next_seq: self.next_seq,
        };
        let mut commit = self.writer.prepare_commit()?;
        commit.set_payload(&serde_json::to_string(&payload)?);
        commit.commit()?;
        self.search.reader.reload()?;
        self.search.indexed.store(self.next_seq, Ordering::Release);
        self.dirty = false;
        Ok(())
    }

    fn catch_up_all(&mut self, store: &Store) -> anyhow::Result<()> {
        while self.catch_up(store, CATCH_UP_CHUNK)? {
            self.dirty = true;
            self.commit()?;
        }
        self.commit()
    }

    /// Run on a thread of its own, committing at most every `interval`.
    /// Send it the sequence numbers of removed events (or none) after each
    /// write.
    pub fn spawn(mut self, store: Arc<Store>, interval: Duration) -> Sender<Vec<u64>> {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u64>>();
        std::thread::Builder::new()
            .name("search-indexer".into())
            .spawn(move || {
                if let Err(err) = self.run(&store, &rx, interval) {
                    tracing::error!("the search indexer stopped: {err:#}");
                }
            })
            .expect("failed to spawn the search indexer");
        tx
    }

    fn run(
        &mut self,
        store: &Store,
        rx: &Receiver<Vec<u64>>,
        interval: Duration,
    ) -> anyhow::Result<()> {
        self.catch_up_all(store)?;
        tracing::info!("search index caught up to {}", self.next_seq);
        while let Ok(removed) = rx.recv() {
            self.remove(&removed);
            let deadline = Instant::now() + interval;
            while let Ok(removed) =
                rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                self.remove(&removed);
            }
            self.catch_up_all(store)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::event::tests::signed;
    use crate::record;
    use crate::store::tests::{open, put};
    use serde_json::json;

    fn view_text(event: &Event) -> Vec<String> {
        let record = record::encode(event);
        tokens(&text(&EventView::new(&record).unwrap()))
    }

    #[test]
    fn tokenizes_folding_case_and_accents() {
        assert_eq!(
            tokens("Héllo, WORLD! naïve-café"),
            ["hello", "world", "naive", "cafe"]
        );
        assert!(tokens(&"x".repeat(100)).is_empty());
    }

    #[test]
    fn extracts_profiles_and_text_tags() {
        let profile = json!({"name": "Alice", "about": "Rust dev", "picture": "https://pic"});
        let event = signed(1, 100, 0, vec![], &profile.to_string());
        assert_eq!(view_text(&event), ["alice", "rust", "dev"]);
        let article = signed(
            1,
            100,
            30023,
            vec![vec!["d", "x"], vec!["title", "Big News"]],
            "body",
        );
        assert_eq!(view_text(&article), ["body", "big", "news"]);
    }

    struct Fixture {
        _dirs: (tempfile::TempDir, tempfile::TempDir),
        store: Store,
        index: Arc<SearchIndex>,
        indexer: Indexer,
    }

    fn fixture() -> Fixture {
        let (db, store) = open();
        let dir = tempfile::tempdir().unwrap();
        let (index, indexer) = SearchIndex::open(dir.path(), vec![0, 1, 30023], &store).unwrap();
        Fixture {
            _dirs: (db, dir),
            store,
            index,
            indexer,
        }
    }

    impl Fixture {
        fn index_all(&mut self) {
            self.indexer.catch_up_all(&self.store).unwrap();
        }

        /// Run a search filter as a REQ would.
        fn search(&self, filter: serde_json::Value) -> Vec<String> {
            let mut filter = Filter::parse(&filter).unwrap();
            assert!(filter.search.is_some());
            self.index.restrict(&mut filter);
            crate::query::run(&self.store, Some(&self.index), &[filter], 100, 500)
                .unwrap()
                .events
                .iter()
                .map(|json| serde_json::from_str::<Event>(json).unwrap().id)
                .collect()
        }
    }

    #[test]
    fn excludes_words() {
        let mut f = fixture();
        let plain = signed(1, 100, 1, vec![], "nostr nostr is neat");
        let bitcoin = signed(2, 200, 1, vec![], "nostr and Bitcoin");
        let ecash = signed(3, 300, 1, vec![], "nostr e-cash");
        let cash = signed(1, 400, 1, vec![], "cash only");
        let article = signed(2, 500, 30023, vec![vec!["d", "a"]], "long read");
        let reaction = signed(3, 600, 7, vec![], "+");
        for event in [&plain, &bitcoin, &ecash, &cash, &article, &reaction] {
            put(&f.store, event);
        }
        f.index_all();
        let ids =
            |events: &[&Event]| -> Vec<String> { events.iter().map(|e| e.id.clone()).collect() };

        assert_eq!(
            f.search(json!({"search": "nostr -bitcoin"})),
            ids(&[&plain, &ecash])
        );
        assert_eq!(
            f.search(json!({"search": "nostr -bitcoin sort:new"})),
            ids(&[&ecash, &plain])
        );
        assert_eq!(
            f.search(json!({"search": "nostr -e-cash"})),
            ids(&[&plain, &bitcoin])
        );
        // Only exclusions: newest first, among the searchable kinds.
        assert_eq!(
            f.search(json!({"search": "-bitcoin"})),
            ids(&[&article, &cash, &ecash, &plain])
        );
        assert_eq!(
            f.search(json!({"search": "-bitcoin -cash", "kinds": [1, 7]})),
            ids(&[&plain])
        );
        assert_eq!(
            f.search(json!({"search": "-bitcoin", "kinds": [1], "limit": 2})),
            ids(&[&cash, &ecash])
        );
        // Stored since the last commit makes no difference.
        let late = signed(1, 700, 1, vec![], "nostr later");
        put(&f.store, &late);
        assert_eq!(
            f.search(json!({"search": "nostr -bitcoin -e-cash"})),
            ids(&[&late, &plain])
        );
    }

    #[test]
    fn ranks_by_relevance_or_recency() {
        let mut f = fixture();
        let once = signed(1, 300, 1, vec![], "rust and other things besides");
        let twice = signed(2, 100, 1, vec![], "rust rust");
        let neither = signed(3, 200, 1, vec![], "go");
        let reaction = signed(3, 200, 7, vec![], "rust");
        for event in [&once, &twice, &neither, &reaction] {
            put(&f.store, event);
        }
        f.index_all();
        assert_eq!(
            f.search(json!({"search": "RUST"})),
            [twice.id.as_str(), once.id.as_str()]
        );
        assert_eq!(
            f.search(json!({"search": "rust sort:new"})),
            [once.id.as_str(), twice.id.as_str()]
        );
        assert_eq!(
            f.search(json!({"search": "rust things"})),
            [once.id.as_str()]
        );
        assert_eq!(
            f.search(json!({"search": "rust", "limit": 1})),
            [twice.id.as_str()]
        );
        // Unknown extensions are ignored; unindexed kinds can't match.
        assert_eq!(
            f.search(json!({"search": "rust include:spam", "kinds": [1, 7]}))
                .len(),
            2
        );
        assert!(f.search(json!({"search": "rust", "kinds": [7]})).is_empty());
    }

    #[test]
    fn applies_the_other_fields() {
        let mut f = fixture();
        let a = signed(1, 100, 1, vec![vec!["t", "x"]], "hello");
        let b = signed(2, 200, 1, vec![], "hello");
        let profile = signed(2, 150, 0, vec![], &json!({"name": "hello"}).to_string());
        for event in [&a, &b, &profile] {
            put(&f.store, event);
        }
        f.index_all();
        assert_eq!(
            f.search(json!({"search": "hello", "authors": [a.pubkey]})),
            [a.id.as_str()]
        );
        assert_eq!(
            f.search(json!({"search": "hello", "#t": ["x"]})),
            [a.id.as_str()]
        );
        assert_eq!(
            f.search(json!({"search": "hello", "kinds": [0]})),
            [profile.id.as_str()]
        );
        assert_eq!(
            f.search(json!({"search": "hello sort:new", "since": 120, "until": 200})),
            [b.id.as_str(), profile.id.as_str()]
        );
    }

    #[test]
    fn forgets_replaced_events() {
        let mut f = fixture();
        put(
            &f.store,
            &signed(1, 100, 0, vec![], &json!({"name": "old"}).to_string()),
        );
        f.index_all();
        assert_eq!(f.search(json!({"search": "old"})).len(), 1);

        let new = signed(1, 200, 0, vec![], &json!({"name": "new"}).to_string());
        let batch = f
            .store
            .write_batch([record::encode(&new).as_slice()])
            .unwrap();
        // Gone from the LMDB, so from results, before the index hears of it.
        assert!(f.search(json!({"search": "old"})).is_empty());
        assert_eq!(batch.removed, [1]);
        f.indexer.remove(&batch.removed);
        f.index_all();
        assert!(f.search(json!({"search": "old"})).is_empty());
        assert_eq!(f.search(json!({"search": "new"})), [new.id.as_str()]);
        let searcher = f.index.reader.searcher();
        assert_eq!(searcher.num_docs(), 1);
    }

    #[test]
    fn finds_events_not_yet_indexed() {
        let mut f = fixture();
        let old = signed(1, 100, 1, vec![], "news");
        put(&f.store, &old);
        f.index_all();
        let new = signed(1, 200, 1, vec![], "news");
        put(&f.store, &new);
        assert_eq!(
            f.search(json!({"search": "news"})),
            [new.id.as_str(), old.id.as_str()]
        );
        assert_eq!(
            f.search(json!({"search": "news sort:new"})),
            [new.id.as_str(), old.id.as_str()]
        );
    }

    #[test]
    fn catches_up_after_reopening() {
        let (db, store) = open();
        let dir = tempfile::tempdir().unwrap();
        let note = signed(1, 100, 1, vec![], "persisted");
        put(&store, &note);
        {
            let (_, mut indexer) = SearchIndex::open(dir.path(), vec![1], &store).unwrap();
            indexer.catch_up_all(&store).unwrap();
        }
        let later = signed(1, 200, 1, vec![], "persisted later");
        put(&store, &later);

        let (index, mut indexer) = SearchIndex::open(dir.path(), vec![1], &store).unwrap();
        assert_eq!(index.indexed.load(Ordering::Relaxed), 2);
        indexer.catch_up_all(&store).unwrap();
        assert_eq!(index.reader.searcher().num_docs(), 2);
        drop((index, indexer));

        // An index further along than the LMDB isn't this LMDB's: rebuilt.
        let (_db2, other) = open();
        let (index, _) = SearchIndex::open(dir.path(), vec![1], &other).unwrap();
        assert_eq!(index.reader.searcher().num_docs(), 0);
        drop(index);

        // So is one from an older version.
        {
            let (_, mut indexer) = SearchIndex::open(dir.path(), vec![1], &store).unwrap();
            let mut commit = indexer.writer.prepare_commit().unwrap();
            commit.set_payload(r#"{"version":1,"next_seq":3}"#);
            commit.commit().unwrap();
        }
        let (index, _) = SearchIndex::open(dir.path(), vec![1], &store).unwrap();
        assert_eq!(index.indexed.load(Ordering::Relaxed), 0);
        drop(db);
    }

    #[test]
    fn autocompletes_names_and_titles() {
        let mut f = fixture();
        let profile = |seed, name: &str| {
            let content = json!({"name": name, "about": "bitcoin maximalist"});
            signed(seed, 100, 0, vec![], &content.to_string())
        };
        let ali = profile(1, "Ali");
        let alice = profile(2, "Alice in Wonderland Fan Club");
        let jack = profile(3, "Jack Dorsey");
        let article = signed(
            1,
            100,
            30023,
            vec![vec!["d", "a"], vec!["title", "Alpine"]],
            "x",
        );
        let note = signed(1, 100, 1, vec![], "alibi");
        for event in [&ali, &alice, &jack, &article, &note] {
            put(&f.store, event);
        }
        f.index_all();
        let autocomplete = |text: &str| json!({"search": format!("{text} autocomplete:true")});
        // The shorter name is the better match.
        assert_eq!(
            f.search(autocomplete("ali")),
            [ali.id.as_str(), alice.id.as_str()]
        );
        assert_eq!(f.search(autocomplete("jac dor")), [jack.id.as_str()]);
        assert_eq!(f.search(autocomplete("alp")), [article.id.as_str()]);
        // Not bios, not notes, not the middle of a word.
        assert!(f.search(autocomplete("bitc")).is_empty());
        assert!(f.search(autocomplete("alib")).is_empty());
        assert!(f.search(autocomplete("orsey")).is_empty());
        // Ordinary search still finds the bio.
        assert_eq!(f.search(json!({"search": "bitcoin"})).len(), 3);

        // Any kind with a title, searchable or not; but only its title.
        let listing = signed(
            5,
            100,
            30402,
            vec![vec!["d", "b"], vec!["title", "Bicycle"]],
            "red",
        );
        put(&f.store, &listing);
        f.index_all();
        assert_eq!(f.search(autocomplete("bicy")), [listing.id.as_str()]);
        let kinds = json!({"search": "bicy autocomplete:true", "kinds": [30402]});
        assert_eq!(f.search(kinds), [listing.id.as_str()]);
        assert!(f.search(json!({"search": "bicycle"})).is_empty());
        assert!(
            f.search(json!({"search": "red", "kinds": [30402]}))
                .is_empty()
        );

        // Past what's indexed, a term is still checked in full.
        let long = profile(4, "Supercalifragilisticexpialidocious");
        put(&f.store, &long);
        f.index_all();
        assert_eq!(
            f.search(autocomplete("supercalifragilisticexpi")),
            [long.id.as_str()]
        );
        assert!(f.search(autocomplete("supercalifragilisticky")).is_empty());
    }

    /// Random events and `sort:new` searches, plain and autocomplete, some
    /// indexed and some not, checked against matching every event.
    #[test]
    fn agrees_with_brute_force() {
        use rand::rngs::StdRng;
        use rand::{RngExt, SeedableRng};

        let mut f = fixture();
        let mut rng = StdRng::seed_from_u64(11);
        const KINDS: [u16; 3] = [1, 7, 30023];
        // Two that share their first MAX_PREFIX characters.
        let words = [
            "apple",
            "Banana",
            "cherry",
            "date",
            "élan",
            "supercalifragilisticexpialidocious",
            "supercalifragilisticky",
        ];
        let mut all = Vec::new();
        for i in 0..300 {
            let content: Vec<&str> = (0..rng.random_range(0..5))
                .map(|_| words[rng.random_range(0..words.len())])
                .collect();
            let kind = KINDS[rng.random_range(0..3)];
            let d = i.to_string();
            let mut tags = vec![vec!["d", d.as_str()]];
            if rng.random_bool(0.3) {
                tags.push(vec!["t", "x"]);
            }
            let title = words[rng.random_range(0..words.len())];
            if rng.random_bool(0.5) {
                tags.push(vec!["title", title]);
            }
            let event = signed(
                rng.random_range(1..4),
                rng.random_range(100..160),
                kind,
                tags,
                &content.join(" "),
            );
            put(&f.store, &event);
            all.push(event);
            if i == 200 {
                f.index_all();
            }
        }
        let pubkeys: Vec<String> = (1..4)
            .map(|seed| signed(seed, 0, 1, vec![], "").pubkey)
            .collect();

        for _ in 0..200 {
            let autocomplete = rng.random_bool(0.5);
            let (min, max) = if autocomplete { (1, 3) } else { (0, 3) };
            let mut terms: Vec<String> = (0..rng.random_range(min..max))
                .map(|_| {
                    let word = words[rng.random_range(0..words.len())];
                    if autocomplete {
                        let len = rng.random_range(1..=word.chars().count());
                        word.chars().take(len).collect()
                    } else {
                        word.to_string()
                    }
                })
                .collect();
            if !autocomplete {
                let count = rng.random_range(usize::from(terms.is_empty())..3);
                for _ in 0..count {
                    terms.push(format!("-{}", words[rng.random_range(0..words.len())]));
                }
            }
            let extensions = match autocomplete {
                true => "sort:new autocomplete:true",
                false => "sort:new",
            };
            let mut filter = serde_json::Map::new();
            filter.insert(
                "search".into(),
                json!(format!("{} {extensions}", terms.join(" "))),
            );
            if rng.random_bool(0.3) {
                filter.insert("authors".into(), json!(pubkeys[..rng.random_range(1..3)]));
            }
            if rng.random_bool(0.3) {
                filter.insert("kinds".into(), json!([KINDS[rng.random_range(0..3)]]));
            }
            if rng.random_bool(0.3) {
                filter.insert("#t".into(), json!(["x"]));
            }
            if rng.random_bool(0.3) {
                filter.insert("since".into(), json!(rng.random_range(100..160)));
            }
            let limit = rng.random_range(1..40);
            filter.insert("limit".into(), json!(limit));
            let filter = serde_json::Value::Object(filter);

            let mut parsed = Filter::parse(&filter).unwrap();
            f.index.restrict(&mut parsed);
            let mut expected: Vec<&Event> = all
                .iter()
                .filter(|e| {
                    let record = record::encode(e);
                    parsed.matches(&EventView::new(&record).unwrap())
                })
                .collect();
            expected.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let expected: Vec<&str> = expected.iter().take(limit).map(|e| e.id.as_str()).collect();
            assert_eq!(f.search(filter.clone()), expected, "{filter}");
        }
    }
}
