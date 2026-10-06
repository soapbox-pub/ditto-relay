//! NIP-50 search, in a tantivy index kept beside the LMDB.
//!
//! The LMDB stays the source of truth. The index holds, for each event of a
//! searchable kind, its sequence number, kind, author, `created_at`, and
//! text; a search finds sequence numbers there and loads the events from
//! the LMDB. Sequence numbers are never reused, so a hit whose event is no
//! longer stored, or has been replaced and kept only as history, is simply
//! skipped: deleting those from the index keeps it small, but nothing
//! depends on it. Old versions are never indexed.
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
//! The other extensions, like `pow:` and `media:`, are [conditions] on the
//! event rather than its text, which the index doesn't hold: hits are
//! checked against them. A search with only those, too, is answered from
//! the LMDB, which indexes them for every kind.
//!
//! [conditions]: crate::facets
//!
//! An autocomplete search looks instead at the names people look things up
//! by — a profile's name, display name, and NIP-05, and any event's title —
//! and its terms, and those it excludes, are prefixes. A search of only
//! kind 0 autocompletes unless it says `autocomplete:false`; any other with
//! `autocomplete:true`. Names are indexed in a field of their own as every
//! prefix of every word, up to [`MAX_PREFIX`] characters, so a prefix is
//! looked up like any term. Names are indexed whatever the kind: the
//! searchable kinds only limit ordinary search.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tantivy::collector::{Collector, Count, DocSetCollector, SegmentCollector, TopDocs};
use tantivy::columnar::Column;
use tantivy::index::SegmentId;
use tantivy::query::{
    BooleanQuery, ConstScoreQuery, Occur, Query, RangeQuery, TermQuery, TermSetQuery,
};
use tantivy::schema::{
    FAST, Field, INDEXED, IndexRecordOption, Schema, TextFieldIndexing, TextOptions,
};
use tantivy::tokenizer::{
    AsciiFoldingFilter, LowerCaser, PreTokenizedString, RemoveLongFilter, SimpleTokenizer,
    TextAnalyzer, Token,
};
use tantivy::{
    DocAddress, DocId, Index, IndexReader, IndexWriter, Order, ReloadPolicy, Score, Searcher,
    SegmentOrdinal, SegmentReader, TantivyDocument, Term,
};
use tokio_util::sync::CancellationToken;

use crate::filter::{Filter, Search, Sort};
use crate::lmdb::Txn;
use crate::query::{MAX_EXAMINED, TooExpensive};
use crate::rank::WALK_BUDGET;
use crate::record::{Content, Element, EventView};
use crate::store::Store;

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

/// The most sequence numbers indexed per commit.
const CATCH_UP_CHUNK: usize = 400_000;

/// How many threads catching up reads records with.
const CATCH_UP_THREADS: u64 = 8;

/// The fewest sequence numbers to catch up with that are split between
/// threads.
const CATCH_UP_SPLIT: u64 = if cfg!(test) { 4 } else { 10_000 };

/// How far ahead of the record it's on catching up reads records, and how
/// far it goes before reading ahead again.
const READ_AHEAD: usize = 64 << 20;

/// The most sequence numbers past the last commit a search checks by hand.
const MAX_UNINDEXED: u64 = 10_000;

/// The most hits one filter may examine, to fill its limit after the
/// fields the index doesn't hold (tags) are checked.
const MAX_HITS: usize = 10_000;

/// How many of a term's hits the index orders or gathers in the time it
/// takes to read and check an event, about.
const HITS_PER_READ: u64 = 500;

/// How many threads one search's segments are searched with.
const SEARCH_THREADS: usize = 8;

/// The share of the index a search's kinds must make up to be checked hit
/// by hit rather than looked up. Any filter a search's terms are looked up
/// with makes the index score every document with them all, where terms
/// alone have the best found by skipping most; one that rules out little
/// isn't worth that.
const CHECKED_KINDS: f64 = 0.5;

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
    let content = view.content().to_text();
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
    let text = text(view);
    // Which of the terms, and of each excluded group's, the text has.
    let mut have = vec![false; terms.len()];
    let mut have_excluded: Vec<Vec<bool>> = excluded
        .iter()
        .map(|group| vec![false; group.len()])
        .collect();
    let mut wanting = terms.len();
    TOKENIZER.with_borrow_mut(|analyzer| {
        let mut stream = analyzer.token_stream(&text);
        while stream.advance() {
            let token = stream.token().text.as_str();
            for (term, have) in terms.iter().zip(&mut have) {
                if !*have && term == token {
                    *have = true;
                    wanting -= 1;
                }
            }
            for (group, have) in excluded.iter().zip(&mut have_excluded) {
                for (term, have) in group.iter().zip(have) {
                    *have |= term == token;
                }
            }
            // Only the rest of the text could bring in an excluded word.
            if wanting == 0 && excluded.is_empty() {
                break;
            }
        }
    });
    wanting == 0
        && !have_excluded
            .iter()
            .any(|group| group.iter().all(|&have| have))
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
/// event's names, and not every term of any group it excludes does.
pub fn matches_prefixes(terms: &[String], excluded: &[Vec<String>], view: &EventView) -> bool {
    if terms.is_empty() && excluded.is_empty() {
        return true;
    }
    let have = tokens(&names(view));
    let begins = |term: &String| have.iter().any(|word| word.starts_with(term.as_str()));
    terms.iter().all(begins) && !excluded.iter().any(|group| group.iter().all(begins))
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
    builder.add_u64_field("kind", INDEXED | FAST);
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
    /// The fast field columns opened, by segment and field, which opening
    /// for every search would cost a good part of it.
    columns: Mutex<HashMap<(SegmentId, &'static str), Column<u64>>>,
}

impl SearchIndex {
    /// Open the index at `dir`, or create it, rebuilding it if it doesn't
    /// belong with `store`. The indexer catches it up once spawned.
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
                Some(p) if p.next_seq <= store_next_seq && index.schema() == schema => {
                    opened = Some((index, p.next_seq));
                }
                _ => {
                    tracing::warn!("rebuilding the search index at {}", dir.display());
                    drop(index);
                    std::fs::remove_dir_all(dir)?;
                }
            }
        }
        let (mut index, next_seq) = match opened {
            Some(opened) => opened,
            None => {
                std::fs::create_dir_all(dir).with_context(|| {
                    format!("Could not create the search index at {}", dir.display())
                })?;
                (Index::create_in_dir(dir, schema.clone())?, 0)
            }
        };
        index.tokenizers().register(ANALYZER, analyzer());
        index.set_multithread_executor(SEARCH_THREADS)?;

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
            columns: Mutex::default(),
        });
        let indexer = Indexer {
            writer: index.writer(WRITER_MEMORY)?,
            search: search.clone(),
            next_seq,
            dirty: false,
        };
        Ok((search, indexer))
    }

    /// Every event stored below this sequence number is searchable.
    pub fn indexed(&self) -> u64 {
        self.indexed.load(Ordering::Acquire)
    }

    /// Limit a search filter to the kinds indexed, so it matches the same
    /// events live as it finds stored. Autocomplete has every kind, and so
    /// does a search with only extensions, which the LMDB answers.
    pub fn restrict(&self, filter: &mut Filter) {
        if filter
            .search
            .as_ref()
            .is_none_or(|search| search.autocomplete || !search.has_text())
        {
            return;
        }
        let kinds: Vec<u16> = match filter.kinds.take() {
            Some(kinds) => kinds
                .into_iter()
                .filter(|kind| self.kinds.binary_search(kind).is_ok())
                .collect(),
            None => self
                .kinds
                .iter()
                .copied()
                .filter(|&kind| filter.wants_kind(kind))
                .collect(),
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

    /// The query for a search filter. With `kinds` false, kinds are left
    /// for the caller to check.
    fn query(&self, filter: &Filter, search: &Search, kinds: bool) -> Box<dyn Query> {
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
            // Prefixes longer than are indexed would exclude words they
            // don't begin: those hits are checked by hand instead.
            if search.autocomplete && group.iter().any(|term| prefix(term) != term) {
                continue;
            }
            let mut terms = group.iter().map(|term| {
                let term = match search.autocomplete {
                    true => Term::from_field_text(f.names, term),
                    false => Term::from_field_text(f.text, term),
                };
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
        if let Some(kinds) = filter.kinds.as_ref().filter(|&k| kinds && *k != self.kinds) {
            let terms = kinds
                .iter()
                .map(|&k| Term::from_field_u64(f.kind, k.into()));
            clauses.push((Occur::Must, any_of(terms.collect())));
        }
        if let Some(authors) = &filter.authors {
            let terms = authors.iter().map(|a| Term::from_field_bytes(f.pubkey, a));
            clauses.push((Occur::Must, any_of(terms.collect())));
        }
        if filter.since > 0 || filter.until < u32::MAX {
            let bound = |t: u32| Bound::Included(Term::from_field_u64(f.created_at, t.into()));
            clauses.push((
                Occur::Must,
                Box::new(RangeQuery::new(bound(filter.since), bound(filter.until))),
            ));
        }
        // A term alone has the best found by skipping blocks of its postings
        // that can't score among them, which a boolean query of one term
        // doesn't do.
        if let [(Occur::Must, _)] = clauses.as_slice() {
            return clauses.pop().expect("a clause").1;
        }
        Box::new(BooleanQuery::new(clauses))
    }

    /// Run a search filter: the best matches by relevance, or with
    /// `sort:new`, the newest, or with a ranked sort, the best
    /// [ranked](crate::rank) of up to [`MAX_HITS`] matches.
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
        if let Some(found) = self.walk_common(store, txn, &searcher, filter, search, limit)? {
            return Ok(found);
        }
        let mut unindexed = unindexed(store, txn, indexed, filter)?;
        // The searcher may have some of those too.
        let mut seen: HashSet<u64> = unindexed.iter().map(|(seq, _)| *seq).collect();
        unindexed.sort_unstable_by(|(_, a), (_, b)| newest_first(a, b));
        // With `distinct:author`, how many authors have been found, which
        // is how many events there are to return.
        let mut authors: HashSet<[u8; 32]> = HashSet::new();
        if search.distinct_author {
            authors.extend(unindexed.iter().map(|(_, view)| *view.pubkey()));
        }

        let checked = self.checked_kinds(&searcher, filter)?;
        let query = self.query(filter, search, checked.is_none());
        let mut columns: HashMap<u32, Column<u64>> = HashMap::new();
        let mut kind_columns: HashMap<u32, Column<u64>> = HashMap::new();
        if search.sort.is_ranked() {
            let count = searcher.search(&query, &Count)?;
            if count <= crate::rank::MAX_CANDIDATES {
                let kinds = checked
                    .as_ref()
                    .map(|kinds| kinds.iter().copied().collect());
                let collector = Seqs { index: self, kinds };
                let mut candidates = searcher.search(&query, &collector)?;
                candidates.extend(seen.iter().copied());
                candidates.sort_unstable();
                candidates.dedup();
                // As many as ranking the newest matches reads.
                let direct = candidates.len().min(MAX_HITS);
                let fill = crate::rank::newest_of(filter, search.distinct_author);
                let cancel = CancellationToken::new();
                let best = crate::rank::best_among(
                    store,
                    txn,
                    filter,
                    &candidates,
                    // Autocomplete prefixes past MAX_PREFIX aren't indexed.
                    !search.autocomplete,
                    direct,
                    &fill,
                    WALK_BUDGET,
                    limit,
                    &cancel,
                )?;
                if let Some(found) = best {
                    return Ok(found);
                }
            }
        }
        let mut hits = Vec::new();
        let mut offset = 0;
        // Ranked searches take every match, up to MAX_HITS, so at once:
        // each page orders every match again.
        let mut page = match search.sort.is_ranked() {
            true => MAX_HITS,
            false => (limit * 2).max(32),
        };
        loop {
            let top = TopDocs::with_limit(page).and_offset(offset);
            // Ranked searches rank every match, so take them newest first.
            let page_hits: Vec<(f32, DocAddress)> = if search.sort != Sort::Relevance {
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
                if let Some(kinds) = &checked
                    && !column_value(self, &searcher, &mut kind_columns, "kind", address)?
                        .is_some_and(|kind| kinds.contains(&kind))
                {
                    continue;
                }
                let Some(seq) = seq_of(self, &searcher, &mut columns, address)? else {
                    continue;
                };
                if !seen.insert(seq) {
                    continue;
                }
                // Gone since, or stored after this snapshot.
                let Some(view) = store.load(txn, seq)? else {
                    continue;
                };
                // Replaced since, and the index not told yet.
                if hit_matches(filter, search, &view) && store.is_current(txn, seq, &view)? {
                    if search.distinct_author {
                        authors.insert(*view.pubkey());
                    }
                    hits.push((score, seq, view));
                }
            }
            offset += count;
            let enough = match (search.sort.is_ranked(), search.distinct_author) {
                (true, _) => false,
                (false, true) => authors.len() >= limit,
                (false, false) => hits.len() + unindexed.len() >= limit,
            };
            if enough || count < page || offset >= MAX_HITS {
                break;
            }
            page = (page * 2).min(MAX_HITS - offset);
        }

        let mut found = unindexed;
        if search.sort.is_ranked() {
            found.extend(hits.into_iter().map(|(_, seq, view)| (seq, view)));
            crate::rank::sort(store, txn, filter, search.sort, &mut found)?;
        } else if search.sort == Sort::New {
            found.extend(hits.into_iter().map(|(_, seq, view)| (seq, view)));
            found.sort_unstable_by(|(_, a), (_, b)| newest_first(a, b));
        } else {
            // Not yet indexed means new, and they have every term: first.
            hits.sort_by(|(x, _, a), (y, _, b)| y.total_cmp(x).then_with(|| newest_first(a, b)));
            found.extend(hits.into_iter().map(|(_, seq, view)| (seq, view)));
        }
        if search.distinct_author {
            let mut authors = HashSet::new();
            found.retain(|(_, view)| authors.insert(*view.pubkey()));
        }
        found.truncate(limit);
        Ok(found)
    }
}

impl SearchIndex {
    /// A segment's fast field column, opened once.
    fn column(&self, segment: &SegmentReader, field: &'static str) -> tantivy::Result<Column<u64>> {
        let key = (segment.segment_id(), field);
        if let Some(column) = self
            .columns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(column.clone());
        }
        let column = segment.fast_fields().u64(field)?;
        let mut columns = self.columns.lock().unwrap_or_else(|e| e.into_inner());
        columns.insert(key, column.clone());
        Ok(column)
    }

    /// Close the columns of segments merged away.
    fn forget_merged(&self) {
        let searcher = self.reader.searcher();
        let live: HashSet<SegmentId> = searcher
            .segment_readers()
            .iter()
            .map(SegmentReader::segment_id)
            .collect();
        let mut columns = self.columns.lock().unwrap_or_else(|e| e.into_inner());
        columns.retain(|(segment, _), _| live.contains(segment));
    }

    /// A `sort:new` or ranked search for words common enough that reading
    /// events newest or best first from the LMDB, checking their text, finds
    /// its matches sooner than looking them up, which orders every match
    /// by time first. None if they aren't, or that doesn't find them within
    /// [`WALK_BUDGET`] events.
    fn walk_common<'t>(
        &self,
        store: &Store,
        txn: &'t Txn,
        searcher: &Searcher,
        filter: &Filter,
        search: &Search,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<(u64, EventView<'t>)>>> {
        if search.sort == Sort::Relevance {
            return Ok(None);
        }
        let field = match search.autocomplete {
            true => self.fields.names,
            false => self.fields.text,
        };
        let mut rarest = u64::MAX;
        for term in &search.terms {
            let term = match search.autocomplete {
                true => prefix(term),
                false => term,
            };
            rarest = rarest.min(searcher.doc_freq(&Term::from_field_text(field, term))?);
        }
        // About how many events are read to find enough, at best, against
        // what the index would read of every match.
        let reads = (limit as u64).saturating_mul(searcher.num_docs() / rarest.max(1));
        if reads > WALK_BUDGET as u64 || reads.saturating_mul(HITS_PER_READ) > rarest {
            return Ok(None);
        }
        let cancel = CancellationToken::new();
        Ok(match search.sort.is_ranked() {
            true => crate::rank::walk_matching(store, txn, filter, limit, WALK_BUDGET, &cancel)?,
            false => crate::query::newest(store, txn, filter, limit, WALK_BUDGET, &cancel)?,
        })
    }

    /// The kinds a search's hits are to be checked against one by one,
    /// rather than looked up with its terms: those of a filter that asks
    /// for kinds making up most of the index.
    fn checked_kinds(
        &self,
        searcher: &Searcher,
        filter: &Filter,
    ) -> anyhow::Result<Option<HashSet<u64>>> {
        let Some(kinds) = filter.kinds.as_ref().filter(|&k| *k != self.kinds) else {
            return Ok(None);
        };
        let mut docs = 0;
        for &kind in kinds {
            docs += searcher.doc_freq(&Term::from_field_u64(self.fields.kind, kind.into()))?;
        }
        let share = docs as f64 / searcher.num_docs().max(1) as f64;
        Ok((share >= CHECKED_KINDS).then(|| kinds.iter().map(|&k| k.into()).collect()))
    }

    /// Add the sequence numbers of every event a search filter matches to
    /// `out`. Fails with [`TooExpensive`] when that's too many to check.
    pub fn collect(
        &self,
        store: &Store,
        txn: &Txn,
        filter: &Filter,
        search: &Search,
        out: &mut HashSet<u64>,
    ) -> anyhow::Result<()> {
        let indexed = self.indexed.load(Ordering::Acquire);
        let searcher = self.reader.searcher();
        out.extend(
            unindexed(store, txn, indexed, filter)?
                .into_iter()
                .map(|(seq, _)| seq),
        );
        let query = self.query(filter, search, true);
        if searcher.search(&query, &Count)? > MAX_EXAMINED {
            return Err(TooExpensive.into());
        }
        let mut columns = HashMap::new();
        for address in searcher.search(&query, &DocSetCollector)? {
            let Some(seq) = seq_of(self, &searcher, &mut columns, address)? else {
                continue;
            };
            if out.contains(&seq) {
                continue;
            }
            if let Some(view) = store.load(txn, seq)?
                && hit_matches(filter, search, &view)
                && store.is_current(txn, seq, &view)?
            {
                out.insert(seq);
            }
        }
        Ok(())
    }
}

/// Collects the sequence numbers of every hit, reading their columns a block
/// of hits at a time; with `kinds`, only of hits of those kinds.
struct Seqs<'a> {
    index: &'a SearchIndex,
    kinds: Option<Arc<[u64]>>,
}

struct SegmentSeqs {
    seq: Column<u64>,
    kind: Option<(Column<u64>, Arc<[u64]>)>,
    seqs: Vec<Option<u64>>,
    kinds: Vec<Option<u64>>,
    found: Vec<u64>,
}

impl Collector for Seqs<'_> {
    type Fruit = Vec<u64>;
    type Child = SegmentSeqs;

    fn for_segment(
        &self,
        _: SegmentOrdinal,
        segment: &SegmentReader,
    ) -> tantivy::Result<SegmentSeqs> {
        let kind = match &self.kinds {
            Some(kinds) => Some((self.index.column(segment, "kind")?, kinds.clone())),
            None => None,
        };
        Ok(SegmentSeqs {
            seq: self.index.column(segment, "seq")?,
            kind,
            seqs: Vec::new(),
            kinds: Vec::new(),
            found: Vec::new(),
        })
    }

    fn requires_scoring(&self) -> bool {
        false
    }

    fn merge_fruits(&self, fruits: Vec<Vec<u64>>) -> tantivy::Result<Vec<u64>> {
        Ok(fruits.concat())
    }
}

impl SegmentCollector for SegmentSeqs {
    type Fruit = Vec<u64>;

    fn collect(&mut self, doc: DocId, _: Score) {
        self.collect_block(&[doc]);
    }

    fn collect_block(&mut self, docs: &[DocId]) {
        self.seqs.resize(docs.len(), None);
        self.seq.first_vals(docs, &mut self.seqs);
        if let Some((column, wanted)) = &self.kind {
            self.kinds.resize(docs.len(), None);
            column.first_vals(docs, &mut self.kinds);
            for (seq, kind) in self.seqs.iter().zip(&self.kinds) {
                if let (Some(seq), Some(kind)) = (seq, kind)
                    && wanted.contains(kind)
                {
                    self.found.push(*seq);
                }
            }
        } else {
            self.found.extend(self.seqs.iter().flatten());
        }
    }

    fn harvest(self) -> Vec<u64> {
        self.found
    }
}

/// The most terms [`any_of`] matches by their postings rather than a set.
const MAX_TERM_UNION: usize = 16;

/// Documents with any of `terms`, unscored. A few are matched by their
/// postings, which a search's own terms, much rarer, skip through; a set
/// query instead reads every posting of every term, millions of them for a
/// common kind, into a bitset first. Many terms are cheaper as a set.
fn any_of(mut terms: Vec<Term>) -> Box<dyn Query> {
    if terms.len() > MAX_TERM_UNION {
        return Box::new(TermSetQuery::new(terms));
    }
    let query: Box<dyn Query> = match terms.len() {
        1 => Box::new(TermQuery::new(terms.remove(0), IndexRecordOption::Basic)),
        _ => Box::new(BooleanQuery::new(
            terms
                .into_iter()
                .map(|term| {
                    let query = TermQuery::new(term, IndexRecordOption::Basic);
                    (Occur::Should, Box::new(query) as Box<dyn Query>)
                })
                .collect(),
        )),
    };
    Box::new(ConstScoreQuery::new(query, 0.0))
}

/// Add to the index every searchable event stored under a sequence number
/// from `start` up to `stop`.
fn index_range(
    store: &Store,
    writer: &IndexWriter,
    search: &SearchIndex,
    start: u64,
    stop: u64,
) -> anyhow::Result<()> {
    let txn = store.read()?;
    let mut cursor = txn.cursor(store.tables.events)?;
    let mut entry = cursor.set_range(&start.to_ne_bytes())?;
    // Where in memory records were last read ahead from.
    let mut read_ahead = 0usize;
    while let Some((key, record)) = entry {
        let seq = u64::from_ne_bytes(key.try_into()?);
        if seq >= stop {
            break;
        }
        let at = record.as_ptr() as usize;
        if at.abs_diff(read_ahead) > READ_AHEAD / 2 {
            store.will_need_records(record, READ_AHEAD);
            read_ahead = at;
        }
        // Old versions, kept as history, aren't searchable.
        if let Some(view) = EventView::new(record)
            && store.is_current(&txn, seq, &view)?
            && let Some(doc) = search.document(seq, &view)
        {
            writer.add_document(doc)?;
        }
        entry = cursor.next()?;
    }
    Ok(())
}

/// The current, unexpired events stored since the index was last committed
/// that a filter matches, checked by hand. Only the newest [`MAX_UNINDEXED`].
fn unindexed<'t>(
    store: &Store,
    txn: &'t Txn,
    indexed: u64,
    filter: &Filter,
) -> anyhow::Result<Vec<(u64, EventView<'t>)>> {
    let next_seq = store.next_seq(txn)?;
    let mut found = Vec::new();
    let mut cursor = txn.cursor(store.tables.events)?;
    let start = indexed.max(next_seq.saturating_sub(MAX_UNINDEXED));
    let now = crate::event::now();
    let mut entry = cursor.set_range(&start.to_ne_bytes())?;
    while let Some((key, record)) = entry {
        let seq = u64::from_ne_bytes(key.try_into()?);
        if let Some(view) =
            EventView::new(record).filter(|view| !view.is_expired(now) && filter.matches(view))
            && store.is_current(txn, seq, &view)?
        {
            found.push((seq, view));
        }
        entry = cursor.next()?;
    }
    Ok(found)
}

/// The sequence number of a hit, looking each segment's column up once.
fn seq_of(
    index: &SearchIndex,
    searcher: &Searcher,
    columns: &mut HashMap<u32, Column<u64>>,
    address: DocAddress,
) -> anyhow::Result<Option<u64>> {
    column_value(index, searcher, columns, "seq", address)
}

/// A hit's value of the fast field `field`, looking each segment's column
/// up once.
fn column_value(
    index: &SearchIndex,
    searcher: &Searcher,
    columns: &mut HashMap<u32, Column<u64>>,
    field: &'static str,
    address: DocAddress,
) -> anyhow::Result<Option<u64>> {
    let column = match columns.entry(address.segment_ord) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(index.column(searcher.segment_reader(address.segment_ord), field)?)
        }
    };
    Ok(column.first(address.doc_id))
}

/// Whether a hit matches the rest of its filter. Autocomplete terms may be
/// longer than what's indexed, so those are checked too.
fn hit_matches(filter: &Filter, search: &Search, view: &EventView) -> bool {
    match search.autocomplete {
        true => filter.matches(view),
        false => filter.matches_fields(view),
    }
}

/// Newest first; on a tie, the lowest id first (NIP-01).
pub fn newest_first(a: &EventView, b: &EventView) -> std::cmp::Ordering {
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
    /// Index what's been stored since last time, up to `max` sequence
    /// numbers' worth. Returns whether there's more.
    ///
    /// Many are read [`CATCH_UP_THREADS`] at a time, each a share of them:
    /// records are mostly out of memory when rebuilding, and one thread
    /// waits on the disk for each page in turn.
    pub fn catch_up(&mut self, store: &Store, max: usize) -> anyhow::Result<bool> {
        let end = store.next_seq(&*store.read()?)?;
        let from = self.next_seq;
        let to = end.min(from.saturating_add(max as u64));
        let threads = match to - from >= CATCH_UP_SPLIT {
            true => CATCH_UP_THREADS,
            false => 1,
        };
        let share = (to - from).div_ceil(threads);
        let (writer, search) = (&self.writer, &*self.search);
        std::thread::scope(|scope| {
            let shares: Vec<_> = (0..threads)
                .map(|n| from + n * share)
                .take_while(|&start| start < to)
                .map(|start| {
                    let stop = (start + share).min(to);
                    scope.spawn(move || index_range(store, writer, search, start, stop))
                })
                .collect();
            shares
                .into_iter()
                .try_for_each(|share| share.join().expect("an indexing thread panicked"))
        })?;
        self.dirty |= to != from;
        self.next_seq = to;
        Ok(to < end)
    }

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
            next_seq: self.next_seq,
        };
        let mut commit = self.writer.prepare_commit()?;
        commit.set_payload(&serde_json::to_string(&payload)?);
        commit.commit()?;
        self.search.reader.reload()?;
        self.search.forget_merged();
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
    use crate::store::tests::{MAX_VALUES, open, put, test_tags};
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
            let mut filter = Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap();
            assert!(filter.search.is_some());
            self.index.restrict(&mut filter);
            crate::query::run(
                &self.store,
                Some(&self.index),
                None,
                &[filter],
                100,
                500,
                &Default::default(),
            )
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
    fn checks_extensions() {
        let mut f = fixture();
        let pic = |seed, at, kind, content| {
            let tags = vec![vec!["imeta", "url https://x.com/a.png", "m image/png"]];
            signed(seed, at, kind, tags, content)
        };
        let cat = pic(1, 100, 1, "my cat");
        let words = signed(2, 200, 1, vec![], "my cat in words");
        let dog = pic(2, 300, 1, "my dog");
        let reaction = pic(3, 400, 7, "+");
        let newer_cat = pic(1, 500, 1, "cat again");
        for event in [&cat, &words, &dog, &reaction] {
            put(&f.store, event);
        }
        f.index_all();
        // Not yet indexed.
        put(&f.store, &newer_cat);
        let ids =
            |events: &[&Event]| -> Vec<String> { events.iter().map(|e| e.id.clone()).collect() };

        assert_eq!(
            f.search(json!({"search": "cat media:true sort:new"})),
            ids(&[&newer_cat, &cat])
        );
        assert_eq!(
            f.search(json!({"search": "cat -media:true"})),
            ids(&[&words])
        );
        // Without text: from the LMDB, newest first, of any kind.
        assert_eq!(
            f.search(json!({"search": "media:true"})),
            ids(&[&newer_cat, &reaction, &dog, &cat])
        );
        assert_eq!(
            f.search(json!({"search": "media:true", "kinds": [1], "limit": 2})),
            ids(&[&newer_cat, &dog])
        );
        // The newest of each author.
        assert_eq!(
            f.search(json!({"search": "media:true distinct:author", "kinds": [1]})),
            ids(&[&newer_cat, &dog])
        );
        assert_eq!(
            f.search(json!({"search": "my distinct:author sort:new"})),
            ids(&[&dog, &cat])
        );
    }

    #[test]
    fn ranks_matches() {
        let mut f = fixture();
        let one = signed(1, 100, 1, vec![], "cat one");
        let two = signed(1, 300, 1, vec![], "cat two");
        let three = signed(2, 200, 1, vec![], "cat three");
        let dog = signed(2, 400, 1, vec![], "dog");
        let react = |seed, to: &Event| signed(seed, 500, 7, vec![vec!["e", &to.id]], "+");
        for event in [&one, &two, &three, &dog] {
            put(&f.store, event);
        }
        for event in [
            react(3, &one),
            react(4, &one),
            react(3, &three),
            react(3, &dog),
        ] {
            put(&f.store, &event);
        }
        f.index_all();
        // Not yet indexed, and more engaged with than any.
        let four = signed(3, 50, 1, vec![], "cat four");
        put(&f.store, &four);
        for seed in 4..7 {
            put(&f.store, &react(seed, &four));
        }
        let ids =
            |events: &[&Event]| -> Vec<String> { events.iter().map(|e| e.id.clone()).collect() };
        assert_eq!(
            f.search(json!({"search": "cat sort:top"})),
            ids(&[&four, &one, &three, &two])
        );
        assert_eq!(
            f.search(json!({"search": "cat sort:top distinct:author", "limit": 2})),
            ids(&[&four, &one])
        );
        // Only the argued over are controversial; the rest, newest first.
        let reply = signed(7, 600, 1, vec![vec!["e", &two.id, "", "root"]], "no");
        put(&f.store, &reply);
        put(&f.store, &react(8, &two));
        assert_eq!(
            f.search(json!({"search": "cat sort:controversial"})),
            ids(&[&two, &three, &one, &four])
        );
    }

    #[test]
    fn counts_searches() {
        let mut f = fixture();
        let hello = signed(1, 100, 1, vec![vec!["t", "x"]], "hello world");
        let bitcoin = signed(2, 200, 1, vec![], "hello bitcoin");
        let reaction = signed(2, 200, 7, vec![], "hello");
        for event in [&hello, &bitcoin, &reaction] {
            put(&f.store, event);
        }
        f.index_all();
        put(&f.store, &signed(3, 300, 1, vec![], "hello again"));
        let count = |filter: serde_json::Value| {
            let mut filter = Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap();
            f.index.restrict(&mut filter);
            crate::query::count(&f.store, Some(&f.index), &[filter], &Default::default())
                .unwrap()
                .count
        };
        // Indexed or not yet, but only the searchable kinds.
        assert_eq!(count(json!({"search": "hello"})), 3);
        assert_eq!(count(json!({"search": "hello -bitcoin"})), 2);
        assert_eq!(count(json!({"search": "hello", "#t": ["x"]})), 1);
        assert_eq!(count(json!({"search": "-bitcoin"})), 2);
        assert_eq!(count(json!({"search": "hello", "since": 150})), 2);
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
            .write_batch([record::encode(&new).as_slice()], 0)
            .unwrap();
        // History now, so gone from results before the index hears of it.
        assert!(f.search(json!({"search": "old"})).is_empty());
        assert_eq!(batch.removed, [1]);
        f.indexer.remove(&batch.removed);
        f.index_all();
        assert!(f.search(json!({"search": "old"})).is_empty());
        assert_eq!(f.search(json!({"search": "new"})), [new.id.as_str()]);
        let searcher = f.index.reader.searcher();
        assert_eq!(searcher.num_docs(), 1);

        // An older version arriving late is history from the start: never
        // searchable, indexed or not.
        let older = signed(1, 50, 0, vec![], &json!({"name": "older"}).to_string());
        assert_eq!(put(&f.store, &older), crate::store::Outcome::Archived(3));
        assert!(f.search(json!({"search": "older"})).is_empty());
        f.index_all();
        assert!(f.search(json!({"search": "older"})).is_empty());
        assert_eq!(f.index.reader.searcher().num_docs(), 1);
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
        drop((index, db));
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
        // Exclusions are prefixes of names too.
        assert_eq!(f.search(autocomplete("ali -won")), [ali.id.as_str()]);
        assert_eq!(f.search(autocomplete("ali -wonderlands")).len(), 2);
        assert_eq!(f.search(autocomplete("ali -alice-fan")), [ali.id.as_str()]);
        // Profiles autocomplete unless told not to.
        let profiles = |text: &str| json!({"search": text, "kinds": [0]});
        assert_eq!(f.search(profiles("jac")), [jack.id.as_str()]);
        assert!(f.search(profiles("bitcoin")).is_empty());
        assert_eq!(f.search(profiles("bitcoin autocomplete:false")).len(), 3);
        assert!(f.search(profiles("jac autocomplete:false")).is_empty());

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
        let excluding = |rest: &str| f.search(autocomplete(&format!("sup -{rest}")));
        assert!(excluding("supercalifragilisticexpi").is_empty());
        assert_eq!(excluding("supercalifragilisticky"), [long.id.as_str()]);

        // Any kind, indexed or not yet.
        let settings = signed(
            6,
            100,
            30078,
            vec![vec!["d", "c"], vec!["title", "Bicycles"]],
            "",
        );
        put(&f.store, &settings);
        let bicy = |f: &Fixture| f.search(autocomplete("bicy")).len();
        assert_eq!(bicy(&f), 2);
        f.index_all();
        assert_eq!(bicy(&f), 2);
        let both = json!({"search": "bicy autocomplete:true", "kinds": [30078, 30402]});
        assert_eq!(f.search(both).len(), 2);
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
        let records: Vec<Vec<u8>> = all.iter().map(record::encode).collect();

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
            // Nothing's engaged with, so ranked is newest first too.
            let sort = ["sort:new", "sort:hot", "sort:top"][rng.random_range(0..3)];
            let mut extensions = match autocomplete {
                true => format!("{sort} autocomplete:true"),
                false => sort.to_string(),
            };
            if rng.random_bool(0.3) {
                let conditions = [
                    "tag:t",
                    "-tag:title",
                    "sentiment:neutral",
                    "-sentiment:neutral",
                    "language:en",
                    "distinct:author",
                ];
                extensions.push(' ');
                extensions.push_str(conditions[rng.random_range(0..conditions.len())]);
            }
            let mut filter = serde_json::Map::new();
            filter.insert(
                "search".into(),
                json!(format!("{} {extensions}", terms.join(" "))),
            );
            if rng.random_bool(0.3) {
                filter.insert("authors".into(), json!(pubkeys[..rng.random_range(1..3)]));
            }
            if rng.random_bool(0.4) {
                // Most of the index, checked hit by hit, or a little,
                // looked up.
                let kinds = match rng.random_range(0..4) {
                    3 => vec![1, 30023],
                    n => vec![KINDS[n]],
                };
                filter.insert("kinds".into(), json!(kinds));
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

            let mut parsed = Filter::parse(&filter, &test_tags(), MAX_VALUES).unwrap();
            f.index.restrict(&mut parsed);
            let mut expected: Vec<&Event> = all
                .iter()
                .zip(&records)
                .filter(|(_, record)| parsed.matches(&EventView::new(record).unwrap()))
                .map(|(e, _)| e)
                .collect();
            expected.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            if parsed.search.as_ref().unwrap().distinct_author {
                let mut authors = HashSet::new();
                expected.retain(|e| authors.insert(e.pubkey.clone()));
            }
            let expected: Vec<&str> = expected.iter().take(limit).map(|e| e.id.as_str()).collect();
            assert_eq!(f.search(filter.clone()), expected, "{filter}");
        }
    }
}
