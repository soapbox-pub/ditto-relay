# Changelog

Release notes, one section per version. `ngit release publish` takes the
section matching the tag it publishes, so every release needs one here before
it is tagged.

## [2.5.2]

- `ditto-relay salvage` writes every event in a database's records file as
  JSON lines, reading nothing else of the database: for a database whose
  main file is lost or damaged, which can then be stored anew by importing
  them. `--from` begins at a sequence number, as where one stopped.
- `import`, with the relay stopped, keeps 25,000,000 index changes in
  memory before merging them, rather than 1,500,000, and merges them in
  transactions of 250,000.
- Events are stored faster: about 40% more a second, on a third less CPU.
  A new event's signature check, encoding and the read-ahead for the
  writer are done in one trip to the blocking pool rather than three,
  which under a flood of events grew it to hundreds of threads. Queries
  answered while events pour in keep their speed, and a message bigger
  than 64 KiB is parsed off the threads every connection shares. The
  read-ahead itself is only done while the database doesn't fit in
  memory.
- Queries take about 40% less CPU. A query's events are read through one
  cursor, each `EVENT` message is built in one go, and the events queries
  returned lately are kept in memory, up to 128 MiB, so one asked for
  again is neither looked up nor written out anew. Whether it may be
  returned is still decided each time.
- NIP-77 syncs of busy inboxes run about 2.5 times as fast, and COUNTs
  of a tag, with their HyperLogLog sketches, about twice as fast. Each
  event's id, `created_at`, expiration and author are now kept apart from
  it, in a `headers` file in the database's directory, a row for each
  event at a place its sequence number gives, which syncs, sketches and
  `distinct:author` counts read instead of the events. In a database from
  before, or if the file's lost, the writer files the headers of the
  events already stored, the newest first, whenever it has nothing else
  to do; until it's done, those are read as before.
- New events' signatures are checked many at once: BIP-340 batch
  verification, on libsecp256k1's own arithmetic, by a few threads that
  each take every event waiting. A batch that fails is checked a
  signature at a time, so every verdict is libsecp256k1's. Storing a
  flood of events takes about a third less CPU, and the batches made are
  counted in `signature_batches_total` and `signatures_batched_total`.
- The pubkeys that signed events lately are kept parsed, so checking a
  signature by a key that signs often, as Concord's plane keys do, skips
  a tenth of the work.
- The indexes' new entries are kept in memory, and merged into the
  database once 1,500,000 are, in order, rather than put in one by one.
  Storing a flood of events goes about 15% faster on 13% less CPU,
  writes a fifth as much to disk, and leaves a database file an eighth
  the size, in a relay using a quarter of the memory. Queries read the
  entries in memory with those in the database. Each commit's changes
  are kept beside it in a `filed` table until they're merged, and filed
  again in memory if the relay stops before then. The writer merges
  them a slice of about 20,000 at a time between batches of writes, so
  no write waits on a whole merge: the time it takes is
  `writer_phase_seconds_total{phase="merge"}`.
- An event published, with no write policy plugin, goes from the
  connection to the threads checking signatures, to the writer, and back,
  without a task of its own, and the OKs of those stored together are
  sent together: storing a flood of events takes 11% less CPU, and goes
  8% faster.
- The search indexer is handed the events the relay stores rather than
  reading them back from the database, which kept the pages of every one
  in the relay's memory: 100 MB less after storing 200,000 events. It
  keeps up on one thread with 16 MB, rather than four with 64, which it
  takes only to catch up with many events, as when rebuilding.
- Checkpoints are made every second the relay writes, rather than every
  10 seconds: a crash of the machine loses at most about a second of
  writes. Pages LMDB frees can be used again once the next checkpoint is
  durable, so the database's files grew by about as much as was written
  in 10 seconds: after storing a flood of events they're 40% smaller, and
  the relay holds 20% less memory.
- After each checkpoint the relay unmaps the database's pages it has
  mapped in. They stay in the page cache, and are read from there again
  as they're needed; LMDB maps in every page a write copies, so storing
  events alone left all of them counted in the relay's memory: 740 MB
  after storing 200,000 events, 410 MB now.
- Only text that looks like prose has its language and sentiment guessed:
  three words of letters or more, making up at least half of it. In hex,
  base64, JSON and identifiers, whatlang found languages, Welsh most of
  all, often confidently: in recent Dreamith events, the most common after
  English, all of it misread. It's also a third less work.
- Kind 21059, Concord's ephemeral gift wraps, is taken for ciphertext, as
  kind 1059 is: no language or sentiment is guessed of it.
- A new event for a subscription whose stored events are all sent is sent
  to it by the thread that matched it, rather than handed to its
  connection to send: those of an event that 20 subscriptions get are sent
  without waiting on 20 connections to be woken one after another, on
  less CPU. Ephemeral events go to live subscriptions as soon as their
  signatures are checked, without a task of their own.
- New events go out to live subscriptions just before they're committed,
  rather than after: a REQ, COUNT, or NIP-77 sync waits for the commit
  under way, if any, before reading, so none is missed or counted twice.
- A quiet connection holds no read buffer while it waits, and its queues,
  of the events of its subscriptions and the answers to those it
  publishes, hold nothing while they're empty: a connection takes 5 KB of
  memory rather than 27.
- WebSocket connections are the relay's own, rather than tungstenite's,
  through axum: frames are read into one buffer and unmasked in place,
  and what's sent is framed straight into one buffer, an EVENT message's
  JSON copied once, then written at once. Queries take 9-16% less CPU,
  and sending to live subscriptions 4% less.
- The relay allocates memory with mimalloc rather than the C library's
  allocator: the release binaries' musl's is slow with many threads.
  Storing a flood of events goes about 6% faster on 5% less CPU, and
  queries take 11-15% less.
- A stored event's text is checked to be UTF-8 only when it's read, not
  each time the event is, which was about 6% of a query's CPU.

- A write's time is split, in metrics, into reading ahead what storing it
  reads (`write_prefetch_seconds`), waiting in the queue
  (`write_queue_wait_seconds`), and its batch (`write_batch_seconds`). A
  write that takes a second or more is logged, at most every 10 seconds,
  with how long it was queued, the longest thing the writer did meanwhile,
  how long its batch took, and the kinds of the slow writes.
- A COUNT asked for while the same one is running, by any connection,
  waits for it rather than counting again, and one that took a second or
  more is kept for 5 minutes and told to whoever asks for it meanwhile.
  Ditto's chart of each client's users asks every visitor for the same
  `distinct:author` counts, each of which reads hundreds of thousands of
  events. How many COUNTs were answered this way is
  `counts_shared_total`.
- Small queries are answered faster: a REQ that reads up to 128 events, a
  COUNT the database keeps or that sketches up to 1,024 events' authors,
  and the messages of a NIP-77 sync covering up to 4,096 events are
  answered as they arrive, rather than queued for a thread of their own. Looking up an event by id, or the newest of a kind,
  now answers about twice as many requests a second.
- An event sent again once it's stored is recognized sooner, before
  waiting for a thread to check its signature: about twice as many resent
  events are answered a second.
- `ditto-relay repack` no longer fails, leaving the old file in place,
  when the first keys of a table, or all of them, are deleted as it
  copies it, as the records of removed events often are.
- The writer, which stores events one after another, spends about 11%
  less CPU an event, so a relay stores about 10% more events a second.
  The index entries in memory are kept in order only for `facets`, the
  one index read by ranges of keys; the tag keys an event is filed under
  are worked out as it's queued, off the writer; and a tally of each
  tag key's events since the relay started spares looking them up to
  decide whether to start its HyperLogLog sketch. So after a restart, a
  key short of 1,000 events gets its sketch only once 1,000 more come.
- An event's id is hashed with ring's SHA-256, in assembly, rather than
  the sha2 crate's Rust: on processors without SHA instructions, as Intel
  Xeons before Ice Lake are, storing events takes 8% less CPU, and goes
  6% faster.
- Merging the index entries kept in memory into the database puts a
  key's new values in one go, so LMDB finds the key once rather than once
  a value: about 5% more events stored a second.
- Events' records are stored by a thread of their own, in a transaction
  of its own in the records file, as the writer files them in the
  indexes; it commits as it goes, and the writer's commit waits for the
  rest. The writer takes 11% less CPU an event, and with many clients
  sending at once, about 7% more events are stored a second. What's
  committed is as before: an event's record before its indexes, so a
  query never finds the one without the other. A record of a batch that
  then fails may be left past the last event stored, as a crash may
  leave one; it's written over, or dropped on opening.
- The search index's writer keeping up has 64 MiB of memory rather than
  16, so it writes bigger segments, which cost less to merge: storing
  events takes 4% less CPU, and the relay's memory use is no higher.
- The filter that rules out deletions keeps each key's bits in one cache
  line. Its file, `deletions.bloom`, is of another shape, so the first
  start after upgrading builds it anew from the deletions stored; until
  it's done, checking whether an event was deleted searches the
  database.

- LMDB reuses no page freed since the oldest read still open, so while one
  stays open its file grows by every page written. How long each
  environment's oldest read has held pages back is now
  `lmdb_pages_held_seconds`, with `lmdb_open_reads`, and one that has for 10
  minutes or more is logged. A process that dies mid-read, as a
  `ditto-relay` command killed from a shell can, used to leave its slot
  holding pages back until the relay restarted: every minute the relay now
  frees such slots, logs it, and counts them in
  `lmdb_dead_readers_freed_total`.

- `repack` is gentler and faster. It stops copying whenever the relay's
  writer falls behind, and says how long it waited for it: on relay.ditto.pub
  a repack's first minutes held writes up for 25 seconds. It reads ahead on
  32 threads by default rather than 8, and reads a key with many values,
  like `created`'s one, in a piece per 16,384 of them rather than 256 pieces
  in all, most of them empty: copying it went 9 times slower than the table
  before. What a repack cut short left is freed once the relay has opened
  the database, not while it opens it, which took 20 seconds rather than 4.

## [2.5.1]

- The writer says where its time goes, in metrics: how long it spends on
  each kind of work (`writer_phase_seconds_total`), its thread's CPU, in
  user space and the kernel, and how long it's been on what it's doing now
  (`writer_busy_seconds`). Commits and writes are histograms
  (`commit_seconds`, `write_latency_seconds`), so the slowest show. Once the
  writer's been on one thing for 5 seconds, every write waiting, it's
  logged as a warning, naming what, and again every 10 seconds it lasts.
- A NIP-09 deletion of 64 or fewer events and addresses, none of them
  stored, as nearly all are, is done with as it's stored, rather than
  queued and dropped in two commits of their own.
- `ditto-relay free-old` frees the old files `compact` keeps a little at a
  time. Removing them with `rm` held up every write on ZFS for as long as
  freeing hundreds of gigabytes took.
- `ditto-relay repack` compacts the database while the relay runs, the
  indexes or, with `--bodies`, the event records. The relay copies the
  database as it was when the repack began, keeps what it writes meanwhile
  in a journal, and catches the copy up from it. Then it puts the copy in
  place of the old file, its writes waiting about a second, and once the
  reads under way are done with the old file, frees it a little at a time:
  on ZFS, removing hundreds of gigabytes at once held up every write for
  many minutes. It refuses to begin without room for the copy, flushes the
  copy before the writer waits, gives up rather than hold the writer up if
  the copy can't catch up, and holds off sweeps of big deletions meanwhile,
  whose every entry removed it would copy too.
- NIP-09 deletions are removed together. Each was found, then removed, in
  transactions of its own, one a chunk, so a relay sent them faster than a
  chunk a write fell behind, however few events they named; most name
  events it doesn't have. Now a chunk finds and removes as many as fit, in
  one transaction. They take turns with the other deletions, which a stream
  of them used to hold up, since the smallest went first.
- `ditto-relay deletions` says a NIP-09 deletion is waiting its turn, and
  counts its ids and addresses in the singular when there's one.
- Writes no longer stall for tens of seconds once many events have been
  deleted. Storing an event too big for a page, LMDB looked for a run of
  free pages by loading up to 60 more records of its freelist a page,
  scanning all it held after each; in a freelist of scattered single pages,
  as deleting leaves, it never found one, and every write waited. It now
  looks once in what it has loaded, then takes pages from the end of the
  file. LMDB is built from a copy in `vendor/` for this.
- `ditto-relay compact --bodies` compacts the event records too, as it does
  the indexes, keeping the old file as `db/bodies/data.mdb.old`. Deleting
  many events fragments them, and a file written anew, as `compact` wrote
  them for ZFS, kept the fragments as they were.

## [2.5.0]

- A slow deletion no longer holds up the rest. What a deletion removes was
  found one at a time, oldest first, so a deletion by search, which can take
  hours to find its events in a big database, held up every deletion queued
  after it, NIP-09 deletions included. Those of NIP-09 deletions and of
  events a filter picked are found at once now, and a filter's and a
  request to vanish's on threads of their own, neither waiting on the other.
- Of the deletions removed one event at a time, the one with the fewest
  events left goes first, so a NIP-09 deletion of a note never waits behind
  a deletion of thousands.
- `ditto-relay cancel <id>` cancels a queued deletion, leaving the rest
  queued. What it's removed stays removed, and the rest is shown again. One
  sweeping the indexes can't be stopped partway, and says so.
- `ditto-relay delete --ids <file>` deletes the events whose ids are listed,
  a line each, or on stdin with `-`, however many, as one deletion: millions
  of them are swept from each index once, rather than removed one at a time
  in batches small enough for a filter on the command line.

## [2.4.0]

- A better command line. Every command and option has help: `-h` for a
  summary, `--help` or `ditto-relay help <command>` for the whole story, with
  examples. `--version` works, a mistyped command is told what it may have
  meant, and `ditto-relay serve` names running the relay, which is still the
  default. New commands:
  - `ditto-relay deletions` lists the deletions queued and not yet done, from
    `delete`, NIP-09 and NIP-62, with how far removing each has got.
  - `ditto-relay export` writes stored events as JSON lines, every one or what
    a filter matches, in the order they were stored, while the relay runs or
    not.
  - `ditto-relay import` stores events read as JSON lines, from a file or
    stdin, checking their signatures and storing them in order. A running
    relay is sent them, and stores them itself.
  - `ditto-relay config path` says which config file is in use, and
    `ditto-relay config show` prints the settings in effect, defaults filled
    in.
  - `ditto-relay check --json` and `ditto-relay deletions --json`, for scripts.
- Every kind's text is searchable again, as it was before the rewrite, so a
  kind the relay knows nothing of, like a custom NIP (kind 30817), is found
  by its words. Only kinds whose content isn't text are left out: reposts,
  ciphertext, NIP-51 lists and sets, and zap receipts. Of a kind it doesn't
  know, JSON content gives its `name`, `about`, `description` and
  `display_name`, base64 nothing, and anything else its words. `name`,
  `description`, `location` and `about` tags are searchable too.
  **`search_kinds` is gone**, and a config that sets it no longer loads; its
  opposite, `search_excluded_kinds`, lists the kinds left out. The search
  index is rebuilt on upgrade, and whenever `search_excluded_kinds` changes.
- Autocomplete matches every `title`, `name`, `subject` and `d` tag of any
  kind, not only an event's first title, and the `name` in any JSON content,
  such as a NIP-28 channel's.
- Reading ahead no longer deadlocks ZFS. The search indexer and `export`
  asked the kernel to read ahead with `POSIX_FADV_WILLNEED`, whose readahead
  on ZFS (2.4.4 here) takes locks in the opposite order to a write: the
  writer and the indexer each waited on the other, and with them every
  commit to the pool, until the host was rebooted. The bytes are now read
  with `pread` on a thread of their own. Keeping up with new events, a few
  at a time, the indexer no longer reads ahead at all: it read 64 MB past
  them on every commit.
- HTTPS without a reverse proxy. With `[tls] enabled = true`, the relay serves
  `wss://` on `[::]:443` itself, with a certificate for `public_url`'s domain
  from Let's Encrypt (or any ACME CA, by `directory`). It renews the
  certificate with a third of its lifetime left and swaps it in without a
  restart. The CA validates over TLS-ALPN-01 on 443, or HTTP-01 on 80, where
  everything else is redirected to HTTPS. `ditto-relay check` says when the
  certificate expires. The systemd unit grants `CAP_NET_BIND_SERVICE` for the
  two ports.
- Kinds can be kept to the parties to an event again, with `auth_kinds`: only
  its author and the pubkeys it tags may read it, once they've authenticated
  with NIP-42. Filters naming no kinds don't see them, and events asked for by
  id are checked one by one. `auth_kinds` is empty by default, so reads stay
  open to everyone.
  A connection is challenged to authenticate only once it's refused something
  for want of it.
- The relay warns, at startup and in `ditto-relay check`, when its database is
  kept on ZFS in records bigger than LMDB's 4K pages, naming the dataset to
  `zfs set recordsize=4K`. In 16K records, ZFS read a record from disk
  before every page written, and writes were many times slower. After the
  change, `ditto-relay compact` writes `bodies` anew too, so both files get
  the new records.
- `ditto-relay compact` rewrites the database's indexes into a new file,
  holding only what's live, packed in order, with the relay stopped. The old
  file is kept beside it until it's removed. After a big delete, LMDB's file
  stays as big as ever, with what's left scattered through it; packed, far
  more of it stays in memory. It reads on 32 threads, ahead of the copy, as
  `mdb_copy -c` waits on the disk for one page at a time.
- Writes are much faster: commits are no longer flushed to disk one at a
  time, and `lmdb_sync` is gone (a config that sets it still loads). The
  database survives a crash of the machine, on any filesystem, by
  checkpoints: every 10 seconds the relay makes the latest commit durable and
  keeps LMDB from reusing its pages, and when it starts after the machine has
  gone down, it puts the database back as it was at the last one. At most
  about 10 seconds of writes are lost, and when only the relay stopped,
  nothing. The old `lmdb_sync = false` wrote through LMDB's memory map, whose
  pages the kernel writes in any order, and could leave the database
  unreadable. A search index that kept events the database lost is kept,
  rather than rebuilt from nothing, and their sequence numbers aren't given to
  other events.
- Deleting is instant. `ditto-relay delete` returns as soon as the running
  relay has queued the deletion, and what it matches is hidden from clients
  from then on: every event read is checked against the deletions pending,
  in memory. The relay removes the events afterwards, in the background, and
  says how it's going in its log; a queued deletion survives a restart. Only
  events stored before it was asked for are deleted. NIP-09 deletions and
  NIP-62 requests to vanish work the same way, so one by a prolific author no
  longer holds up every write while it's carried out. Counts answered from
  the indexes alone include what's hidden until it's gone.
- `ditto-relay delete` takes any filter a REQ does, search text included,
  and one with a `limit` or `distinct:author` deletes the events it picks as
  of then, by its sort: `sort:top` with a limit deletes the most engaged
  with.
- Big deletions are some hundred times faster to carry out. Of hundreds of
  thousands of events or more, each index is swept once, in order, read
  ahead on many threads, rather than every event taken out of twenty places
  at random; on a copy of a 276-million-event database, its 3 billion index
  entries were swept in about 13 minutes. Smaller ones are removed an event
  at a time, as before.
- Removing no longer holds up the running relay's writes. Each transaction
  is sized to take about 50 ms, by how long the last took, and once the
  relay has written anything, the next waits at least as long, so a busy
  writer spends at most half its time deleting, and an idle one deletes
  flat out. Before, it removed 1,000 events per transaction however long
  that took: in a database with a big freelist, as long as 40 seconds, with
  every write waiting on it.
- A crash could leave the index entries of an event behind after its record
  was removed: the two files commit one after the other. An event's record
  is now removed in a transaction of its own, after its index entries.
- Building the search index reads the records ahead of itself, as it was
  meant to: it asked the kernel for pages at the wrong offsets, and so for
  nothing. The relay finds where LMDB maps its files now.

## [2.3.0]

- The relay makes its own key the first time it starts, in `secret.key` in
  `data_dir` unless `secret_key_file` says otherwise, so NIP-85 assertions,
  trending labels, and NIP-11's `self` work without setting anything up.
  `ditto-relay check` says which key it would use, or that one would be made,
  without making it. **A relay that had no `secret_key_file` now serves all
  three**; `nip85 = false` turns the assertions off, and `trends_interval = 0`
  the labels.
- NIP-11's `software` is the relay's homepage,
  `https://gitworkshop.dev/soapbox.pub/ditto-relay`, as the spec requires,
  rather than its name. `software`, `icon` and `banner` can be set to other
  URLs, or to `""` to leave them out.
- The relay's page sends all three CORS headers NIP-11 requires, and answers
  preflight `OPTIONS` requests, which got a 405.
- The example config sets settings off from their descriptions: settings are
  commented out with `#`, descriptions with `# `, and sections have banners.
  Its `pubkey` is a placeholder rather than a real key.

## [2.2.0]

- NIP-77 negentropy syncing, so strfry (`strfry sync`), `nak sync`, and other
  clients and relays can find which events each side is missing without
  sending them all. It's on by default; `negentropy = false` turns it off,
  and `negentropy_max_events` (1,000,000, as strfry's `maxSyncEvents`) bounds
  how many events one sync may cover. Syncs find their events as a REQ does,
  honoring `since`, `until` and `limit`; search filters can't be synced.
- The negentropy protocol is the relay's own, in `src/negentropy.rs`, ported
  from the `negentropy` crate, which a message of a few bytes could make
  abort the process.
- Arti comes from the head of Soapbox's fork: the guard manager expands its
  sample at most once a second, and the onion service waits at least 10
  seconds before retrying a descriptor upload.

## [2.1.2]

- Clients are pinged every 30 seconds rather than every 60, well under the
  60 seconds nginx waits by default on a quiet connection before closing it.
  A client not heard from in a minute is now dropped.

## [2.1.1]

- The onion service stays reachable. Arti now comes from Soapbox's fork,
  where each descriptor upload waits at least 120 seconds: Arti gave up on
  slow directory relays after 30 and never published to them, so the onion
  dropped out for minutes to an hour at a time, about twenty times a day. The
  fork also makes choosing relays far cheaper in CPU.

## [2.1.0]

- `ditto-relay delete --filter <json> [--age <seconds>] [--dry-run]` removes
  every stored event a filter matches, and drops it from the search index.
  While the relay runs, `delete` asks it, over a Unix socket in the database
  directory, and the relay's own writer removes the events between its other
  writes; a second process asking LMDB for its writer lock could wait on a
  busy relay indefinitely. With the relay stopped, `delete` does it itself,
  holding a lock the relay waits for as it starts. `--dry-run` only reads.
- `ditto-relay check` validates the configuration, and the onion key if Tor
  is on, without starting the relay or opening its database.
- The relay can serve itself as a Tor onion service too, with Tor (Arti)
  built in, by setting `enabled = true` under `[tor]`. The onion's key is a
  file in C Tor's format, so an existing onion's address can be kept, and
  `[tor.service]` and `[tor.arti]` take Arti's own settings. Over Tor the
  landing page and NIP-11 name the onion, AUTH and requests to vanish may name
  it, and the write policy plugin is told `sourceType` `"Tor"`. Over HTTPS,
  the landing page points Tor Browser to the onion with `Onion-Location`.
- The default `log` keeps Tor's routine out of the log.

## [2.0.0]

The first release of Ditto Relay in Rust, rewritten on its own database in
place of the OpenSearch-backed relay that came before it.

- Events are kept as compact binary records in LMDB, with indexes built on its
  sorted duplicate keys, and full-text search runs on Tantivy.
- NIPs 1, 9, 11, 40, 42, 45, 50, 62 and 70. Reads are open to everyone; AUTH
  is only needed to publish NIP-70 protected events.
- NIP-50 search, with the `sort:hot`, `sort:top`, `sort:rising`,
  `sort:controversial` and `sort:zaps` orderings ranked by a web of trust
  seeded from pubkeys of your choosing, and the `autocomplete:`, `language:`,
  `sentiment:`, `media:`, `video:`, `nsfw:`, `protocol:`, `client:`, `tag:`,
  `pow:` and `distinct:author` extensions, each of which a leading `-`
  negates, and negative search terms.
- A `sort:hot` page that the week before its `until` leaves short of its
  limit goes on to the weeks before, each ranked after the last, so a week
  with nothing hot never comes back as an empty page, which clients take for
  the end of what the filter matches.
- NIP-45 `COUNT`, with HyperLogLog sketches for large tags.
- NIP-85 trusted assertions and trending labels, signed by the relay's own
  key.
- Replaceable and addressable events keep the versions they replace.
- strfry-compatible write policy plugins, and Prometheus metrics on an address
  of their own.
- Configuration is a TOML file, named with `--config` or found in
  `~/.config/ditto-relay` or `/etc/ditto-relay`; `ditto-relay.example.toml`
  lists every setting.
- Each release publishes static binaries for x86_64 and aarch64 Linux, and
  `.deb` and `.rpm` packages that install the binary, a systemd unit and
  `/etc/ditto-relay/ditto-relay.toml`, and create the `ditto-relay` user and
  `/var/lib/ditto-relay`.
- The landing page shows the version it is running.
