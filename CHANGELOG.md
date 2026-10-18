# Changelog

Release notes, one section per version. `ngit release publish` takes the
section matching the tag it publishes, so every release needs one here before
it is tagged.

## [Unreleased]

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
