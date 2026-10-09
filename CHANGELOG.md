# Changelog

Release notes, one section per version. `ngit release publish` takes the
section matching the tag it publishes, so every release needs one here before
it is tagged.

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
