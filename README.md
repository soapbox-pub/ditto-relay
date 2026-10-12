# Ditto Relay

A high-performance [Nostr](https://github.com/nostr-protocol/nostr) relay written in
Rust. It runs on its own database: events are kept as compact binary records in
[LMDB](http://www.lmdb.tech/doc/), with indexes built on its sorted duplicate keys,
and full-text search runs on [Tantivy](https://github.com/quickwit-oss/tantivy).

**Up to 5× faster than strfry**, with a 35% smaller database.
[See the benchmarks.](#benchmarks)

- NIPs 1, 9, 11, 40, 42, 45, 50, 62, and 70
- NIP-50 search with `sort:hot`, `sort:top`, and other extensions, ranked by a web of
  trust seeded from pubkeys you choose
- NIP-45 `COUNT`, with HyperLogLog sketches for large tags
- NIP-85 trusted assertions and trending labels, signed by the relay's own key
- strfry-compatible write policy plugins
- Prometheus metrics
- Built-in Tor onion service, off by default

## Installing

Each release publishes static binaries for x86_64 and aarch64 Linux, and `.deb` and
`.rpm` packages, as a [NIP-82](https://github.com/nostr-protocol/nips/blob/master/82.md)
release on Nostr. The packages install the binary, a systemd unit, and
`/etc/ditto-relay/ditto-relay.toml`, and create the `ditto-relay` user and
`/var/lib/ditto-relay`.

Debian and Ubuntu:

```sh
sudo curl -fsSL -o /etc/apt/sources.list.d/ditto-relay.sources https://pkg.soapbox.pub/deb/soapbox.pub/ditto-relay/source
sudo apt update
sudo apt install ditto-relay
```

Fedora and RHEL:

```sh
sudo curl -fsSL -o /etc/yum.repos.d/ditto-relay.repo https://pkg.soapbox.pub/rpm/soapbox.pub/ditto-relay/repo
sudo dnf install ditto-relay
```

Set `url` in `/etc/ditto-relay/ditto-relay.toml`, then:

```sh
sudo systemctl enable --now ditto-relay
```

The relay listens on `127.0.0.1:13131`; put a reverse proxy with TLS in front of it.
[`CHANGELOG.md`](CHANGELOG.md) says what changed in each release.

## Running from source

```sh
cargo build --release
echo 'url = "ws://127.0.0.1:13131"' > ditto-relay.toml
./target/release/ditto-relay --config ditto-relay.toml
```

Configuration is a TOML file, read from the path `--config` names, or else the first
of `~/.config/ditto-relay/ditto-relay.toml` and `/etc/ditto-relay/ditto-relay.toml`.
[`ditto-relay.example.toml`](ditto-relay.example.toml) lists every setting with its
default; only `url` is required. Data is stored in `data_dir`, by default
`~/.local/share/ditto-relay` (`/var/lib/ditto-relay` as root).

## Deleting events

```sh
ditto-relay delete --filter '{"#t":["spam"]}' --dry-run
ditto-relay delete --filter '{"kinds":[1]}' --age 7776000
```

`delete` removes every stored event a NIP-01 filter matches, as `strfry delete` does.
`--age` only removes events at least that many seconds old. `--dry-run` only counts
them. Run it with the relay's own config (as the relay's user) while the relay is
running: it removes events in small transactions between the relay's writes, and the
relay drops them from the search index within a few seconds. Removing an address's
current version also removes its older versions that the filter matches, and the newest
version left becomes current. Nothing stops deleted events from being published again.

## Tor

```toml
[tor]
enabled = true
```

With Tor turned on, the relay is a Tor onion service too. Tor is built in (it's
[Arti](https://arti.torproject.org/)), so there's nothing else to install or
configure. The onion's address is logged at startup, and it answers about a minute
later, once Tor has published it. The key the address is made from is kept in
`data_dir/tor/hs_ed25519_secret_key`, in C Tor's format: back it up to keep the
address, or put an existing onion's `hs_ed25519_secret_key` there to keep that one.
[`ditto-relay.example.toml`](ditto-relay.example.toml) lists the rest of the settings,
including Arti's own.

## Benchmarks

![Ditto Relay vs. strfry. Queries per second: 19,200 vs. 3,700, 5.1× faster. p99 query latency: 4.8 vs. 19.1 ms, 4.0× lower. Publishing: 7,500 vs. 4,200 events/s, 1.8× faster. Importing: 4,500 vs. 3,500 events/s, 1.3× faster.](docs/benchmark.svg)

| | Ditto Relay | strfry | |
| --- | --- | --- | --- |
| Queries/s, 16 connections | 19,200 | 3,700 | **5.1× faster** |
| p99 latency, 16 connections | 4.8 ms | 19.1 ms | **4.0× lower** |
| p99 latency, 1 connection | 1.8 ms | 6.0 ms | **3.4× lower** |
| Queries/s, 1 connection | 4,800 | 1,500 | **3.1× faster** |
| Events/s published to live subscribers | 7,500 | 4,200 | **1.8× faster** |
| Events/s imported | 4,500 | 3,500 | **1.3× faster** |
| Database size | 7.8 GB | 12 GB | **35% smaller** |

Same machine, same clients, 2 million real events and 33,613 real `REQ`s from
relay.ditto.pub, against [strfry](https://github.com/hoytech/strfry) `4cd3cf6`.

## License

[GNU Affero General Public License v3.0 or later](LICENSE).
