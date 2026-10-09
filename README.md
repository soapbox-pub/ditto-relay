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

## Installing

Each release publishes static binaries for x86_64 and aarch64 Linux, and `.deb` and
`.rpm` packages, as a [NIP-82](https://github.com/nostr-protocol/nips/blob/master/82.md)
release on Nostr. The packages install the binary, a systemd unit, and
`/etc/ditto-relay/ditto-relay.toml`, and create the `ditto-relay` user and
`/var/lib/ditto-relay`. Set `url` in the config, then:

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
