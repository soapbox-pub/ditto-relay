# Agent instructions

- **Always commit after making changes.**

## Releasing

A tag `vX.Y.Z` runs `.ngit/act/workflows/release.yml` on ngit-ci, which tests,
builds static binaries for x86_64 and aarch64 with `contrib/release/build.sh`,
packages each as a `.deb` and an `.rpm` with `contrib/package/build.sh`, and
publishes them all as a NIP-82 release with `ngit release publish` (what to
publish is in `.ngit/release.yaml`). Before tagging:

1. Bump `version` in `Cargo.toml`. The workflow refuses a tag that disagrees
   with it, and it is the version NIP-11 and the landing page show.
2. Add a `## [X.Y.Z]` section to `CHANGELOG.md`. It becomes the release notes,
   and the workflow refuses a tag without one.
3. Commit, tag with `git tag -a vX.Y.Z`, and push both.

A tag with a suffix, like `v2.1.0-rc.1`, publishes to the `beta` channel rather
than `main`. Releases are signed by the `NSYTE_BUNKER` session provisioned for
the repository, on the Soapbox key that owns the application.

To build a release by hand, `contrib/release/tools.sh` installs zig,
cargo-zigbuild and nfpm, pinned with their checksums:

```sh
export PATH="$(contrib/release/tools.sh ~/.cache/ditto-relay-release-tools):$PATH"
contrib/release/build.sh dist                  # both architectures, or name one
contrib/package/build.sh 2.0.0 x86_64 dist/ditto-relay-2.0.0-linux-x86_64 dist
```

The packages' install scripts are `contrib/package/*.sh`, each run by both
dpkg and rpm, which pass them different arguments.
