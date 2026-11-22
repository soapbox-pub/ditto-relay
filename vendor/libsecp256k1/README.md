# libsecp256k1 internals

The headers of libsecp256k1 as secp256k1-sys 0.14.1 vendors it
(`depend/secp256k1/src` and `include`), copied unchanged, with its licence.
Every symbol carries that crate's `rustsecp256k1_v0_14_` prefix.

`csrc/schnorr_batch.c` includes them for libsecp256k1's field, scalar and
group arithmetic and its multi-scalar multiplication, all `static`, so
nothing it compiles clashes with the library secp256k1-sys links. The
precomputed tables of multiples of G are that library's, found by name, so
`build.rs` compiles with the `ECMULT_WINDOW_SIZE` secp256k1-sys does: they
must agree.

When secp256k1-sys is upgraded, replace these with the new version's: the
prefix changes with it, so a stale copy fails to link rather than run.
