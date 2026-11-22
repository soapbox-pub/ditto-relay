//! Compiles BIP-340 batch verification, `csrc/schnorr_batch.c`, on the
//! libsecp256k1 internals in `vendor/libsecp256k1`.

fn main() {
    println!("cargo:rerun-if-changed=csrc/schnorr_batch.c");
    println!("cargo:rerun-if-changed=vendor/libsecp256k1");
    cc::Build::new()
        .file("csrc/schnorr_batch.c")
        .include("vendor/libsecp256k1")
        .include("vendor/libsecp256k1/include")
        .include("vendor/libsecp256k1/src")
        // As secp256k1-sys builds the library whose tables of multiples of
        // G this reads.
        .define("ECMULT_WINDOW_SIZE", Some("15"))
        // Arithmetic, too slow unoptimized for even the tests.
        .opt_level(3)
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter")
        .compile("schnorr_batch");
}
