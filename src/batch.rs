//! Checking many signatures at once: BIP-340 batch verification, in
//! `csrc/schnorr_batch.c`, on libsecp256k1's own arithmetic.
//!
//! One check costs a double multiplication of points, most of it doubling
//! after doubling that every signature pays for anew; a batch shares them,
//! in one multiplication of many points. Each signature still lifts its
//! nonce's point, a square root, but its key's comes parsed, and signatures
//! by one key share its point. A batch that passes means every signature in
//! it is good; one that fails is checked a signature at a time, so every
//! verdict is libsecp256k1's own.

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::LazyLock;

use secp256k1::ffi::CPtr;
use sha2::{Digest, Sha256};

use crate::event::Signed;

unsafe extern "C" {
    fn ditto_schnorrsig_verify_batch(
        sigs: *const u8,
        challenges: *const u8,
        weights: *const u8,
        key_of: *const u32,
        n: usize,
        keys: *const u8,
        m: usize,
    ) -> c_int;
}

/// The fewest signatures checked as a batch rather than one at a time.
pub const MIN_BATCH: usize = 2;

/// BIP-340's challenge hash, its tag hashed in already.
static CHALLENGE: LazyLock<Sha256> = LazyLock::new(|| {
    let tag = Sha256::digest(b"BIP0340/challenge");
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update(tag);
    hash
});

/// Whether each signature is good, as [`Signed::check`] says.
pub fn check_all(signed: &[Signed]) -> Vec<Result<(), String>> {
    if signed.len() >= MIN_BATCH && all_good(signed) {
        return vec![Ok(()); signed.len()];
    }
    signed.iter().map(Signed::check).collect()
}

/// Whether every signature is good, checked as one batch: false if one
/// may not be.
pub fn all_good(signed: &[Signed]) -> bool {
    let n = signed.len();
    if n == 0 {
        return true;
    }
    let mut sigs = Vec::with_capacity(64 * n);
    let mut challenges = Vec::with_capacity(32 * n);
    let mut key_of = Vec::with_capacity(n);
    let mut keys = Vec::new();
    let mut index = HashMap::with_capacity(n);
    for signed in signed {
        let key = *index.entry(signed.x).or_insert_with(|| {
            // SAFETY: a pointer to the parsed key, which outlives the read.
            let point = unsafe { *signed.pubkey.as_c_ptr() };
            keys.extend_from_slice(&point.underlying_bytes());
            (keys.len() / 64 - 1) as u32
        });
        key_of.push(key);
        sigs.extend_from_slice(&signed.sig);
        let mut challenge = CHALLENGE.clone();
        challenge.update(&signed.sig[..32]);
        challenge.update(signed.x);
        challenge.update(signed.id);
        challenges.extend_from_slice(&challenge.finalize());
    }
    // 128 random bits each: a forgery passes with probability 2^-128, and
    // a weight that short splits into one half of the usual two, so its
    // point costs half as much in the multiplication.
    let mut random = vec![0; 16 * (n - 1)];
    if getrandom::fill(&mut random).is_err() {
        return false;
    }
    let mut weights = vec![0; 32 * (n - 1)];
    let (weights_32, _) = weights.as_chunks_mut::<32>();
    for (weight, random) in weights_32.iter_mut().zip(random.as_chunks::<16>().0) {
        weight[16..].copy_from_slice(random);
    }
    // SAFETY: each buffer holds what the function reads of it, for n
    // signatures by keys.len() / 64 keys, every index below that.
    let good = unsafe {
        ditto_schnorrsig_verify_batch(
            sigs.as_ptr(),
            challenges.as_ptr(),
            weights.as_ptr(),
            key_of.as_ptr(),
            n,
            keys.as_ptr(),
            keys.len() / 64,
        )
    };
    good == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tests::signed;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use secp256k1::XOnlyPublicKey;

    /// BIP-340's test vectors of 32-byte messages: public key, message,
    /// signature, whether it verifies.
    const VECTORS: [(&str, &str, &str, bool); 15] = [
        (
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            true,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            true,
        ),
        (
            "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            true,
        ),
        (
            "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            true,
        ),
        (
            "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
            "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
            "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
            true,
        ),
        (
            "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            false,
        ),
        (
            "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            false,
        ),
        (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            false,
        ),
    ];

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    /// A vector as checking it takes, or None if its key isn't one.
    fn vector(i: usize) -> Option<Signed> {
        let (key, msg, sig, _) = VECTORS[i];
        let x = bytes(key);
        Some(Signed {
            id: bytes(msg),
            x,
            pubkey: XOnlyPublicKey::from_byte_array(x).ok()?,
            sig: bytes(sig),
        })
    }

    fn verdicts(signed: &[Signed]) -> Vec<Result<(), String>> {
        signed.iter().map(Signed::check).collect()
    }

    #[test]
    fn says_what_bip340s_vectors_do() {
        let good: Vec<usize> = (0..VECTORS.len()).filter(|&i| VECTORS[i].3).collect();
        for &i in &good {
            assert_eq!(vector(i).unwrap().check(), Ok(()), "{i}");
        }
        // In any order, and twice over.
        let mut batch: Vec<Signed> = good
            .iter()
            .chain(&good)
            .rev()
            .map(|&i| vector(i).unwrap())
            .collect();
        assert!(all_good(&batch));
        for bad in (0..VECTORS.len()).filter(|&i| !VECTORS[i].3) {
            let Some(signed) = vector(bad) else {
                // Refused as it's parsed, before any signature is checked.
                assert!(matches!(bad, 5 | 14), "{bad}");
                continue;
            };
            assert!(signed.check().is_err(), "{bad}");
            for at in [0, 3, batch.len()] {
                batch.insert(at, vector(bad).unwrap());
                assert!(!all_good(&batch), "{bad} at {at}");
                assert_eq!(check_all(&batch), verdicts(&batch), "{bad} at {at}");
                batch.remove(at);
            }
        }
    }

    /// Every way a signature among good ones can be bad fails the batch,
    /// and each is then judged as it would be alone.
    #[test]
    fn fails_a_batch_with_any_bad_signature() {
        let mut rng = StdRng::seed_from_u64(7);
        let events: Vec<_> = (0..120u32)
            .map(|i| {
                signed(
                    (i % 20) as u8 + 1,
                    1_700_000_000 + u64::from(i),
                    1,
                    vec![],
                    &i.to_string(),
                )
            })
            .collect();
        let good: Vec<Signed> = events.iter().map(|ev| ev.signed().unwrap()).collect();
        assert!(all_good(&good));
        assert_eq!(check_all(&good), vec![Ok(()); good.len()]);
        for round in 0..1000 {
            let n = rng.random_range(2..=good.len());
            let mut batch: Vec<Signed> = good[..n].to_vec();
            let i = rng.random_range(0..n);
            match round % 3 {
                0 => {
                    let bit = rng.random_range(0..512);
                    batch[i].sig[bit / 8] ^= 1 << (bit % 8);
                }
                1 => batch[i].sig = good[(i + 1) % good.len()].sig,
                _ => {
                    let other = &good[(i + 1 + rng.random_range(0..19)) % good.len()];
                    if other.x == batch[i].x {
                        continue;
                    }
                    batch[i].x = other.x;
                    batch[i].pubkey = other.pubkey;
                }
            }
            assert!(!all_good(&batch), "round {round}");
            let expected = verdicts(&batch);
            assert!(expected[i].is_err(), "round {round}");
            assert_eq!(check_all(&batch), expected, "round {round}");
        }
    }
}
