/* BIP-340 batch verification, on libsecp256k1's field, group and
 * multi-scalar arithmetic: see vendor/libsecp256k1/README.md.
 *
 * A batch of n signatures by m keys is valid if
 *
 *     (sum a_i s_i) G - sum a_i R_i - sum_k (sum_{i by k} a_i e_i) P_k
 *         = infinity
 *
 * for weights a_i, a_0 = 1 and the rest random and secret: R_i the point
 * with x r_i and even y, P_k the key's point, e_i the challenge. If any
 * signature is invalid the sum is infinity with probability about 2^-128
 * over the weights, which its signer can't know. So a valid batch means
 * every signature is; one that isn't, or that has a signature that doesn't
 * parse, says nothing about which, and the caller checks each. */

#define SECP256K1_BUILD

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/secp256k1.h"
#include "assumptions.h"
#include "util.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "int128_impl.h"
#include "scratch_impl.h"

typedef struct {
    const rustsecp256k1_v0_14_ge *points;
    const rustsecp256k1_v0_14_scalar *scalars;
} batch_points;

static int batch_point(rustsecp256k1_v0_14_scalar *sc, rustsecp256k1_v0_14_ge *pt, size_t idx, void *data) {
    const batch_points *batch = (const batch_points *)data;
    *sc = batch->scalars[idx];
    *pt = batch->points[idx];
    return 1;
}

static void batch_error(const char *str, void *data) {
    (void)str;
    (void)data;
}

/* Whether all `n` signatures are valid. `sigs` are 64 bytes each,
 * `challenges` each one's BIP-340 challenge hash, `weights` 32 random bytes
 * for each but the first, and `key_of` the index among the `m` `keys` of
 * the one it's by: each a parsed x-only pubkey, libsecp256k1's 64 bytes
 * of its point. 1 if they are; 0 if one may not be, or memory ran out. */
int ditto_schnorrsig_verify_batch(
    const unsigned char *sigs,
    const unsigned char *challenges,
    const unsigned char *weights,
    const uint32_t *key_of,
    size_t n,
    const unsigned char *keys,
    size_t m
) {
    const rustsecp256k1_v0_14_callback callback = { batch_error, NULL };
    rustsecp256k1_v0_14_ge *points;
    rustsecp256k1_v0_14_scalar *scalars;
    rustsecp256k1_v0_14_scalar g_scalar;
    rustsecp256k1_v0_14_scratch scratch;
    rustsecp256k1_v0_14_gej sum;
    batch_points batch;
    size_t i, size, total;
    int ok = 1;

    if (n == 0) {
        return 1;
    }
    if (m == 0 || m > n || n > SIZE_MAX / 2 / sizeof(rustsecp256k1_v0_14_ge)) {
        return 0;
    }
    total = n + m;
    points = (rustsecp256k1_v0_14_ge *)malloc(total * sizeof(*points));
    scalars = (rustsecp256k1_v0_14_scalar *)malloc(total * sizeof(*scalars));
    if (points == NULL || scalars == NULL) {
        free(points);
        free(scalars);
        return 0;
    }
    /* Points 0..n are the R_i, n..n+m the keys. */
    for (i = 0; i < m; i++) {
        rustsecp256k1_v0_14_ge_from_bytes(&points[n + i], &keys[64 * i]);
        rustsecp256k1_v0_14_scalar_set_int(&scalars[n + i], 0);
    }
    rustsecp256k1_v0_14_scalar_set_int(&g_scalar, 0);
    for (i = 0; i < n; i++) {
        const unsigned char *sig = &sigs[64 * i];
        rustsecp256k1_v0_14_fe rx;
        rustsecp256k1_v0_14_scalar s, e, a;
        int overflow;

        if (key_of[i] >= m) {
            ok = 0;
            break;
        }
        /* As schnorrsig_verify refuses them. */
        if (!rustsecp256k1_v0_14_fe_set_b32_limit(&rx, &sig[0])
            || !rustsecp256k1_v0_14_ge_set_xo_var(&points[i], &rx, 0)) {
            ok = 0;
            break;
        }
        rustsecp256k1_v0_14_scalar_set_b32(&s, &sig[32], &overflow);
        if (overflow) {
            ok = 0;
            break;
        }
        /* The challenge modulo the order, as BIP-340 has it. */
        rustsecp256k1_v0_14_scalar_set_b32(&e, &challenges[32 * i], NULL);
        if (i == 0) {
            rustsecp256k1_v0_14_scalar_set_int(&a, 1);
        } else {
            rustsecp256k1_v0_14_scalar_set_b32(&a, &weights[32 * (i - 1)], NULL);
            if (rustsecp256k1_v0_14_scalar_is_zero(&a)) {
                ok = 0;
                break;
            }
        }
        rustsecp256k1_v0_14_scalar_mul(&s, &s, &a);
        rustsecp256k1_v0_14_scalar_add(&g_scalar, &g_scalar, &s);
        rustsecp256k1_v0_14_scalar_negate(&scalars[i], &a);
        rustsecp256k1_v0_14_scalar_mul(&e, &e, &a);
        rustsecp256k1_v0_14_scalar_negate(&e, &e);
        rustsecp256k1_v0_14_scalar_add(&scalars[n + key_of[i]], &scalars[n + key_of[i]], &e);
    }
    if (ok) {
        size = rustsecp256k1_v0_14_strauss_scratch_size(total)
            + rustsecp256k1_v0_14_pippenger_scratch_size(total, rustsecp256k1_v0_14_pippenger_bucket_window(total))
            + 64 * ALIGNMENT;
        memcpy(scratch.magic, "scratch", 8);
        scratch.data = malloc(size);
        scratch.alloc_size = 0;
        scratch.max_size = size;
        batch.points = points;
        batch.scalars = scalars;
        ok = rustsecp256k1_v0_14_ecmult_multi_var(
            &callback,
            scratch.data == NULL ? NULL : &scratch,
            &sum,
            &g_scalar,
            batch_point,
            &batch,
            total
        ) && rustsecp256k1_v0_14_gej_is_infinity(&sum);
        free(scratch.data);
    }
    free(points);
    free(scalars);
    return ok;
}
