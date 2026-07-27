#define _POSIX_C_SOURCE 200809L
#include "api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t rng_state = UINT64_C(0x46535048494e4353);

/* The parallel SPHINCS+ sha2.c MGF helper references this namespaced utility. */
void SPX_u32_to_bytes(unsigned char *out, uint32_t in) {
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

void randombytes(unsigned char *out, size_t outlen) {
    for (size_t i = 0; i < outlen; ++i) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        out[i] = (unsigned char)rng_state;
    }
}

static double seconds_since(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

int main(void) {
    static const uint8_t msg[] =
        "F-SPHINCS+ DAA issuer credential benchmark";
    uint8_t *pk = malloc(FS_PK_BYTES);
    uint8_t *sk = malloc(FS_SK_BYTES);
    uint8_t *sig = malloc(FS_SIG_BYTES);
    size_t siglen = 0;
    struct timespec t0, t1;
    if (!pk || !sk || !sig) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    printf("F-SPHINCS+-SHA256 parameters: n=256 d=%u k=%u q=%u h=%u\n",
           FS_D, FS_K, FS_Q, FS_H);
    printf("sizes: pk=%u B sk=%u B sig=%u B\n",
           FS_PK_BYTES, FS_SK_BYTES, FS_SIG_BYTES);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (fsphincs_keypair(pk, sk) != 0) return 2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("keygen = %.6f s\n", seconds_since(t0, t1));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (fsphincs_sign_signature(sig, &siglen, msg, sizeof(msg) - 1, sk) != 0)
        return 3;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("sign = %.6f s\n", seconds_since(t0, t1));
    if (siglen != FS_SIG_BYTES) return 4;

    fsphincs_profile_reset();
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (fsphincs_verify(sig, siglen, msg, sizeof(msg) - 1, pk) != 0) return 5;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("verify = %.6f ms\n", 1000.0 * seconds_since(t0, t1));
    fsphincs_profile prof;
    fsphincs_profile_get(&prof);
    printf("verify SHA-256 calls: total=%llu compression_blocks=%llu leaf=%llu tree=%llu pad=%llu H2=%llu H3=%llu\n",
           (unsigned long long)prof.total,
           (unsigned long long)prof.compression_blocks,
           (unsigned long long)prof.leaf_hash,
           (unsigned long long)prof.tree_node,
           (unsigned long long)prof.padding_root,
           (unsigned long long)prof.h2,
           (unsigned long long)prof.h3);
    printf("M-FORS layer SHA-256 calls:");
    for (uint32_t layer = 0; layer <= FS_H; ++layer)
        printf(" L%u=%llu", layer,
               (unsigned long long)prof.mfors_layer[layer]);
    printf("\n");
    if (prof.total != 4841 || prof.compression_blocks != 14043 ||
        prof.leaf_hash != 245 ||
        prof.tree_node != 4361 || prof.padding_root != 203 ||
        prof.h2 != 28 || prof.h3 != 4) {
        fprintf(stderr, "unexpected verifier SHA-256 workload\n");
        return 10;
    }
    for (uint32_t layer = 0; layer <= FS_H; ++layer) {
        if (prof.mfors_layer[layer] != 691) {
            fprintf(stderr, "unexpected M-FORS layer workload\n");
            return 11;
        }
    }

    sig[FS_SIG_BYTES / 2] ^= 1;
    if (fsphincs_verify(sig, siglen, msg, sizeof(msg) - 1, pk) == 0) {
        fprintf(stderr, "mutated signature accepted\n");
        return 6;
    }
    sig[FS_SIG_BYTES / 2] ^= 1;
    uint8_t changed_msg[sizeof(msg) - 1];
    memcpy(changed_msg, msg, sizeof(changed_msg));
    changed_msg[0] ^= 1;
    if (fsphincs_verify(sig, siglen, changed_msg, sizeof(changed_msg), pk) == 0) {
        fprintf(stderr, "mutated message accepted\n");
        return 7;
    }
    uint8_t changed_pk[FS_PK_BYTES];
    memcpy(changed_pk, pk, sizeof(changed_pk));
    changed_pk[FS_PK_BYTES - 1] ^= 1;
    if (fsphincs_verify(sig, siglen, msg, sizeof(msg) - 1, changed_pk) == 0) {
        fprintf(stderr, "mutated public key accepted\n");
        return 8;
    }
    if (fsphincs_verify(sig, siglen - 1, msg, sizeof(msg) - 1, pk) == 0) {
        fprintf(stderr, "truncated signature accepted\n");
        return 9;
    }
    printf("round-trip and mutation test: ok\n");
    free(sig); free(sk); free(pk);
    return 0;
}
