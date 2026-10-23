#define _POSIX_C_SOURCE 200809L
#include "api.h"
#include "issuer_anchor.h"

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

/* Generates reproducible benchmark bytes only; never use this RNG in production. */
void randombytes(unsigned char *out, size_t outlen) {
    for (size_t i = 0; i < outlen; ++i) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        out[i] = (unsigned char)rng_state;
    }
}

/* Converts a monotonic clock interval to fractional seconds. */
static double seconds_since(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

/* Measures native operations and checks mutations/root capability outside timings. */
int main(void) {
    uint8_t msg[3u * (FS_SECURITY / 8u)];
    for (size_t i = 0; i < sizeof(msg); ++i) msg[i] = (uint8_t)i;
    uint8_t *pk = malloc(FS_PK_BYTES);
    uint8_t *sk = malloc(FS_SK_BYTES);
    uint8_t *sig = malloc(FS_SIG_BYTES);
    size_t siglen = 0;
    struct timespec t0, t1;
    if (!pk || !sk || !sig) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    printf("F-SPHINCS+ set=" FS_NAME " H1_version=%u node_bytes=%u H3=SHA-%u anchors=%u parameters: seed_bits=256 d=%u k=%u q=%u h=%u\n",
           FS_H1_VERSION, FS_NODE_BYTES, FS_H3_DIGEST_BYTES * 8u, FS_ANCHORS,
           FS_D, FS_K, FS_Q, FS_H);
    printf("sizes: pk=%u B sk=%u B sig=%u B\n",
           FS_PK_BYTES, FS_SK_BYTES, FS_SIG_BYTES);
    printf("leaf_prf_version=%u address_bytes=%u seed_bytes=%u output_bytes=%u pi_i_compressions=%u\n",
           FS_LEAF_PRF_VERSION, FS_LEAF_ADDR_BYTES, FS_N, FS_N, FS_ANCHORS);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (fsphincs_keypair(pk, sk) != 0) return 2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("keygen = %.6f s\n", seconds_since(t0, t1));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (fsphincs_sign_signature(sig, &siglen, msg, sizeof(msg), sk) != 0)
        return 3;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("sign = %.6f s\n", seconds_since(t0, t1));
    if (siglen != FS_SIG_BYTES) return 4;

    fsphincs_profile_reset();
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (fsphincs_verify(sig, siglen, msg, sizeof(msg), pk) != 0) return 5;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("verify = %.9f s\n", seconds_since(t0, t1));
    fsphincs_profile prof;
    fsphincs_profile_get(&prof);
    printf("verify SHA-256 calls: total=%llu compression_blocks=%llu leaf=%llu tree=%llu pad=%llu H2=%llu H3=%llu\n",
           (unsigned long long)prof.total,
           (unsigned long long)prof.compression_blocks,
           (unsigned long long)prof.leaf_hash,
           (unsigned long long)prof.tree_node,
           (unsigned long long)prof.padding_root,
           (unsigned long long)prof.h2,
           (unsigned long long)(FS_SECURITY == 256 ? 0 : prof.h3));
    printf("verify SHA-512 calls: total=%llu compression_blocks=%llu\n",
           (unsigned long long)prof.sha512_calls, (unsigned long long)prof.sha512_compression_blocks);
    printf("M-FORS layer SHA-256 calls:");
    for (uint32_t layer = 0; layer <= FS_H; ++layer)
        printf(" L%u=%llu", layer,
               (unsigned long long)prof.mfors_layer[layer]);
    printf("\n");
    const uint64_t per_layer =
        FS_K + FS_K * FS_D + (FS_AGG_LEAVES - FS_K) +
        (FS_AGG_LEAVES - 1u) + 1u +
        (FS_MFORS_MSG_BYTES + FS_N - 1u) / FS_N;
    const uint64_t expected_leaf = (FS_H + 1u) * FS_K;
    const uint64_t expected_tree =
        (FS_H + 1u) * (FS_K * FS_D + FS_AGG_LEAVES - 1u);
    const uint64_t expected_pad =
        (FS_H + 1u) * (FS_AGG_LEAVES - FS_K);
    const uint64_t expected_h2 =
        (FS_H + 1u) * (1u + (FS_MFORS_MSG_BYTES + FS_N - 1u) / FS_N);
    const uint64_t expected_h3 =
        1u + (FS_H3_BYTES + FS_H3_DIGEST_BYTES - 1u) / FS_H3_DIGEST_BYTES;
    const size_t B = FS_H3_BLOCK_BYTES, pad = FS_SECURITY == 256 ? 17 : 9;
    const size_t prefix = 9 + FS_N + FS_PK_BYTES + FS_H3_DIGEST_BYTES;
    const size_t h3_blocks_count = (9 + FS_N + FS_PK_BYTES + sizeof(msg) + pad + B - 1) / B +
        prefix / B + (expected_h3 - 1) * ((prefix % B + 4 + pad + B - 1) / B);
    const uint64_t expected_blocks =
        1u + expected_leaf + expected_tree * ((16u + 2u * FS_NODE_BYTES + 9u + 63u) / 64u) + expected_pad +
        expected_h2 * 2u + (FS_SECURITY == 256 ? 0 : h3_blocks_count);
    if (prof.total != (FS_H + 1u) * per_layer + (FS_SECURITY == 256 ? 0 : expected_h3) ||
        prof.compression_blocks != expected_blocks ||
        prof.leaf_hash != expected_leaf ||
        prof.tree_node != expected_tree || prof.padding_root != expected_pad ||
        prof.h2 != expected_h2 || prof.h3 != expected_h3 ||
        prof.sha512_calls != (FS_SECURITY == 256 ? expected_h3 : 0) ||
        prof.sha512_compression_blocks != (FS_SECURITY == 256 ? h3_blocks_count : 0)) {
        fprintf(stderr, "unexpected verifier SHA-256 workload\n");
        return 10;
    }
    for (uint32_t layer = 0; layer <= FS_H; ++layer) {
        if (prof.mfors_layer[layer] != per_layer) {
            fprintf(stderr, "unexpected M-FORS layer workload\n");
            return 11;
        }
    }

    /* Exercise exactly the guest's layer-streaming API and compact boundaries. */
    uint8_t streamed[FS_MFORS_MSG_BYTES];
    uint64_t streamed_index;
    fsphincs_hash_context stream_ctx;
    fsphincs_hash_init(&stream_ctx, pk);
    fsphincs_verify_begin(streamed, &streamed_index, sig, msg, sizeof(msg), pk);
    for (uint32_t step = 0; step <= FS_H; ++step) {
        if (fsphincs_verify_layer_ctx(streamed, sig + FS_N + step * FS_MFORS_SIG_BYTES,
                                 &stream_ctx, FS_H - step, streamed_index)) return 20;
        streamed_index /= FS_Q;
        const size_t offsets[] = {
            FS_N + step * FS_MFORS_SIG_BYTES,
            FS_N + step * FS_MFORS_SIG_BYTES + FS_N,
            FS_N + (step + 1u) * FS_MFORS_SIG_BYTES - 1u
        };
        for (size_t j = 0; j < sizeof(offsets) / sizeof(offsets[0]); ++j) {
            sig[offsets[j]] ^= 1;
            if (!fsphincs_verify(sig, siglen, msg, sizeof(msg), pk)) return 21;
            sig[offsets[j]] ^= 1;
        }
    }
    if (fsphincs_verify_finish(streamed, pk)) return 22;
    if (!fsphincs_verify(sig, siglen + 1u, msg, sizeof(msg), pk)) return 23;
#if FS_SECURITY != 256
    if (!fsphincs_verify(sig, FS_N + (FS_H + 1u) * FS_K * (FS_D + 1u) * FS_N,
                         msg, sizeof(msg), pk)) return 24;
#endif
    printf("streaming_and_serialization_test=ok layer_bytes=%u node_bytes=%u\n",
           FS_MFORS_SIG_BYTES, FS_NODE_BYTES);

    sig[FS_SIG_BYTES / 2] ^= 1;
    if (fsphincs_verify(sig, siglen, msg, sizeof(msg), pk) == 0) {
        fprintf(stderr, "mutated signature accepted\n");
        return 6;
    }
    sig[FS_SIG_BYTES / 2] ^= 1;
    sig[0] ^= 1;
    if (fsphincs_verify(sig, siglen, msg, sizeof(msg), pk) == 0) {
        fprintf(stderr, "mutated H3 randomizer accepted\n");
        return 16;
    }
    sig[0] ^= 1;
    uint8_t changed_msg[sizeof(msg)];
    memcpy(changed_msg, msg, sizeof(changed_msg));
    changed_msg[0] ^= 1;
    if (fsphincs_verify(sig, siglen, changed_msg, sizeof(changed_msg), pk) == 0) {
        fprintf(stderr, "mutated message accepted\n");
        return 7;
    }
    uint8_t changed_pk[FS_PK_BYTES];
    memcpy(changed_pk, pk, sizeof(changed_pk));
    changed_pk[FS_PK_BYTES - 1] ^= 1;
    if (fsphincs_verify(sig, siglen, msg, sizeof(msg), changed_pk) == 0) {
        fprintf(stderr, "mutated public key accepted\n");
        return 8;
    }
    if (fsphincs_verify(sig, siglen - 1, msg, sizeof(msg), pk) == 0) {
        fprintf(stderr, "truncated signature accepted\n");
        return 9;
    }
    printf("round-trip and mutation test: ok\n");
    /* Extract S_root, erase the master key, then sign two new messages. */
    const size_t certlen = fsphincs_issuer_anchor_certificate_bytes();
    uint8_t *cert = malloc(certlen);
    uint8_t root_seed[FS_N], addr[FS_ANCHORS * FS_LEAF_ADDR_BYTES], outputs[FS_ANCHORS * FS_N];
    uint8_t lower_seed[FS_N], R[FS_N];
    if (!cert || fsphincs_issuer_anchor_generate(cert, certlen, pk, sk) ||
        fsphincs_issuer_anchor_relation(root_seed, addr, outputs, cert, certlen, pk, sk))
        return 12;
    memset(sk, 0, FS_SK_BYTES);
    if (fsphincs_issuer_anchor_verify(cert, certlen, pk)) return 13;
    cert[8] = FS_SECURITY == 128 ? FS_LEAF_PRF_VERSION : FS_FORMAT_VERSION;
    if (!fsphincs_issuer_anchor_verify(cert, certlen, pk)) return 19;
    cert[8] = FS_CERTIFICATE_VERSION;
    if (!fsphincs_issuer_anchor_verify(cert, certlen - 1, pk) ||
        !fsphincs_issuer_anchor_verify(cert, certlen + 1, pk)) return 17;
    for (size_t i = 0; i < 16; ++i) {
        cert[i] ^= 1;
        if (!fsphincs_issuer_anchor_verify(cert, certlen, pk)) return 18;
        cert[i] ^= 1;
    }
    for (unsigned trial = 0; trial < 2; ++trial) {
        memset(lower_seed, 0x42 + trial, sizeof(lower_seed));
        memset(R, 0xc0 + trial, sizeof(R));
        msg[0] ^= (uint8_t)(0x10 + trial);
        if (fsphincs_sign_with_root_seed(sig, &siglen, msg, sizeof(msg), pk,
                                        root_seed, lower_seed, R) ||
            fsphincs_verify(sig, siglen, msg, sizeof(msg), pk)) return 14;
    }
    for (size_t i = 0; i < certlen; i += 32) {
        cert[i] ^= 1;
        if (!fsphincs_issuer_anchor_verify(cert, certlen, pk)) return 15;
        cert[i] ^= 1;
    }
    printf("root_seed_capability_test=ok fresh_credentials=2 original_master_erased=1 certificate_bytes=%zu\n", certlen);
    free(cert); free(sig); free(sk); free(pk);
    return 0;
}
