#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"
#ifdef DAA_BENCH_FSPHINCS
#include "issuer_anchor.h"
#else
#include "params.h"
#endif

static uint64_t rng = UINT64_C(0x44aa7213);

// Supplies reproducible randomness for credential benchmarks.
void randombytes(unsigned char *out, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        out[i] = (unsigned char)rng;
    }
}

#ifdef DAA_BENCH_FSPHINCS
// Encodes addresses used by the native SHA-2 implementation.
void SPX_u32_to_bytes(unsigned char *out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) out[i] = (unsigned char)(value >> (24 - 8 * i));
}
#endif

// Reads a monotonic timestamp in milliseconds.
static double milliseconds(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) abort();
    return (double)time.tv_sec * 1000.0 + (double)time.tv_nsec / 1000000.0;
}

// Measures credential KeyGen, signing, and verification without regression workloads.
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    char *end;
    unsigned long iterations = strtoul(argv[1], &end, 10);
    if (!iterations || *end) return 1;
#ifdef DAA_BENCH_FSPHINCS
    const size_t pk_bytes = FS_PK_BYTES, sk_bytes = FS_SK_BYTES, sig_bytes = FS_SIG_BYTES;
    const size_t message_bytes = 3u * (FS_SECURITY / 8u);
    size_t certificate_bytes = fsphincs_issuer_anchor_certificate_bytes();
    uint8_t *certificate = malloc(certificate_bytes);
    uint8_t witness[FS_N], addresses[FS_ANCHORS * FS_LEAF_ADDR_BYTES];
    uint8_t anchors[FS_ANCHORS * FS_LEAF_BYTES];
    if (!certificate) return 2;
#else
    const size_t pk_bytes = SPX_PK_BYTES, sk_bytes = SPX_SK_BYTES, sig_bytes = SPX_BYTES;
    const size_t message_bytes = 3u * SPX_N;
#endif
    uint8_t *pk = malloc(pk_bytes), *sk = malloc(sk_bytes), *sig = malloc(sig_bytes);
    uint8_t *message = malloc(message_bytes);
    if (!pk || !sk || !sig || !message) return 2;
    memset(message, 0x5c, message_bytes);
    double keygen = 0, sign = 0, verify = 0;
    for (unsigned long i = 0; i < iterations; ++i) {
        size_t length = 0;
        double started = milliseconds();
#ifdef DAA_BENCH_FSPHINCS
        if (fsphincs_issuer_keypair(pk, sk, certificate, certificate_bytes) ||
            fsphincs_issuer_anchor_relation(witness, addresses, anchors,
                certificate, certificate_bytes, pk, sk)) return 3;
#else
        if (crypto_sign_keypair(pk, sk)) return 3;
#endif
        keygen += milliseconds() - started;
        started = milliseconds();
#ifdef DAA_BENCH_FSPHINCS
        if (fsphincs_sign_signature(sig, &length, message, message_bytes, sk)) return 4;
#else
        if (crypto_sign_signature(sig, &length, message, message_bytes, sk)) return 4;
#endif
        sign += milliseconds() - started;
        if (length != sig_bytes) return 4;
        started = milliseconds();
#ifdef DAA_BENCH_FSPHINCS
        if (fsphincs_verify(sig, length, message, message_bytes, pk)) return 5;
#else
        if (crypto_sign_verify(sig, length, message, message_bytes, pk)) return 5;
#endif
        verify += milliseconds() - started;
    }
    printf("keygen_ms=%.6f\nsign_ms=%.6f\nverify_ms=%.6f\n", keygen / iterations, sign / iterations, verify / iterations);
    printf("public_key_bytes=%zu\nsecret_key_bytes=%zu\nsignature_bytes=%zu\nmessage_bytes=%zu\n", pk_bytes, sk_bytes, sig_bytes, message_bytes);
#ifdef DAA_BENCH_FSPHINCS
    printf("keygen_includes_public_certificate=1\npublic_certificate_bytes=%zu\n", certificate_bytes);
    free(certificate);
#else
    printf("keygen_includes_public_certificate=0\n");
#endif
    free(message); free(sig); free(sk); free(pk);
    return 0;
}
