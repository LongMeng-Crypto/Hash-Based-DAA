#include "api.h"
#include "issuer_anchor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sha256(uint8_t *, const uint8_t *, size_t);

/* KAT generation must never use an implicit random source. */
void randombytes(unsigned char *out, size_t len) {
    (void)out; (void)len; abort();
}

/* Supplies the parallel SHA library's namespaced MGF utility. */
void SPX_u32_to_bytes(unsigned char *out, uint32_t in) {
    for (unsigned i = 0; i < 4; ++i) out[i] = (uint8_t)(in >> (24 - 8*i));
}

/* Emits one deterministic binary fixture in a portable, unambiguous encoding. */
static void hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s=", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    puts("");
}

/* Emits a compact fingerprint for the committed KAT manifest. */
static void fingerprint(const char *label, const uint8_t *data, size_t len) {
    uint8_t digest[32];
    sha256(digest, data, len);
    hex(label, digest, sizeof(digest));
}

/* Exercises deterministic keys, H3 boundaries, signatures and root certificates. */
int main(void) {
    const uint8_t message[] = "F-SPHINCS+ deterministic format-v3 KAT";
    uint8_t seed[FS_SEED_BYTES], R[FS_N], pk[FS_PK_BYTES], sk[FS_SK_BYTES];
    uint8_t layers[(FS_H + 1) * FS_MFORS_MSG_BYTES], root_seed[FS_N];
    uint8_t addr[FS_ANCHORS * FS_N], outputs[FS_ANCHORS * FS_N];
    uint8_t *sig = malloc(FS_SIG_BYTES);
    const size_t clen = fsphincs_issuer_anchor_certificate_bytes();
    uint8_t *cert = malloc(clen);
    size_t siglen = 0;
    uint64_t index = 0;
    if (!sig || !cert) return 1;
    for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(R); ++i) R[i] = (uint8_t)(0xa0+i);
    if (fsphincs_seed_keypair(pk, sk, seed) ||
        fsphincs_sign_signature_with_randomizer(sig, &siglen, message,
            sizeof(message)-1, sk, R) ||
        siglen != FS_SIG_BYTES ||
        fsphincs_trace_signature(layers, &index, sig, siglen, message,
            sizeof(message)-1, pk) ||
        fsphincs_verify(sig, siglen, message, sizeof(message)-1, pk) ||
        fsphincs_issuer_anchor_generate(cert, clen, pk, sk) ||
        fsphincs_issuer_anchor_relation(root_seed, addr, outputs, cert, clen, pk, sk))
        return 2;
    printf("parameter=%s\n", FS_NAME);
    fingerprint("kat_pk", pk, sizeof(pk));
    fingerprint("kat_sk", sk, sizeof(sk));
    fingerprint("kat_signature", sig, siglen);
    fingerprint("kat_certificate", cert, clen);
    fingerprint("kat_root_seed", root_seed, sizeof(root_seed));
    fingerprint("kat_anchors", outputs, sizeof(outputs));
    printf("kat_index=%llu\n", (unsigned long long)index);
    for (unsigned layer = 0; layer <= FS_H; ++layer) {
        char label[32];
        snprintf(label, sizeof(label), "kat_layer_%u", layer);
        fingerprint(label, layers + layer * FS_MFORS_MSG_BYTES, FS_MFORS_MSG_BYTES);
    }
    /* The independent verifier checks full paths, not merely our fingerprints. */
    hex("fixture_pk", pk, sizeof(pk));
    hex("fixture_sk", sk, sizeof(sk));
    hex("fixture_sig", sig, siglen);
    hex("fixture_message", message, sizeof(message)-1);
    hex("fixture_certificate", cert, clen);
    hex("fixture_root_seed", root_seed, sizeof(root_seed));
    hex("fixture_addresses", addr, sizeof(addr));
    hex("fixture_anchors", outputs, sizeof(outputs));
    uint8_t testmsg[257], md[FS_MFORS_MSG_BYTES];
    for (size_t i = 0; i < sizeof(testmsg); ++i) testmsg[i] = (uint8_t)(i*37);
    const size_t lengths[] = {0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 257};
    for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
        char label[32];
        fsphincs_verify_begin(md, &index, R, testmsg, lengths[i], pk);
        snprintf(label, sizeof(label), "h3_%zu", lengths[i]);
        hex(label, md, sizeof(md));
        printf("index_%zu=%llu\n", lengths[i], (unsigned long long)index);
    }
    memcpy(md, testmsg, sizeof(md));
    printf("parsed_indices=");
    for (unsigned i = 0; i < FS_K; ++i) printf("%u,", fsphincs_md_index(md, i));
    puts("");
    free(cert); free(sig);
    return 0;
}
