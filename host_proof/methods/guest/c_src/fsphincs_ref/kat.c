#include "api.h"
#include "issuer_anchor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2_compat.h"

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

/* Exhausts local positions and checks boundary/range handling without hashing. */
static int check_compact_addresses(void) {
    uint8_t address[FS_LEAF_ADDR_BYTES], previous[FS_LEAF_ADDR_BYTES];
    memset(previous, 0xff, sizeof(previous));
    const uint64_t node = (UINT64_C(1) << (FS_H * FS_LOGQ)) - 1;
    for (uint32_t tree = 0; tree < FS_K; ++tree) {
        for (uint32_t leaf = 0; leaf < (UINT32_C(1) << FS_D); ++leaf) {
            if (fsphincs_leaf_prf_address(address, FS_H, node, tree, leaf)) return -1;
            const uint32_t decoded_leaf = ((uint32_t)address[13] << 8) | address[14];
            if (address[0] != 2 || address[1] != FS_LEAF_PRF_VERSION ||
                address[2] != FS_PARAMETER_ID || address[3] != FS_H ||
                address[12] != tree || decoded_leaf != leaf || address[15] != 0 ||
                memcmp(address, previous, sizeof(address)) == 0) return -1;
            memcpy(previous, address, sizeof(previous));
        }
    }
    for (uint32_t layer = 0; layer <= FS_H; ++layer) {
        const uint64_t limit = UINT64_C(1) << (layer * FS_LOGQ);
        if (fsphincs_leaf_prf_address(address, layer, limit - 1, 0, 0)) return -1;
        uint64_t decoded = 0;
        for (unsigned i = 4; i < 12; ++i) decoded = (decoded << 8) | address[i];
        if (decoded != limit - 1 || address[3] != layer ||
            fsphincs_leaf_prf_address(address, layer, limit, 0, 0) == 0) return -1;
    }
    if (fsphincs_leaf_prf_address(NULL, 0, 0, 0, 0) == 0 ||
        fsphincs_leaf_prf_address(address, FS_H + 1, 0, 0, 0) == 0 ||
        fsphincs_leaf_prf_address(address, UINT32_MAX, 0, 0, 0) == 0 ||
        fsphincs_leaf_prf_address(address, 0, 0, FS_K, 0) == 0 ||
        fsphincs_leaf_prf_address(address, 0, 0, 0, UINT32_C(1) << FS_D) == 0)
        return -1;
    return 0;
}

/* Exercises deterministic keys, H3 boundaries, signatures and root certificates. */
int main(void) {
    const uint8_t message[] = "F-SPHINCS+ deterministic format-v3 KAT";
    uint8_t seed[FS_SEED_BYTES], R[FS_N], pk[FS_PK_BYTES], sk[FS_SK_BYTES];
    uint8_t layers[(FS_H + 1) * FS_MFORS_MSG_BYTES], root_seed[FS_N];
    uint8_t addr[FS_ANCHORS * FS_LEAF_ADDR_BYTES], outputs[FS_ANCHORS * FS_N];
    uint8_t *sig = malloc(FS_SIG_BYTES);
    const size_t clen = fsphincs_issuer_anchor_certificate_bytes();
    uint8_t *cert = malloc(clen);
    size_t siglen = 0;
    uint64_t index = 0;
    if (!sig || !cert || check_compact_addresses()) return 1;
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
    printf("kat_leaf_prf_version=%u\n", FS_LEAF_PRF_VERSION);
    printf("kat_h1_version=%u\nkat_node_bytes=%u\n", FS_H1_VERSION, FS_NODE_BYTES);
    fingerprint("kat_pk", pk, sizeof(pk));
    fingerprint("kat_sk", sk, sizeof(sk));
    fingerprint("kat_signature", sig, siglen);
    fingerprint("kat_certificate", cert, clen);
    fingerprint("kat_root_seed", root_seed, sizeof(root_seed));
    fingerprint("kat_anchors", outputs, sizeof(outputs));
    fingerprint("kat_addresses", addr, sizeof(addr));
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
