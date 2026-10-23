#include "issuer_anchor.h"
#include "api.h"
#include "sha2_compat.h"

#include <string.h>

#define ANCHOR_HEADER_BYTES 16u
#define ANCHOR_KIND_FSPHINCS_ROOT 3u

/* Encodes the format, exact credential set, anchor count, and hash selection. */
static void write_header(uint8_t out[ANCHOR_HEADER_BYTES]) {
    static const uint8_t magic[8] = {'D', 'A', 'A', 'F', 'R', 'O', 'O', 'T'};
    memcpy(out, magic, sizeof(magic));
    out[8] = FS_CERTIFICATE_VERSION;
    out[9] = ANCHOR_KIND_FSPHINCS_ROOT;
    out[10] = (uint8_t)(FS_SECURITY >> 8);
    out[11] = (uint8_t)FS_SECURITY;
    out[12] = FS_FAST;
    out[13] = FS_D;
    out[14] = FS_K;
    out[15] = FS_ANCHORS;
}

/* Rejects old address/certificate versions, cross-set data, and trailing bytes. */
static int valid_header(const uint8_t *certificate, size_t len) {
    uint8_t expected[ANCHOR_HEADER_BYTES];
    write_header(expected);
    return certificate && len == fsphincs_issuer_anchor_certificate_bytes() &&
           memcmp(certificate, expected, sizeof(expected)) == 0;
}

/* Reports only selected inner paths plus their shared aggregation path. */
size_t fsphincs_issuer_anchor_certificate_bytes(void) {
    return ANCHOR_HEADER_BYTES + FS_ANCHOR_PAYLOAD_BYTES;
}

/* Builds root-only authentication material without publishing other tree roots. */
int fsphincs_issuer_anchor_generate(uint8_t *certificate, size_t len,
                                    const uint8_t *pk, const uint8_t *sk) {
    if (!certificate || !pk || !sk ||
        len != fsphincs_issuer_anchor_certificate_bytes() ||
        memcmp(sk + FS_N, pk, FS_PK_BYTES) != 0) return -1;
    uint8_t root_seed[FS_N], root_pk[FS_MFORS_MSG_BYTES];
    fsphincs_derive_root_seed(root_seed, sk);
    write_header(certificate);
    int rc = fsphincs_root_anchor_generate(certificate + ANCHOR_HEADER_BYTES,
                                           root_pk, root_seed, pk);
    memset(root_seed, 0, sizeof(root_seed));
    if (rc != 0 || memcmp(root_pk, pk + FS_N, sizeof(root_pk)) != 0) return -1;
    return 0;
}

/* Authenticates all disclosed PRF outputs to the registered M-FORS public key. */
int fsphincs_issuer_anchor_verify(const uint8_t *certificate, size_t len,
                                  const uint8_t *pk) {
    if (!pk || !valid_header(certificate, len)) return -1;
    uint8_t recovered[FS_MFORS_MSG_BYTES];
    fsphincs_root_anchor_recover(recovered, certificate + ANCHOR_HEADER_BYTES, pk);
    return memcmp(recovered, pk + FS_N, sizeof(recovered)) == 0 ? 0 : -1;
}

/* Derives the public addressed-PRF statement from an authenticated certificate. */
int fsphincs_issuer_anchor_statement(uint8_t addresses[FS_ANCHORS * FS_LEAF_ADDR_BYTES],
    uint8_t anchors[FS_ANCHORS * FS_N], const uint8_t *certificate,
    size_t len, const uint8_t *pk) {
    if (!addresses || !anchors ||
        fsphincs_issuer_anchor_verify(certificate, len, pk) != 0) return -1;
    const size_t stride = FS_TREE_SIG_BYTES;
    for (uint32_t i = 0; i < FS_ANCHORS; ++i) {
        fsphincs_root_anchor_address(addresses + i * FS_LEAF_ADDR_BYTES, i);
        memcpy(anchors + i * FS_N,
               certificate + ANCHOR_HEADER_BYTES + i * stride, FS_N);
    }
    return 0;
}

/* Exports the one root seed and checks each endpoint before invoking VOLEith. */
int fsphincs_issuer_anchor_relation(uint8_t root_seed[FS_N],
    uint8_t addresses[FS_ANCHORS * FS_LEAF_ADDR_BYTES], uint8_t anchors[FS_ANCHORS * FS_N],
    const uint8_t *certificate, size_t len, const uint8_t *pk, const uint8_t *sk) {
    if (!root_seed || !sk || !pk || memcmp(sk + FS_N, pk, FS_PK_BYTES) != 0 ||
        fsphincs_issuer_anchor_statement(addresses, anchors, certificate, len, pk) != 0)
        return -1;
    fsphincs_derive_root_seed(root_seed, sk);
    uint8_t input[FS_N + FS_LEAF_ADDR_BYTES], expected[FS_N];
    memcpy(input, root_seed, FS_N);
    for (uint32_t i = 0; i < FS_ANCHORS; ++i) {
        memcpy(input + FS_N, addresses + i * FS_LEAF_ADDR_BYTES, FS_LEAF_ADDR_BYTES);
        sha256(expected, input, sizeof(input));
        if (memcmp(expected, anchors + i * FS_N, FS_N) != 0) return -1;
    }
    return 0;
}
