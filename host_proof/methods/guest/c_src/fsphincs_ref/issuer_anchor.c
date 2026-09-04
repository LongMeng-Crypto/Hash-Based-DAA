#include "issuer_anchor.h"

#include <stdlib.h>
#include <string.h>

#include "api.h"

void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

#define ANCHOR_HEADER_BYTES 16u
#define ANCHOR_KIND_FSPHINCS 2u
#define ANCHOR_NODES 2u
#define LOWER_LAYER 1u
#define LOWER_NODE 0u
#define TOP_LAYER 0u
#define TOP_NODE 0u

enum {
    DOM_NODE_SEED = 1,
    DOM_LEAF_SECRET = 2,
    DOM_LEAF_HASH = 3,
    DOM_TREE_NODE = 4,
    DOM_PAD_ROOT = 5,
    DOM_H2 = 6
};

static const uint8_t anchor_magic[8] = {'D', 'A', 'A', 'A', 'N', 'C', '2', 0};

static void put_u32(uint8_t out[4], uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void put_u64(uint8_t out[8], uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)value;
        value >>= 8;
    }
}

static void make_addr(uint8_t out[32], uint8_t domain, uint32_t layer,
                      uint64_t node, uint32_t tree, uint32_t height,
                      uint32_t index) {
    memset(out, 0, 32);
    out[0] = domain;
    put_u32(out + 4, layer);
    put_u64(out + 8, node);
    put_u32(out + 16, tree);
    put_u32(out + 20, height);
    put_u32(out + 24, index);
}

static void init_prefix(uint8_t *out, const uint8_t pub_seed[FS_N],
                        uint8_t domain, uint32_t layer, uint64_t node,
                        uint32_t tree) {
    memcpy(out, pub_seed, FS_N);
    memset(out + FS_N, 0, 32);
    out[FS_N] = domain;
    put_u32(out + FS_N + 4, layer);
    put_u64(out + FS_N + 8, node);
    put_u32(out + FS_N + 16, tree);
}

static void derive_node_seed(uint8_t out[FS_N], const uint8_t master[FS_N],
                             const uint8_t address[32]) {
    uint8_t input[FS_N + 32];
    memcpy(input, master, FS_N);
    memcpy(input + FS_N, address, 32);
    sha256(out, input, sizeof(input));
}

static void derive_leaf_secret(uint8_t out[FS_N],
                               const uint8_t node_seed[FS_N],
                               const uint8_t address[32]) {
    uint8_t input[FS_N + 32];
    memcpy(input, node_seed, FS_N);
    memcpy(input + FS_N, address, 32);
    sha256(out, input, sizeof(input));
}

static void hash_leaf(uint8_t out[FS_N], const uint8_t secret[FS_N],
                      const uint8_t pub_seed[FS_N], uint32_t layer,
                      uint64_t node, uint32_t tree, uint32_t leaf) {
    uint8_t input[FS_N + 32 + FS_N];
    init_prefix(input, pub_seed, DOM_LEAF_HASH, layer, node, tree);
    put_u32(input + FS_N + 24, leaf);
    memcpy(input + FS_N + 32, secret, FS_N);
    sha256(out, input, sizeof(input));
}

static void hash_node(uint8_t out[FS_N], const uint8_t left[FS_N],
                      const uint8_t right[FS_N],
                      const uint8_t pub_seed[FS_N], uint32_t layer,
                      uint64_t node, uint32_t tree, uint32_t height,
                      uint32_t index) {
    uint8_t input[FS_N + 32 + 2 * FS_N];
    init_prefix(input, pub_seed, DOM_TREE_NODE, layer, node, tree);
    put_u32(input + FS_N + 20, height);
    put_u32(input + FS_N + 24, index);
    memcpy(input + FS_N + 32, left, FS_N);
    memcpy(input + FS_N + 32 + FS_N, right, FS_N);
    sha256(out, input, sizeof(input));
}

static void root_from_auth(uint8_t root[FS_N], const uint8_t secret[FS_N],
                           const uint8_t *auth, uint32_t target,
                           const uint8_t pub_seed[FS_N], uint32_t layer,
                           uint64_t node, uint32_t tree) {
    uint8_t current[FS_N], next[FS_N];
    hash_leaf(current, secret, pub_seed, layer, node, tree, target);
    uint32_t index = target;
    for (uint32_t height = 0; height < FS_D; ++height) {
        const uint8_t *sibling = auth + (size_t)height * FS_N;
        if ((index & 1u) == 0)
            hash_node(next, current, sibling, pub_seed, layer, node, tree,
                      height + 1, index >> 1);
        else
            hash_node(next, sibling, current, pub_seed, layer, node, tree,
                      height + 1, index >> 1);
        memcpy(current, next, FS_N);
        index >>= 1;
    }
    memcpy(root, current, FS_N);
}

static void aggregate_roots(uint8_t root[FS_N], const uint8_t *roots,
                            const uint8_t pub_seed[FS_N], uint32_t layer,
                            uint64_t node) {
    uint8_t nodes[FS_AGG_LEAVES * FS_N];
    uint8_t pad_input[FS_N + 32];
    memcpy(nodes, roots, FS_K * FS_N);
    init_prefix(pad_input, pub_seed, DOM_PAD_ROOT, layer, node, FS_K);
    for (uint32_t i = FS_K; i < FS_AGG_LEAVES; ++i) {
        put_u32(pad_input + FS_N + 16, i);
        sha256(nodes + (size_t)i * FS_N, pad_input, sizeof(pad_input));
    }
    uint32_t count = FS_AGG_LEAVES;
    for (uint32_t height = 0; count > 1; ++height) {
        for (uint32_t i = 0; i < count / 2; ++i)
            hash_node(nodes + (size_t)i * FS_N,
                      nodes + (size_t)(2 * i) * FS_N,
                      nodes + (size_t)(2 * i + 1) * FS_N,
                      pub_seed, layer, node, FS_K, height + 1, i);
        count >>= 1;
    }
    memcpy(root, nodes, FS_N);
}

static void expand(uint8_t *out, size_t outlen, uint8_t domain,
                   const uint8_t seed[FS_N], const uint8_t address[32]) {
    uint8_t input[1 + FS_N + 32 + 4], digest[FS_N];
    input[0] = domain;
    memcpy(input + 1, seed, FS_N);
    memcpy(input + 1 + FS_N, address, 32);
    for (uint32_t counter = 0; outlen != 0; ++counter) {
        put_u32(input + 1 + FS_N + 32, counter);
        sha256(digest, input, sizeof(input));
        const size_t take = outlen < FS_N ? outlen : FS_N;
        memcpy(out, digest, take);
        out += take;
        outlen -= take;
    }
}

static void root_to_pk(uint8_t pk_value[FS_MFORS_MSG_BYTES],
                       const uint8_t root[FS_N],
                       const uint8_t pub_seed[FS_N], uint32_t layer,
                       uint64_t node) {
    uint8_t address[32], input[FS_N + 32 + FS_N], seed[FS_N];
    make_addr(address, DOM_H2, layer, node, FS_K, 0, 0);
    memcpy(input, pub_seed, FS_N);
    memcpy(input + FS_N, address, 32);
    memcpy(input + FS_N + 32, root, FS_N);
    sha256(seed, input, sizeof(input));
    expand(pk_value, FS_MFORS_MSG_BYTES, DOM_H2, seed, address);
}

static uint32_t md_index(const uint8_t md[FS_MFORS_MSG_BYTES],
                         uint32_t tree) {
    return ((uint32_t)md[2 * tree] << 8) | md[2 * tree + 1];
}

static size_t component_bytes(void) {
    return (size_t)(FS_D + FS_K) * FS_N;
}

static void compress_signature(uint8_t *out, const uint8_t *signature,
                               const uint8_t md[FS_MFORS_MSG_BYTES],
                               const uint8_t pub_seed[FS_N], uint32_t layer,
                               uint64_t node) {
    memcpy(out, signature, (size_t)(FS_D + 1u) * FS_N);
    out += (size_t)(FS_D + 1u) * FS_N;
    for (uint32_t tree = 1; tree < FS_K; ++tree) {
        const uint8_t *part = signature +
                              (size_t)tree * (FS_D + 1u) * FS_N;
        root_from_auth(out, part, part + FS_N, md_index(md, tree),
                       pub_seed, layer, node, tree);
        out += FS_N;
    }
}

static void recover_component(uint8_t pk_value[FS_MFORS_MSG_BYTES],
                              const uint8_t *component,
                              const uint8_t md[FS_MFORS_MSG_BYTES],
                              const uint8_t pub_seed[FS_N], uint32_t layer,
                              uint64_t node) {
    uint8_t roots[FS_K * FS_N], aggregate[FS_N];
    root_from_auth(roots, component, component + FS_N, md_index(md, 0),
                   pub_seed, layer, node, 0);
    component += (size_t)(FS_D + 1u) * FS_N;
    memcpy(roots + FS_N, component, (size_t)(FS_K - 1u) * FS_N);
    aggregate_roots(aggregate, roots, pub_seed, layer, node);
    root_to_pk(pk_value, aggregate, pub_seed, layer, node);
}

size_t fsphincs_issuer_anchor_certificate_bytes(void) {
    return ANCHOR_HEADER_BYTES + 2u * component_bytes();
}

static void write_header(uint8_t out[ANCHOR_HEADER_BYTES]) {
    memcpy(out, anchor_magic, sizeof(anchor_magic));
    out[8] = ANCHOR_KIND_FSPHINCS;
    out[9] = FS_N;
    out[10] = FS_D;
    out[11] = FS_K;
    out[12] = FS_H;
    out[13] = FS_LOGQ;
    out[14] = ANCHOR_NODES;
    out[15] = 0;
}

static int valid_header(const uint8_t *certificate, size_t certificate_len) {
    uint8_t expected[ANCHOR_HEADER_BYTES];
    if (certificate == NULL ||
        certificate_len != fsphincs_issuer_anchor_certificate_bytes())
        return 0;
    write_header(expected);
    return memcmp(certificate, expected, sizeof(expected)) == 0;
}

int fsphincs_issuer_anchor_generate(uint8_t *certificate,
                                    size_t certificate_len,
                                    const uint8_t *pk,
                                    const uint8_t *sk) {
    uint8_t lower_message[FS_MFORS_MSG_BYTES] = {0};
    uint8_t lower_pk[FS_MFORS_MSG_BYTES], top_pk[FS_MFORS_MSG_BYTES];
    uint8_t *lower_signature = NULL, *top_signature = NULL;

    if (certificate == NULL || pk == NULL || sk == NULL ||
        certificate_len != fsphincs_issuer_anchor_certificate_bytes() ||
        memcmp(sk + FS_N, pk, FS_PK_BYTES) != 0)
        return -1;
    lower_signature = (uint8_t *)malloc(FS_MFORS_SIG_BYTES);
    top_signature = (uint8_t *)malloc(FS_MFORS_SIG_BYTES);
    if (lower_signature == NULL || top_signature == NULL) goto fail;

    if (fs_mfors_sign(lower_signature, lower_pk, lower_message, sk, pk,
                      LOWER_LAYER, LOWER_NODE) != 0 ||
        fs_mfors_sign(top_signature, top_pk, lower_pk, sk, pk,
                      TOP_LAYER, TOP_NODE) != 0 ||
        memcmp(top_pk, pk + FS_N, FS_MFORS_MSG_BYTES) != 0)
        goto fail;

    write_header(certificate);
    uint8_t *out = certificate + ANCHOR_HEADER_BYTES;
    compress_signature(out, lower_signature, lower_message, pk,
                       LOWER_LAYER, LOWER_NODE);
    out += component_bytes();
    compress_signature(out, top_signature, lower_pk, pk,
                       TOP_LAYER, TOP_NODE);

    free(top_signature);
    free(lower_signature);
    return 0;

fail:
    free(top_signature);
    free(lower_signature);
    return -1;
}

int fsphincs_issuer_anchor_verify(const uint8_t *certificate,
                                  size_t certificate_len,
                                  const uint8_t *pk) {
    uint8_t lower_message[FS_MFORS_MSG_BYTES] = {0};
    uint8_t lower_pk[FS_MFORS_MSG_BYTES], top_pk[FS_MFORS_MSG_BYTES];
    if (pk == NULL || !valid_header(certificate, certificate_len)) return -1;

    const uint8_t *lower_component = certificate + ANCHOR_HEADER_BYTES;
    const uint8_t *top_component = lower_component + component_bytes();
    recover_component(lower_pk, lower_component, lower_message, pk,
                      LOWER_LAYER, LOWER_NODE);
    recover_component(top_pk, top_component, lower_pk, pk,
                      TOP_LAYER, TOP_NODE);
    return memcmp(top_pk, pk + FS_N, FS_MFORS_MSG_BYTES) == 0 ? 0 : -1;
}

int fsphincs_issuer_anchor_relation(uint8_t master_seed[FS_N],
                                    uint8_t node_addresses[64],
                                    uint8_t leaf_addresses[64],
                                    uint8_t anchor_values[2 * FS_N],
                                    const uint8_t *certificate,
                                    size_t certificate_len,
                                    const uint8_t *pk,
                                    const uint8_t *sk) {
    uint8_t lower_message[FS_MFORS_MSG_BYTES] = {0};
    uint8_t lower_pk[FS_MFORS_MSG_BYTES], node_seed[FS_N], expected[FS_N];
    if (master_seed == NULL || node_addresses == NULL ||
        leaf_addresses == NULL || anchor_values == NULL || pk == NULL ||
        sk == NULL || !valid_header(certificate, certificate_len) ||
        memcmp(sk + FS_N, pk, FS_PK_BYTES) != 0 ||
        fsphincs_issuer_anchor_verify(certificate, certificate_len, pk) != 0)
        return -1;

    const uint8_t *lower_component = certificate + ANCHOR_HEADER_BYTES;
    const uint8_t *top_component = lower_component + component_bytes();
    recover_component(lower_pk, lower_component, lower_message, pk,
                      LOWER_LAYER, LOWER_NODE);
    const uint32_t targets[ANCHOR_NODES] = {0, md_index(lower_pk, 0)};
    const uint32_t layers[ANCHOR_NODES] = {LOWER_LAYER, TOP_LAYER};
    const uint64_t nodes[ANCHOR_NODES] = {LOWER_NODE, TOP_NODE};
    const uint8_t *public_secrets[ANCHOR_NODES] = {
        lower_component, top_component
    };

    for (uint32_t i = 0; i < ANCHOR_NODES; ++i) {
        make_addr(node_addresses + (size_t)i * 32u, DOM_NODE_SEED,
                  layers[i], nodes[i], 0, 0, 0);
        make_addr(leaf_addresses + (size_t)i * 32u, DOM_LEAF_SECRET,
                  layers[i], nodes[i], 0, 0, targets[i]);
        derive_node_seed(node_seed, sk, node_addresses + (size_t)i * 32u);
        derive_leaf_secret(expected, node_seed,
                           leaf_addresses + (size_t)i * 32u);
        if (memcmp(expected, public_secrets[i], FS_N) != 0) return -1;
        memcpy(anchor_values + (size_t)i * FS_N, public_secrets[i], FS_N);
    }
    memcpy(master_seed, sk, FS_N);
    return 0;
}
