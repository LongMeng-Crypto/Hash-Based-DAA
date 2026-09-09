#include "api.h"
#include "sha2_compat.h"

#include <stdlib.h>
#include <string.h>

#ifndef FSPHINCS_VERIFY_ONLY
extern void randombytes(unsigned char *out, size_t outlen);
#endif
#if FS_SECURITY == 256
#define h3_init sha512_inc_init
#define h3_blocks sha512_inc_blocks
#define h3_finalize sha512_inc_finalize
#else
#define h3_init sha256_inc_init
#define h3_blocks sha256_inc_blocks
#define h3_finalize sha256_inc_finalize
#endif

enum {
    DOM_NODE_SEED = 1,
    DOM_LEAF_SECRET = 2,
    DOM_LEAF_HASH = 3,
    DOM_TREE_NODE = 4,
    DOM_PAD_ROOT = 5,
    DOM_H2 = 6,
    DOM_H3_SEED = 7,
    DOM_H3_EXPAND = 8,
    DOM_KEY_SEED = 9
};

#ifdef FSPHINCS_PROFILE
static fsphincs_profile profile;
static int profile_layer = -1;
#endif

/* Clears counters without changing any signature or hash state. */
void fsphincs_profile_reset(void) {
#ifdef FSPHINCS_PROFILE
    memset(&profile, 0, sizeof(profile));
    profile_layer = -1;
#endif
}

/* Copies profiling counters, or zeros when profiling is disabled. */
void fsphincs_profile_get(fsphincs_profile *out) {
    if (out) {
#ifdef FSPHINCS_PROFILE
        *out = profile;
#else
        memset(out, 0, sizeof(*out));
#endif
    }
}

/* Hashes one preimage and attributes its work to the active domain/layer. */
static void counted_sha256(uint8_t out[FS_N], const uint8_t *in, size_t inlen,
                           uint8_t domain) {
#ifdef FSPHINCS_PROFILE
    ++profile.total;
    profile.compression_blocks += (inlen + 9u + 63u) / 64u;
    switch (domain) {
        case DOM_NODE_SEED: ++profile.node_seed; break;
        case DOM_LEAF_SECRET: ++profile.leaf_secret; break;
        case DOM_LEAF_HASH: ++profile.leaf_hash; break;
        case DOM_TREE_NODE: ++profile.tree_node; break;
        case DOM_PAD_ROOT: ++profile.padding_root; break;
        case DOM_H2: ++profile.h2; break;
        case DOM_H3_SEED:
        case DOM_H3_EXPAND: ++profile.h3; break;
        case DOM_KEY_SEED: ++profile.key_seed; break;
    }
    if (profile_layer >= 0 && profile_layer <= (int)FS_H)
        ++profile.mfors_layer[profile_layer];
#else
    (void)domain;
#endif
    sha256(out, in, inlen);
}

/* Streams H3 inputs without copying entire messages or truncating SHA-512 state. */
typedef struct {
    _Alignas(4) uint8_t state[FS_H3_DIGEST_BYTES + 8u];
    _Alignas(4) uint8_t block[FS_H3_BLOCK_BYTES];
    size_t used;
} h3_context;

/* Initializes a SHA-256/512 context selected by the credential parameter set. */
static void h3_start(h3_context *ctx) {
    ctx->used = 0;
    h3_init(ctx->state);
}

/* Counts compression work actually executed, including reused H3 prefix states. */
static void h3_count_blocks(size_t blocks) {
#ifdef FSPHINCS_PROFILE
#if FS_SECURITY == 256
    profile.sha512_compression_blocks += blocks;
#else
    profile.compression_blocks += blocks;
#endif
#else
    (void)blocks;
#endif
}

/* Feeds partial blocks through a bounded scratch buffer and full blocks directly. */
static void h3_update(h3_context *ctx, const uint8_t *data, size_t len) {
    if (ctx->used) {
        size_t take = FS_H3_BLOCK_BYTES - ctx->used;
        if (take > len) take = len;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        len -= take;
        if (ctx->used == FS_H3_BLOCK_BYTES) {
            h3_blocks(ctx->state, ctx->block, 1);
            h3_count_blocks(1);
            ctx->used = 0;
        }
    }
    const size_t blocks = len / FS_H3_BLOCK_BYTES;
    if (blocks) {
        h3_blocks(ctx->state, data, blocks);
        h3_count_blocks(blocks);
        data += blocks * FS_H3_BLOCK_BYTES;
        len -= blocks * FS_H3_BLOCK_BYTES;
    }
    if (len) {
        memcpy(ctx->block + ctx->used, data, len);
        ctx->used += len;
    }
}

/* Finalizes H3 and accounts separately for SHA-256 and SHA-512 workloads. */
static void h3_finish(uint8_t out[FS_H3_DIGEST_BYTES], h3_context *ctx) {
#ifdef FSPHINCS_PROFILE
    ++profile.h3;
#if FS_SECURITY == 256
    ++profile.sha512_calls;
    profile.sha512_compression_blocks += (ctx->used + 17u + 127u) / 128u;
#else
    ++profile.total;
    profile.compression_blocks += (ctx->used + 9u + 63u) / 64u;
#endif
#endif
    h3_finalize(out, ctx->state, ctx->block, ctx->used);
}

/* Encodes an unsigned 32-bit address field in big-endian order. */
static void put_u32(uint8_t out[4], uint32_t x) {
    out[0] = (uint8_t)(x >> 24); out[1] = (uint8_t)(x >> 16);
    out[2] = (uint8_t)(x >> 8); out[3] = (uint8_t)x;
}

/* Encodes an unsigned 64-bit node index in big-endian order. */
static void put_u64(uint8_t out[8], uint64_t x) {
    for (int i = 7; i >= 0; --i) { out[i] = (uint8_t)x; x >>= 8; }
}

/* Retains the v3 address for the node PRF and public hash operations. */
static void make_addr(uint8_t out[32], uint8_t domain, uint32_t layer,
                      uint64_t node, uint32_t tree, uint32_t height,
                      uint32_t index) {
    memset(out, 0, 32);
    out[0] = domain;
    out[1] = FS_FORMAT_VERSION;
    out[2] = (uint8_t)(FS_SECURITY >> 8);
    out[3] = (uint8_t)FS_SECURITY;
    out[28] = FS_FAST;
    out[29] = FS_D;
    out[30] = FS_K;
    out[31] = FS_LOGQ;
    put_u32(out + 4, layer);
    put_u64(out + 8, node);
    put_u32(out + 16, tree);
    put_u32(out + 20, height);
    put_u32(out + 24, index);
}

/* Prepares the reusable public-seed/address prefix of a tree hash. */
static void init_hash_prefix(uint8_t *buf, const uint8_t pub_seed[FS_N],
                             uint8_t domain, uint32_t layer, uint64_t node,
                             uint32_t tree) {
    memcpy(buf, pub_seed, FS_N);
    make_addr(buf + FS_N, domain, layer, node, tree, 0, 0);
}

/* Concatenates bounded preimage fragments and hashes them in the given domain. */
static void hash_parts(uint8_t out[FS_N], uint8_t domain,
                       const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen,
                       const uint8_t *c, size_t clen) {
    size_t len = alen + blen + clen;
    uint8_t buf[160];
    if (len > sizeof(buf)) abort();
    if (alen) memcpy(buf, a, alen);
    if (blen) memcpy(buf + alen, b, blen);
    if (clen) memcpy(buf + alen + blen, c, clen);
    counted_sha256(out, buf, len, domain);
}

/* Expands a domain-separated seed with big-endian counter suffixes. */
static void expand(uint8_t *out, size_t outlen, uint8_t domain,
                   const uint8_t seed[FS_N], const uint8_t addr[32]) {
    uint8_t in[1 + FS_N + 32 + 4], digest[FS_N];
    in[0] = domain;
    memcpy(in + 1, seed, FS_N);
    memcpy(in + 1 + FS_N, addr, 32);
    for (uint32_t ctr = 0; outlen; ++ctr) {
        put_u32(in + 1 + FS_N + 32, ctr);
        counted_sha256(digest, in, sizeof(in), domain);
        size_t take = outlen < FS_N ? outlen : FS_N;
        memcpy(out, digest, take);
        out += take;
        outlen -= take;
    }
}

#ifndef FSPHINCS_VERIFY_ONLY
/* Encodes every valid leaf-PRF position injectively; invalid fields never truncate. */
int fsphincs_leaf_prf_address(uint8_t out[FS_LEAF_ADDR_BYTES], uint32_t layer,
                              uint64_t node, uint32_t tree, uint32_t leaf) {
    _Static_assert(FS_H * FS_LOGQ < 64 && FS_K <= 256 && FS_D <= 16,
                   "compact leaf address cannot represent this parameter set");
    if (!out || layer > FS_H || node >= (UINT64_C(1) << (layer * FS_LOGQ)) ||
        tree >= FS_K || leaf >= (UINT32_C(1) << FS_D)) return -1;
    out[0] = DOM_LEAF_SECRET;
    out[1] = FS_LEAF_PRF_VERSION;
    out[2] = FS_PARAMETER_ID;
    out[3] = (uint8_t)layer;
    put_u64(out + 4, node);
    out[12] = (uint8_t)tree;
    out[13] = (uint8_t)(leaf >> 8);
    out[14] = (uint8_t)leaf;
    out[15] = 0;
    return 0;
}

/* Derives a full 256-bit node seed using the unchanged first PRF. */
static void derive_node_seed(uint8_t out[FS_N], const uint8_t master[FS_N],
                             uint32_t layer, uint64_t node) {
    uint8_t addr[32];
    make_addr(addr, DOM_NODE_SEED, layer, node, 0, 0, 0);
    hash_parts(out, DOM_NODE_SEED, master, FS_N, addr, sizeof(addr), NULL, 0);
}

/* Derives a full 256-bit leaf secret with one compact-address SHA-256 block. */
static void derive_leaf_secret(uint8_t out[FS_N], const uint8_t node_seed[FS_N],
                               uint32_t layer, uint64_t node,
                               uint32_t tree, uint32_t leaf) {
    uint8_t addr[FS_LEAF_ADDR_BYTES];
    if (fsphincs_leaf_prf_address(addr, layer, node, tree, leaf) != 0) abort();
    hash_parts(out, DOM_LEAF_SECRET, node_seed, FS_N, addr, sizeof(addr), NULL, 0);
}
#endif

#ifndef FSPHINCS_VERIFY_ONLY
/* Maps a disclosed leaf secret to its addressed signing-tree leaf. */
static void hash_leaf(uint8_t out[FS_N], const uint8_t secret[FS_N],
                      const uint8_t pub_seed[FS_N], uint32_t layer,
                      uint64_t node, uint32_t tree, uint32_t leaf) {
    uint8_t input[FS_N + 32 + FS_N];
    init_hash_prefix(input, pub_seed, DOM_LEAF_HASH, layer, node, tree);
    put_u32(input + FS_N + 24, leaf);
    memcpy(input + FS_N + 32, secret, FS_N);
    counted_sha256(out, input, sizeof(input), DOM_LEAF_HASH);
}

/* Hashes two ordered child nodes with their public tree address. */
static void hash_node(uint8_t out[FS_N], const uint8_t left[FS_N],
                      const uint8_t right[FS_N], const uint8_t pub_seed[FS_N],
                      uint32_t layer, uint64_t node, uint32_t tree,
                      uint32_t height, uint32_t index) {
    uint8_t input[FS_N + 32 + 2 * FS_N];
    init_hash_prefix(input, pub_seed, DOM_TREE_NODE, layer, node, tree);
    put_u32(input + FS_N + 20, height);
    put_u32(input + FS_N + 24, index);
    memcpy(input + FS_N + 32, left, FS_N);
    memcpy(input + FS_N + 32 + FS_N, right, FS_N);
    counted_sha256(out, input, sizeof(input), DOM_TREE_NODE);
}
#endif

/* Uses two byte loads for both supported d values, never reading past ceil(k*d/8). */
uint32_t fsphincs_md_index(const uint8_t md[FS_MFORS_MSG_BYTES], uint32_t tree) {
    const uint32_t bit = tree * FS_D, byte = bit >> 3, shift = bit & 7u;
    const uint32_t word = ((uint32_t)md[byte] << 8) | md[byte + 1u];
    return (word >> (16u - shift - FS_D)) & ((1u << FS_D) - 1u);
}

/* Clears unused low bits of an M-FORS message/public-value encoding. */
static void canonical_md(uint8_t md[FS_MFORS_MSG_BYTES]) {
#if FS_MFORS_MSG_BITS % 8
    md[FS_MFORS_MSG_BYTES - 1u] &= (uint8_t)(0xffu << (8u - FS_MFORS_MSG_BITS % 8u));
#endif
    (void)md;
}

/* Rejects noncanonical public keys instead of silently ignoring their tail bits. */
static int canonical_pk(const uint8_t pk[FS_PK_BYTES]) {
#if FS_MFORS_MSG_BITS % 8
    return (pk[FS_PK_BYTES - 1u] & ((1u << (8u - FS_MFORS_MSG_BITS % 8u)) - 1u)) == 0;
#else
    (void)pk;
    return 1;
#endif
}

#ifndef FSPHINCS_VERIFY_ONLY
/* Builds one signing tree and optionally records the target leaf's path. */
static int tree_root_and_auth(uint8_t root[FS_N], uint8_t *auth,
                              const uint8_t node_seed[FS_N],
                              const uint8_t pub_seed[FS_N],
                              uint32_t layer, uint64_t node, uint32_t tree,
                              uint32_t target) {
    const uint32_t leaves = 1u << FS_D;
    uint8_t *nodes = (uint8_t *)malloc((size_t)leaves * FS_N);
    uint8_t secret[FS_N];
    if (!nodes) return -1;
    for (uint32_t i = 0; i < leaves; ++i) {
        derive_leaf_secret(secret, node_seed, layer, node, tree, i);
        hash_leaf(nodes + (size_t)i * FS_N, secret, pub_seed,
                  layer, node, tree, i);
    }
    uint32_t count = leaves, idx = target;
    for (uint32_t height = 0; height < FS_D; ++height) {
        if (auth) memcpy(auth + (size_t)height * FS_N,
                         nodes + (size_t)(idx ^ 1u) * FS_N, FS_N);
        for (uint32_t i = 0; i < count / 2; ++i) {
            hash_node(nodes + (size_t)i * FS_N,
                      nodes + (size_t)(2 * i) * FS_N,
                      nodes + (size_t)(2 * i + 1) * FS_N,
                      pub_seed, layer, node, tree, height + 1, i);
        }
        idx >>= 1;
        count >>= 1;
    }
    memcpy(root, nodes, FS_N);
    free(nodes);
    return 0;
}
#endif

/* Recovers a signing-tree root using reusable preimages and ping-pong states. */
static void root_from_auth(uint8_t root[FS_N], const uint8_t secret[FS_N],
                           const uint8_t *auth, uint32_t target,
                           const uint8_t pub_seed[FS_N], uint32_t layer,
                           uint64_t node, uint32_t tree) {
    uint8_t state[2][FS_N];
    uint8_t leaf_input[FS_N + 32 + FS_N];
    uint8_t node_input[FS_N + 32 + 2 * FS_N];
    init_hash_prefix(leaf_input, pub_seed, DOM_LEAF_HASH, layer, node, tree);
    put_u32(leaf_input + FS_N + 24, target);
    memcpy(leaf_input + FS_N + 32, secret, FS_N);
    counted_sha256(state[0], leaf_input, sizeof(leaf_input), DOM_LEAF_HASH);

    init_hash_prefix(node_input, pub_seed, DOM_TREE_NODE, layer, node, tree);
    uint32_t idx = target;
    uint32_t current = 0;
    for (uint32_t height = 0; height < FS_D; ++height) {
        const uint8_t *sibling = auth + (size_t)height * FS_N;
        uint8_t *children = node_input + FS_N + 32;
        put_u32(node_input + FS_N + 20, height + 1);
        put_u32(node_input + FS_N + 24, idx >> 1);
        if ((idx & 1u) == 0) {
            memcpy(children, state[current], FS_N);
            memcpy(children + FS_N, sibling, FS_N);
        } else {
            memcpy(children, sibling, FS_N);
            memcpy(children + FS_N, state[current], FS_N);
        }
        current ^= 1u;
        counted_sha256(state[current], node_input, sizeof(node_input),
                       DOM_TREE_NODE);
        idx >>= 1;
    }
    memcpy(root, state[current], FS_N);
}

/* Optionally records the shared path above the first one or two tree roots. */
static void aggregate_roots_with_path(uint8_t root[FS_N], const uint8_t *roots,
                            const uint8_t pub_seed[FS_N],
                            uint32_t layer, uint64_t node, uint8_t *path) {
    uint8_t nodes[FS_AGG_LEAVES * FS_N];
    uint8_t pad_input[FS_N + 32];
    uint8_t node_input[FS_N + 32 + 2 * FS_N];
    memcpy(nodes, roots, FS_K * FS_N);
    init_hash_prefix(pad_input, pub_seed, DOM_PAD_ROOT, layer, node, FS_K);
    for (uint32_t i = FS_K; i < FS_AGG_LEAVES; ++i) {
        put_u32(pad_input + FS_N + 16, i);
        counted_sha256(nodes + (size_t)i * FS_N, pad_input,
                       sizeof(pad_input), DOM_PAD_ROOT);
    }
    init_hash_prefix(node_input, pub_seed, DOM_TREE_NODE, layer, node, FS_K);
    uint32_t count = FS_AGG_LEAVES;
    for (uint32_t height = 0; count > 1; ++height) {
        if (path && (FS_ANCHORS == 1u || height != 0u)) {
            memcpy(path, nodes + FS_N, FS_N);
            path += FS_N;
        }
        put_u32(node_input + FS_N + 20, height + 1);
        for (uint32_t i = 0; i < count / 2; ++i) {
            put_u32(node_input + FS_N + 24, i);
            memcpy(node_input + FS_N + 32,
                   nodes + (size_t)(2 * i) * FS_N, FS_N);
            memcpy(node_input + FS_N + 32 + FS_N,
                   nodes + (size_t)(2 * i + 1) * FS_N, FS_N);
            counted_sha256(nodes + (size_t)i * FS_N, node_input,
                           sizeof(node_input), DOM_TREE_NODE);
        }
        count >>= 1;
    }
    memcpy(root, nodes, FS_N);
}

/* Aggregates all roots for ordinary signing and streaming verification. */
static void aggregate_roots(uint8_t root[FS_N], const uint8_t *roots,
                            const uint8_t pub_seed[FS_N],
                            uint32_t layer, uint64_t node) {
    aggregate_roots_with_path(root, roots, pub_seed, layer, node, NULL);
}

/* Applies H2 and its expansion to encode the canonical M-FORS public value. */
static void root_to_pk(uint8_t pk[FS_MFORS_MSG_BYTES],
                       const uint8_t root[FS_N], const uint8_t pub_seed[FS_N],
                       uint32_t layer, uint64_t node) {
    uint8_t addr[32], seed[FS_N];
    make_addr(addr, DOM_H2, layer, node, FS_K, 0, 0);
    hash_parts(seed, DOM_H2, pub_seed, FS_N, addr, sizeof(addr), root, FS_N);
    expand(pk, FS_MFORS_MSG_BYTES, DOM_H2, seed, addr);
    canonical_md(pk);
}

#ifndef FSPHINCS_VERIFY_ONLY
/* Generates a node public key from all of its seed-derived signing trees. */
static int mfors_gen_pk(uint8_t pk[FS_MFORS_MSG_BYTES],
                        const uint8_t master_seed[FS_N],
                        const uint8_t pub_seed[FS_N],
                        uint32_t layer, uint64_t node) {
    uint8_t node_seed[FS_N], roots[FS_K * FS_N], aggregate[FS_N];
    derive_node_seed(node_seed, master_seed, layer, node);
    for (uint32_t i = 0; i < FS_K; ++i)
        if (tree_root_and_auth(roots + (size_t)i * FS_N, NULL, node_seed,
                               pub_seed, layer, node, i, 0) != 0) return -1;
    aggregate_roots(aggregate, roots, pub_seed, layer, node);
    root_to_pk(pk, aggregate, pub_seed, layer, node);
    return 0;
}

/* Signs one node using its own seed, without access to an issuer master seed. */
static int mfors_sign_node_seed(uint8_t *sig, uint8_t pk[FS_MFORS_MSG_BYTES],
                  const uint8_t md[FS_MFORS_MSG_BYTES],
                  const uint8_t node_seed[FS_N],
                  const uint8_t pub_seed[FS_N],
                  uint32_t layer, uint64_t node) {
    uint8_t roots[FS_K * FS_N], aggregate[FS_N];
    for (uint32_t i = 0; i < FS_K; ++i) {
        uint32_t idx = fsphincs_md_index(md, i);
        derive_leaf_secret(sig, node_seed, layer, node, i, idx);
        if (tree_root_and_auth(roots + (size_t)i * FS_N, sig + FS_N,
                               node_seed, pub_seed, layer, node, i, idx) != 0)
            return -1;
        sig += (FS_D + 1u) * FS_N;
    }
    aggregate_roots(aggregate, roots, pub_seed, layer, node);
    root_to_pk(pk, aggregate, pub_seed, layer, node);
    return 0;
}
/* Keeps the master-seed API for honest on-demand credential signing. */
int fs_mfors_sign(uint8_t *sig, uint8_t pk[FS_MFORS_MSG_BYTES],
                  const uint8_t md[FS_MFORS_MSG_BYTES],
                  const uint8_t master_seed[FS_N], const uint8_t pub_seed[FS_N],
                  uint32_t layer, uint64_t node) {
    uint8_t seed[FS_N];
    derive_node_seed(seed, master_seed, layer, node);
    return mfors_sign_node_seed(sig, pk, md, seed, pub_seed, layer, node);
}

/* Derives the root-node capability from an honest key; this is not a ZK extractor. */
void fsphincs_derive_root_seed(uint8_t out[FS_N], const uint8_t master[FS_N]) {
    derive_node_seed(out, master, 0, 0);
}

/* Fixes anchors at leaf zero in root signing trees zero and, when needed, one. */
void fsphincs_root_anchor_address(uint8_t out[FS_LEAF_ADDR_BYTES], uint32_t anchor) {
    if (anchor >= FS_ANCHORS || fsphincs_leaf_prf_address(out, 0, 0, anchor, 0) != 0)
        abort();
}

/* Generates only the required authentication material, not a full anchor signature. */
int fsphincs_root_anchor_generate(uint8_t payload[FS_ANCHOR_PAYLOAD_BYTES],
    uint8_t root_pk[FS_MFORS_MSG_BYTES], const uint8_t root_seed[FS_N],
    const uint8_t pub_seed[FS_N]) {
    uint8_t roots[FS_K * FS_N], aggregate[FS_N];
    const size_t stride = (1u + FS_D) * FS_N;
    for (uint32_t i = 0; i < FS_K; ++i) {
        uint8_t *auth = NULL;
        if (i < FS_ANCHORS) {
            uint8_t *part = payload + i * stride;
            derive_leaf_secret(part, root_seed, 0, 0, i, 0);
            auth = part + FS_N;
        }
        if (tree_root_and_auth(roots + i * FS_N, auth, root_seed, pub_seed,
                               0, 0, i, 0) != 0) return -1;
    }
    aggregate_roots_with_path(aggregate, roots, pub_seed, 0, 0,
                             payload + FS_ANCHORS * stride);
    root_to_pk(root_pk, aggregate, pub_seed, 0, 0);
    return 0;
}

/* Reconstructs one/two inner trees and the shared aggregation authentication path. */
void fsphincs_root_anchor_recover(uint8_t root_pk[FS_MFORS_MSG_BYTES],
    const uint8_t payload[FS_ANCHOR_PAYLOAD_BYTES], const uint8_t pub_seed[FS_N]) {
    uint8_t roots[2][FS_N], current[FS_N], next[FS_N];
    const size_t stride = (1u + FS_D) * FS_N;
    for (uint32_t i = 0; i < FS_ANCHORS; ++i)
        root_from_auth(roots[i], payload + i * stride,
                       payload + i * stride + FS_N, 0, pub_seed, 0, 0, i);
    uint32_t height = 0;
    if (FS_ANCHORS == 2u) {
        hash_node(current, roots[0], roots[1], pub_seed, 0, 0, FS_K, 1, 0);
        height = 1;
    } else {
        memcpy(current, roots[0], FS_N);
    }
    const uint8_t *path = payload + FS_ANCHORS * stride;
    for (; height < FS_AGG_LOG; ++height, path += FS_N) {
        hash_node(next, current, path, pub_seed, 0, 0, FS_K, height + 1, 0);
        memcpy(current, next, FS_N);
    }
    root_to_pk(root_pk, current, pub_seed, 0, 0);
}
#endif

/* Recovers one M-FORS public value from disclosed secrets and their paths. */
int fs_mfors_recover(uint8_t pk[FS_MFORS_MSG_BYTES], const uint8_t *sig,
                     const uint8_t md[FS_MFORS_MSG_BYTES],
                     const uint8_t pub_seed[FS_N],
                     uint32_t layer, uint64_t node) {
    uint8_t roots[FS_K * FS_N], aggregate[FS_N];
#ifdef FSPHINCS_PROFILE
    int saved_profile_layer = profile_layer;
    profile_layer = (int)layer;
#endif
    for (uint32_t i = 0; i < FS_K; ++i) {
        uint32_t idx = fsphincs_md_index(md, i);
        root_from_auth(roots + (size_t)i * FS_N, sig, sig + FS_N, idx,
                       pub_seed, layer, node, i);
        sig += (FS_D + 1u) * FS_N;
    }
    aggregate_roots(aggregate, roots, pub_seed, layer, node);
    root_to_pk(pk, aggregate, pub_seed, layer, node);
#ifdef FSPHINCS_PROFILE
    profile_layer = saved_profile_layer;
#endif
    return 0;
}

/* Checks a complete M-FORS signature against the expected public value. */
int fs_mfors_verify(const uint8_t *sig,
                    const uint8_t expected_pk[FS_MFORS_MSG_BYTES],
                    const uint8_t md[FS_MFORS_MSG_BYTES],
                    const uint8_t pub_seed[FS_N],
                    uint32_t layer, uint64_t node) {
    uint8_t recovered[FS_MFORS_MSG_BYTES], diff = 0;
    fs_mfors_recover(recovered, sig, md, pub_seed, layer, node);
    for (size_t i = 0; i < sizeof(recovered); ++i)
        diff |= recovered[i] ^ expected_pk[i];
    return diff == 0 ? 0 : -1;
}

/* H3 v3: SHA-X prehash and MGF1-style SHA-X expansion bind R and the full key. */
static void h3(uint8_t md[FS_MFORS_MSG_BYTES], uint64_t *idx,
                const uint8_t randomizer[FS_N], const uint8_t *msg, size_t msglen,
                const uint8_t pk[FS_PK_BYTES]) {
    const uint8_t context[9] = {DOM_H3_SEED, FS_FORMAT_VERSION,
        (uint8_t)(FS_SECURITY >> 8), (uint8_t)FS_SECURITY,
        FS_FAST, FS_D, FS_K, FS_H, FS_LOGQ};
    uint8_t seed[FS_H3_DIGEST_BYTES], digest[FS_H3_DIGEST_BYTES];
    uint8_t out[FS_H3_BYTES], counter[4], domain = DOM_H3_EXPAND;
    h3_context pre, expansion;
    h3_start(&pre);
    h3_update(&pre, context, sizeof(context));
    h3_update(&pre, randomizer, FS_N);
    h3_update(&pre, pk, FS_PK_BYTES);
    h3_update(&pre, msg, msglen);
    h3_finish(seed, &pre);
    h3_start(&expansion);
    h3_update(&expansion, &domain, 1);
    h3_update(&expansion, context + 1, sizeof(context) - 1u);
    h3_update(&expansion, randomizer, FS_N);
    h3_update(&expansion, pk, FS_PK_BYTES);
    h3_update(&expansion, seed, sizeof(seed));
    for (size_t offset = 0, ctr = 0; offset < sizeof(out); ++ctr) {
        h3_context block = expansion;
        put_u32(counter, (uint32_t)ctr);
        h3_update(&block, counter, sizeof(counter));
        h3_finish(digest, &block);
        size_t take = sizeof(out) - offset;
        if (take > sizeof(digest)) take = sizeof(digest);
        memcpy(out + offset, digest, take);
        offset += take;
    }
    memcpy(md, out, FS_MFORS_MSG_BYTES);
    canonical_md(md);
    *idx = 0;
    uint32_t bit = FS_MFORS_MSG_BITS, left = FS_INDEX_BITS;
    while (left) {
        uint32_t take = 8u - (bit & 7u);
        if (take > left) take = left;
        uint32_t value = (out[bit >> 3] >> (8u - (bit & 7u) - take)) &
                         ((1u << take) - 1u);
        *idx = (*idx << take) | value;
        bit += take;
        left -= take;
    }
}

/* Returns the selected parameter set's serialized public-key length. */
size_t fsphincs_publickeybytes(void) { return FS_PK_BYTES; }
/* Returns the serialized master-seed/public-key secret-key length. */
size_t fsphincs_secretkeybytes(void) { return FS_SK_BYTES; }
/* Returns the randomizer plus seven serialized M-FORS signature lengths. */
size_t fsphincs_signaturebytes(void) { return FS_SIG_BYTES; }
/* Returns the entropy input length for deterministic key generation. */
size_t fsphincs_seedbytes(void) { return FS_SEED_BYTES; }

#ifndef FSPHINCS_VERIFY_ONLY
/* Generates a keypair from caller-supplied master/public-seed entropy. */
int fsphincs_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    uint8_t master[FS_N], pub_seed[FS_N], root_pk[FS_MFORS_MSG_BYTES];
    uint8_t tag = DOM_KEY_SEED;
    hash_parts(master, DOM_KEY_SEED, &tag, 1, seed, FS_N, NULL, 0);
    hash_parts(pub_seed, DOM_KEY_SEED, &tag, 1, seed + FS_N, FS_N, NULL, 0);
    if (mfors_gen_pk(root_pk, master, pub_seed, 0, 0) != 0) return -1;
    memcpy(pk, pub_seed, FS_N);
    memcpy(pk + FS_N, root_pk, FS_MFORS_MSG_BYTES);
    memcpy(sk, master, FS_N);
    memcpy(sk + FS_N, pub_seed, FS_N);
    memcpy(sk + 2 * FS_N, root_pk, FS_MFORS_MSG_BYTES);
    return 0;
}

/* Obtains fresh entropy from the caller's RNG and generates a keypair. */
int fsphincs_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seed[FS_SEED_BYTES];
    randombytes(seed, sizeof(seed));
    return fsphincs_seed_keypair(pk, sk, seed);
}

/* Signs the message through all seven layers using an explicit randomizer. */
int fsphincs_sign_signature_with_randomizer(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk, const uint8_t randomizer[FS_N]) {
    const uint8_t *master = sk, *pub_seed = sk + FS_N;
    uint8_t md[FS_MFORS_MSG_BYTES], value[FS_MFORS_MSG_BYTES];
    uint64_t idx;
    memcpy(sig, randomizer, FS_N);
    h3(md, &idx, randomizer, msg, msglen, sk + FS_N);
    uint8_t *p = sig + FS_N;
    uint64_t node = idx;
    if (fs_mfors_sign(p, value, md, master, pub_seed, FS_H, node) != 0) return -1;
    p += FS_MFORS_SIG_BYTES;
    for (uint32_t step = 1; step <= FS_H; ++step) {
        node /= FS_Q;
        uint32_t layer = FS_H - step;
        if (fs_mfors_sign(p, value, value, master, pub_seed, layer, node) != 0)
            return -1;
        p += FS_MFORS_SIG_BYTES;
    }
    *siglen = FS_SIG_BYTES;
    return 0;
}

/* Produces a fresh valid credential without ever receiving the original master key. */
int fsphincs_sign_with_root_seed(uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t msglen, const uint8_t pk[FS_PK_BYTES],
    const uint8_t root_seed[FS_N], const uint8_t lower_seed[FS_N],
    const uint8_t randomizer[FS_N]) {
    if (!canonical_pk(pk)) return -1;
    uint8_t value[FS_MFORS_MSG_BYTES];
    uint64_t node;
    h3(value, &node, randomizer, msg, msglen, pk);
    memcpy(sig, randomizer, FS_N);
    uint8_t *part = sig + FS_N;
    for (uint32_t step = 0; step <= FS_H; ++step, part += FS_MFORS_SIG_BYTES) {
        int rc = step == FS_H
            ? mfors_sign_node_seed(part, value, value, root_seed, pk, 0, 0)
            : fs_mfors_sign(part, value, value, lower_seed, pk, FS_H - step, node);
        if (rc != 0) return -1;
        node /= FS_Q;
    }
    *siglen = FS_SIG_BYTES;
    return memcmp(value, pk + FS_N, FS_MFORS_MSG_BYTES) == 0 ? 0 : -1;
}

/* Signs with a fresh randomizer obtained from the caller's RNG. */
int fsphincs_sign_signature(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk) {
    uint8_t randomizer[FS_N];
    randombytes(randomizer, sizeof(randomizer));
    return fsphincs_sign_signature_with_randomizer(sig, siglen, msg, msglen,
                                                    sk, randomizer);
}
#endif

/* Compares all bytes without a data-dependent early exit. */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* Initializes streaming verification with H3's message and node index. */
void fsphincs_verify_begin(uint8_t value[FS_MFORS_MSG_BYTES],
                           uint64_t *leaf_index,
                           const uint8_t randomizer[FS_N],
                           const uint8_t *msg, size_t msglen,
                           const uint8_t pk[FS_PK_BYTES]) {
    h3(value, leaf_index, randomizer, msg, msglen, pk);
}

/* Consumes one serialized layer and updates the recovered value in place. */
int fsphincs_verify_layer(uint8_t value[FS_MFORS_MSG_BYTES],
                          const uint8_t layer_sig[FS_MFORS_SIG_BYTES],
                          const uint8_t pub_seed[FS_N],
                          uint32_t layer, uint64_t node) {
    return fs_mfors_recover(value, layer_sig, value, pub_seed, layer, node);
}

/* Accepts only a canonical public key matching the recovered root value. */
int fsphincs_verify_finish(const uint8_t value[FS_MFORS_MSG_BYTES],
                           const uint8_t pk[FS_PK_BYTES]) {
    return canonical_pk(pk) && ct_equal(value, pk + FS_N, FS_MFORS_MSG_BYTES) ? 0 : -1;
}

/* Verifies a full signature and optionally records deterministic layer outputs. */
int fsphincs_trace_signature(uint8_t layer_values[(FS_H + 1u) *
                              FS_MFORS_MSG_BYTES],
                             uint64_t *leaf_index,
                             const uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *pk) {
    if (siglen != FS_SIG_BYTES || !canonical_pk(pk)) return -1;
    uint8_t md[FS_MFORS_MSG_BYTES], value[FS_MFORS_MSG_BYTES];
    uint64_t idx, node;
    h3(md, &idx, sig, msg, msglen, pk);
    if (leaf_index) *leaf_index = idx;
    node = idx;
    const uint8_t *p = sig + FS_N;
    fs_mfors_recover(value, p, md, pk, FS_H, node);
    if (layer_values)
        memcpy(layer_values, value, FS_MFORS_MSG_BYTES);
    p += FS_MFORS_SIG_BYTES;
    for (uint32_t step = 1; step <= FS_H; ++step) {
        node /= FS_Q;
        uint32_t layer = FS_H - step;
        fs_mfors_recover(value, p, value, pk, layer, node);
        if (layer_values)
            memcpy(layer_values + (size_t)step * FS_MFORS_MSG_BYTES,
                   value, FS_MFORS_MSG_BYTES);
        p += FS_MFORS_SIG_BYTES;
    }
    return ct_equal(value, pk + FS_N, FS_MFORS_MSG_BYTES) ? 0 : -1;
}

/* Verifies a detached signature without exporting intermediate values. */
int fsphincs_verify(const uint8_t *sig, size_t siglen,
                    const uint8_t *msg, size_t msglen, const uint8_t *pk) {
    return fsphincs_trace_signature(NULL, NULL, sig, siglen, msg, msglen, pk);
}
