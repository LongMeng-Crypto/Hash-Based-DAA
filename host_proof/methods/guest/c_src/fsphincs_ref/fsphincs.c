#include "api.h"

#include <stdlib.h>
#include <string.h>

#ifndef FSPHINCS_VERIFY_ONLY
extern void randombytes(unsigned char *out, size_t outlen);
#endif
/* Supplied by the existing parallel sphincs_ref SHA-256 implementation. */
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);
void sha256_inc_init(uint8_t *state);
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha256_inc_finalize(uint8_t *out, uint8_t *state,
                         const uint8_t *in, size_t inlen);

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

void fsphincs_profile_reset(void) {
#ifdef FSPHINCS_PROFILE
    memset(&profile, 0, sizeof(profile));
    profile_layer = -1;
#endif
}

void fsphincs_profile_get(fsphincs_profile *out) {
    if (out) {
#ifdef FSPHINCS_PROFILE
        *out = profile;
#else
        memset(out, 0, sizeof(*out));
#endif
    }
}

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

static void h3_seed_hash(uint8_t out[FS_N], uint8_t domain,
                         const uint8_t randomizer[FS_N],
                         const uint8_t *msg, size_t msglen) {
    uint8_t state[40], first[64];
#ifdef FSPHINCS_PROFILE
    ++profile.total;
    ++profile.h3;
    profile.compression_blocks += (1u + FS_N + msglen + 9u + 63u) / 64u;
#endif
    first[0] = domain;
    memcpy(first + 1, randomizer, FS_N);
    sha256_inc_init(state);
    if (msglen < 31) {
        if (msglen) memcpy(first + 1 + FS_N, msg, msglen);
        sha256_inc_finalize(out, state, first, 1 + FS_N + msglen);
        return;
    }
    memcpy(first + 1 + FS_N, msg, 31);
    sha256_inc_blocks(state, first, 1);
    msg += 31;
    msglen -= 31;
    size_t blocks = msglen / 64;
    if (blocks) {
        sha256_inc_blocks(state, msg, blocks);
        msg += blocks * 64;
        msglen -= blocks * 64;
    }
    sha256_inc_finalize(out, state, msg, msglen);
}

static void put_u32(uint8_t out[4], uint32_t x) {
    out[0] = (uint8_t)(x >> 24); out[1] = (uint8_t)(x >> 16);
    out[2] = (uint8_t)(x >> 8); out[3] = (uint8_t)x;
}

static void put_u64(uint8_t out[8], uint64_t x) {
    for (int i = 7; i >= 0; --i) { out[i] = (uint8_t)x; x >>= 8; }
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

static void init_hash_prefix(uint8_t *buf, const uint8_t pub_seed[FS_N],
                             uint8_t domain, uint32_t layer, uint64_t node,
                             uint32_t tree) {
    memcpy(buf, pub_seed, FS_N);
    memset(buf + FS_N, 0, 32);
    buf[FS_N] = domain;
    put_u32(buf + FS_N + 4, layer);
    put_u64(buf + FS_N + 8, node);
    put_u32(buf + FS_N + 16, tree);
}

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
static void derive_node_seed(uint8_t out[FS_N], const uint8_t master[FS_N],
                             uint32_t layer, uint64_t node) {
    uint8_t addr[32];
    make_addr(addr, DOM_NODE_SEED, layer, node, 0, 0, 0);
    hash_parts(out, DOM_NODE_SEED, master, FS_N, addr, sizeof(addr), NULL, 0);
}

static void derive_leaf_secret(uint8_t out[FS_N], const uint8_t node_seed[FS_N],
                               uint32_t layer, uint64_t node,
                               uint32_t tree, uint32_t leaf) {
    uint8_t addr[32];
    make_addr(addr, DOM_LEAF_SECRET, layer, node, tree, 0, leaf);
    hash_parts(out, DOM_LEAF_SECRET, node_seed, FS_N, addr, sizeof(addr), NULL, 0);
}
#endif

#ifndef FSPHINCS_VERIFY_ONLY
static void hash_leaf(uint8_t out[FS_N], const uint8_t secret[FS_N],
                      const uint8_t pub_seed[FS_N], uint32_t layer,
                      uint64_t node, uint32_t tree, uint32_t leaf) {
    uint8_t input[FS_N + 32 + FS_N];
    init_hash_prefix(input, pub_seed, DOM_LEAF_HASH, layer, node, tree);
    put_u32(input + FS_N + 24, leaf);
    memcpy(input + FS_N + 32, secret, FS_N);
    counted_sha256(out, input, sizeof(input), DOM_LEAF_HASH);
}

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

static uint16_t md_index(const uint8_t md[FS_MFORS_MSG_BYTES], uint32_t tree) {
    return (uint16_t)(((uint16_t)md[2 * tree] << 8) | md[2 * tree + 1]);
}

#ifndef FSPHINCS_VERIFY_ONLY
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

static void aggregate_roots(uint8_t root[FS_N], const uint8_t *roots,
                            const uint8_t pub_seed[FS_N],
                            uint32_t layer, uint64_t node) {
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

static void root_to_pk(uint8_t pk[FS_MFORS_MSG_BYTES],
                       const uint8_t root[FS_N], const uint8_t pub_seed[FS_N],
                       uint32_t layer, uint64_t node) {
    uint8_t addr[32], seed[FS_N];
    make_addr(addr, DOM_H2, layer, node, FS_K, 0, 0);
    hash_parts(seed, DOM_H2, pub_seed, FS_N, addr, sizeof(addr), root, FS_N);
    expand(pk, FS_MFORS_MSG_BYTES, DOM_H2, seed, addr);
}

#ifndef FSPHINCS_VERIFY_ONLY
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

int fs_mfors_sign(uint8_t *sig, uint8_t pk[FS_MFORS_MSG_BYTES],
                  const uint8_t md[FS_MFORS_MSG_BYTES],
                  const uint8_t master_seed[FS_N],
                  const uint8_t pub_seed[FS_N],
                  uint32_t layer, uint64_t node) {
    uint8_t node_seed[FS_N], roots[FS_K * FS_N], aggregate[FS_N];
    derive_node_seed(node_seed, master_seed, layer, node);
    for (uint32_t i = 0; i < FS_K; ++i) {
        uint32_t idx = md_index(md, i);
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
#endif

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
        uint32_t idx = md_index(md, i);
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

static void h3(uint8_t md[FS_MFORS_MSG_BYTES], uint64_t *idx,
               const uint8_t randomizer[FS_N],
               const uint8_t *msg, size_t msglen) {
    uint8_t prefix = DOM_H3_SEED, seed[FS_N], addr[32], out[FS_H3_BYTES];
    h3_seed_hash(seed, prefix, randomizer, msg, msglen);
    make_addr(addr, DOM_H3_EXPAND, 0, 0, 0, 0, 0);
    expand(out, sizeof(out), DOM_H3_EXPAND, seed, addr);
    memcpy(md, out, FS_MFORS_MSG_BYTES);
    *idx = 0;
    for (uint32_t i = 0; i < 8; ++i)
        *idx = (*idx << 8) | out[FS_MFORS_MSG_BYTES + i];
    *idx >>= 4; /* retain the first 60 bits */
}

size_t fsphincs_publickeybytes(void) { return FS_PK_BYTES; }
size_t fsphincs_secretkeybytes(void) { return FS_SK_BYTES; }
size_t fsphincs_signaturebytes(void) { return FS_SIG_BYTES; }
size_t fsphincs_seedbytes(void) { return FS_SEED_BYTES; }

#ifndef FSPHINCS_VERIFY_ONLY
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

int fsphincs_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seed[FS_SEED_BYTES];
    randombytes(seed, sizeof(seed));
    return fsphincs_seed_keypair(pk, sk, seed);
}

int fsphincs_sign_signature_with_randomizer(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk, const uint8_t randomizer[FS_N]) {
    const uint8_t *master = sk, *pub_seed = sk + FS_N;
    uint8_t md[FS_MFORS_MSG_BYTES], value[FS_MFORS_MSG_BYTES];
    uint64_t idx;
    memcpy(sig, randomizer, FS_N);
    h3(md, &idx, randomizer, msg, msglen);
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

int fsphincs_sign_signature(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk) {
    uint8_t randomizer[FS_N];
    randombytes(randomizer, sizeof(randomizer));
    return fsphincs_sign_signature_with_randomizer(sig, siglen, msg, msglen,
                                                    sk, randomizer);
}
#endif

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

void fsphincs_verify_begin(uint8_t value[FS_MFORS_MSG_BYTES],
                           uint64_t *leaf_index,
                           const uint8_t randomizer[FS_N],
                           const uint8_t *msg, size_t msglen) {
    h3(value, leaf_index, randomizer, msg, msglen);
}

int fsphincs_verify_layer(uint8_t value[FS_MFORS_MSG_BYTES],
                          const uint8_t layer_sig[FS_MFORS_SIG_BYTES],
                          const uint8_t pub_seed[FS_N],
                          uint32_t layer, uint64_t node) {
    return fs_mfors_recover(value, layer_sig, value, pub_seed, layer, node);
}

int fsphincs_verify_finish(const uint8_t value[FS_MFORS_MSG_BYTES],
                           const uint8_t pk[FS_PK_BYTES]) {
    return ct_equal(value, pk + FS_N, FS_MFORS_MSG_BYTES) ? 0 : -1;
}

int fsphincs_trace_signature(uint8_t layer_values[(FS_H + 1u) *
                              FS_MFORS_MSG_BYTES],
                             uint64_t *leaf_index,
                             const uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *pk) {
    if (siglen != FS_SIG_BYTES) return -1;
    uint8_t md[FS_MFORS_MSG_BYTES], value[FS_MFORS_MSG_BYTES];
    uint64_t idx, node;
    h3(md, &idx, sig, msg, msglen);
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

int fsphincs_verify(const uint8_t *sig, size_t siglen,
                    const uint8_t *msg, size_t msglen, const uint8_t *pk) {
    return fsphincs_trace_signature(NULL, NULL, sig, siglen, msg, msglen, pk);
}
