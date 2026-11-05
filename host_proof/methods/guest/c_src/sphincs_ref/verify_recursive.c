#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "context.h"
#include "hash.h"
#include "sha2.h"
#include "thash.h"
#include "sha2_offsets.h"
#include "address.h"

#if !defined(DAA_SPHINCS_VERIFY)
#error "recursive verifier requires DAA_SPHINCS_VERIFY"
#endif

// Implements put u32 be.
static void put_u32_be(unsigned char *out, uint32_t x)
{
    out[0] = (unsigned char)(x >> 24);
    out[1] = (unsigned char)(x >> 16);
    out[2] = (unsigned char)(x >> 8);
    out[3] = (unsigned char)x;
}

// Implements bytes to u64 be.
static uint64_t bytes_to_u64_be(const unsigned char *in, unsigned int inlen)
{
    uint64_t out = 0;
    for (unsigned int i = 0; i < inlen; i++) {
        out = (out << 8) | in[i];
    }
    return out;
}

// Implements addr set tree.
static void addr_set_tree(unsigned char addr[32], uint64_t tree)
{
    for (int i = 7; i >= 0; i--) {
        addr[SPX_OFFSET_TREE + i] = (unsigned char)tree;
        tree >>= 8;
    }
}

// Implements addr copy subtree.
static void addr_copy_subtree(unsigned char out[32], const unsigned char in[32])
{
    memcpy(out, in, SPX_OFFSET_TREE + 8);
}

// Implements addr copy keypair.
static void addr_copy_keypair(unsigned char out[32], const unsigned char in[32])
{
    memcpy(out, in, SPX_OFFSET_TREE + 8);
    memcpy(out + SPX_OFFSET_KP_ADDR, in + SPX_OFFSET_KP_ADDR, 4);
}

// Implements thash opt.
static void thash_node(unsigned char *out, const unsigned char *in,
                      unsigned int inblocks, const spx_ctx *ctx,
                      const unsigned char addr[32])
{
#if SPX_N == 16 && !SPX_SHA512
    sha256_seeded_thash_128s_simple(out, ctx->state_seeded, (const uint32_t *)addr, in, inblocks);
#else
    thash(out, in, inblocks, ctx, (uint32_t *)addr);
#endif
}

// Computes root 128s.
static void compute_root_from_auth(unsigned char *root, const unsigned char *leaf,
                              uint32_t leaf_idx, uint32_t idx_offset,
                              const unsigned char *auth_path,
                              uint32_t tree_height, const spx_ctx *ctx,
                              unsigned char addr[32])
{

    unsigned char buffer[2 * SPX_N];

    if (leaf_idx & 1) {
        memcpy(buffer, auth_path, SPX_N);
        memcpy(buffer + SPX_N, leaf, SPX_N);
    } else {
        memcpy(buffer, leaf, SPX_N);
        memcpy(buffer + SPX_N, auth_path, SPX_N);
    }
    auth_path += SPX_N;

    for (uint32_t i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        addr[SPX_OFFSET_TREE_HGT] = (unsigned char)(i + 1);
        put_u32_be(addr + SPX_OFFSET_TREE_INDEX, leaf_idx + idx_offset);

        if (leaf_idx & 1) {
            thash_node(buffer + SPX_N, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N);
        } else {
            thash_node(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N, auth_path, SPX_N);
        }
        auth_path += SPX_N;
    }

    leaf_idx >>= 1;
    idx_offset >>= 1;
    addr[SPX_OFFSET_TREE_HGT] = (unsigned char)tree_height;
    put_u32_be(addr + SPX_OFFSET_TREE_INDEX, leaf_idx + idx_offset);
    thash_node(root, buffer, 2, ctx, addr);
}

// Implements message to indices 128s.
static void message_to_fors_indices(uint32_t indices[SPX_FORS_TREES],
                                    const unsigned char *m)
{
    unsigned int offset = 0;
    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        uint32_t idx = 0;
        for (unsigned int j = 0; j < SPX_FORS_HEIGHT; j++) {
            idx |= ((uint32_t)((m[offset >> 3] >> (offset & 7)) & 1u)) << j;
            offset++;
        }
        indices[i] = idx;
    }
}

// Implements fors pk from sig 128s.
static void fors_public_key_from_signature(unsigned char *pk, const unsigned char *sig,
                                  const unsigned char *m, const spx_ctx *ctx,
                                  const unsigned char fors_addr[32])
{

    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    unsigned char fors_tree_addr[32] = {0};
    unsigned char fors_pk_addr[32] = {0};

    addr_copy_keypair(fors_tree_addr, fors_addr);
    addr_copy_keypair(fors_pk_addr, fors_addr);
    fors_tree_addr[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_FORSTREE;
    fors_pk_addr[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_FORSPK;

    message_to_fors_indices(indices, m);

    for (unsigned int i = 0; i < SPX_FORS_TREES; i++) {
        uint32_t idx_offset = i * (1u << SPX_FORS_HEIGHT);
        fors_tree_addr[SPX_OFFSET_TREE_HGT] = 0;
        put_u32_be(fors_tree_addr + SPX_OFFSET_TREE_INDEX, indices[i] + idx_offset);

        thash_node(leaf, sig, 1, ctx, fors_tree_addr);
        sig += SPX_N;

        compute_root_from_auth(roots + i * SPX_N, leaf, indices[i], idx_offset,
                          sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    thash_node(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}

// Implements chain lengths 128s.
static void wots_chain_lengths(unsigned int lengths[SPX_WOTS_LEN],
                               const unsigned char *msg)
{
    unsigned int in = 0;
    unsigned int out = 0;
    unsigned int bits = 0;
    unsigned char total = 0;

    for (unsigned int consumed = 0; consumed < SPX_WOTS_LEN1; consumed++) {
        if (bits == 0) {
            total = msg[in++];
            bits = 8;
        }
        bits -= SPX_WOTS_LOGW;
        lengths[out++] = (total >> bits) & (SPX_WOTS_W - 1);
    }

    unsigned int csum = 0;
    for (unsigned int i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - lengths[i];
    }
    csum <<= ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);

    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    for (int i = (int)sizeof(csum_bytes) - 1; i >= 0; i--) {
        csum_bytes[i] = (unsigned char)csum;
        csum >>= 8;
    }

    in = 0;
    bits = 0;
    total = 0;
    for (unsigned int consumed = 0; consumed < SPX_WOTS_LEN2; consumed++) {
        if (bits == 0) {
            total = csum_bytes[in++];
            bits = 8;
        }
        bits -= SPX_WOTS_LOGW;
        lengths[out++] = (total >> bits) & (SPX_WOTS_W - 1);
    }
}

// Implements zk fixed chain complete 128s.
static void wots_fixed_chain_complete(unsigned char *out,
                                         const unsigned char *sig_elem,
                                         unsigned int start,
                                         const spx_ctx *ctx,
                                         unsigned char addr[32])
{
    sha256_zk_wots_fixed_chain(out, ctx->state_seeded, addr,
                              sig_elem, start);

}

// Implements wots pk from sig 128s.
static void wots_public_key_from_signature(unsigned char *pk, const unsigned char *sig,
                                  const unsigned char *msg, const spx_ctx *ctx,
                                  unsigned char addr[32])
{

    unsigned int lengths[SPX_WOTS_LEN];
    wots_chain_lengths(lengths, msg);

#if !defined(DAA_ZK_WOTS)
    sha256_wots_variable_pk_from_sig(pk, ctx->state_seeded, addr, sig,
                                     lengths);
#else
    for (unsigned int i = 0; i < SPX_WOTS_LEN; i++) {
        unsigned char *out = pk + i * SPX_N;
        addr[SPX_OFFSET_CHAIN_ADDR] = (unsigned char)i;

        wots_fixed_chain_complete(out, sig + i * SPX_N, lengths[i], ctx, addr);
    }
#endif
}

// Implements crypto sign verify.
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{

    if (siglen != SPX_BYTES) {
        return -1;
    }

    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    uint64_t tree;
    uint32_t idx_leaf;
    unsigned char wots_addr[32] = {0};
    unsigned char tree_addr[32] = {0};
    unsigned char wots_pk_addr[32] = {0};

    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);

    wots_addr[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_WOTS;
    tree_addr[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_HASHTREE;
    wots_pk_addr[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_WOTSPK;

    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    addr_set_tree(wots_addr, tree);
    put_u32_be(wots_addr + SPX_OFFSET_KP_ADDR, idx_leaf);

    fors_public_key_from_signature(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (unsigned int i = 0; i < SPX_D; i++) {
        tree_addr[SPX_OFFSET_LAYER] = (unsigned char)i;
        addr_set_tree(tree_addr, tree);

        addr_copy_subtree(wots_addr, tree_addr);
        put_u32_be(wots_addr + SPX_OFFSET_KP_ADDR, idx_leaf);
        wots_addr[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_WOTS;

        addr_copy_keypair(wots_pk_addr, wots_addr);
        wots_pk_addr[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_WOTSPK;

        wots_public_key_from_signature(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES;

        thash_node(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        compute_root_from_auth(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                          &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (uint32_t)(tree & ((1u << SPX_TREE_HEIGHT) - 1));
        tree >>= SPX_TREE_HEIGHT;
    }

    return memcmp(root, pub_root, SPX_N) == 0 ? 0 : -1;
}
