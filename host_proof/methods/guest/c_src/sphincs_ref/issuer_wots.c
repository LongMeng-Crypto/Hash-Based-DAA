#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "params.h"
#include "context.h"
#include "address.h"
#include "hash.h"
#include "thash.h"
#include "utils.h"
#include "merkle.h"
#include "wots.h"
#include "fors.h"
#include "issuer_wots.h"
#include "wotsx1.h"
#include "utilsx1.h"
#include "randombytes.h"

#ifdef DAA_WOTS_SUPPORTED

struct issuer_leaf_info {
    struct leaf_info_x1 wots;
    uint8_t *selected_leaf;
};

// Captures the selected WOTS leaf while the top XMSS tree is generated.
static void issuer_leaf(uint8_t *dest, const spx_ctx *ctx,
    uint32_t index, void *opaque) {
    struct issuer_leaf_info *info = opaque;
    wots_gen_leafx1(dest, ctx, index, &info->wots);
    if (index == 0) memcpy(info->selected_leaf, dest, SPX_N);
}

// Generates issuer keys, one WOTS secret key and its path in one tree traversal.
int sphincs_issuer_wots_seed_keypair(uint8_t *pk, uint8_t *sk,
    uint8_t *cert, size_t cert_len, uint8_t *witness, size_t witness_len,
    const uint8_t *seed) {
    if (!pk || !sk || !cert || !witness || !seed ||
        cert_len != sphincs_issuer_wots_certificate_bytes() ||
        witness_len != SPX_WOTS_BYTES) return -1;
    spx_ctx ctx = {0};
    struct issuer_leaf_info info = {0};
    unsigned steps[SPX_WOTS_LEN] = {0};
    uint32_t tree_addr[8] = {0};
    const uint8_t header[16] = {'D','A','A','W','O','T','S',1,
        SPX_N, SPX_WOTS_LEN, SPX_D, SPX_TREE_HEIGHT,0,0,0,0};
    memcpy(sk, seed, 3 * SPX_N);
    memcpy(pk, seed + 2 * SPX_N, SPX_N);
    memcpy(ctx.sk_seed, seed, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    memcpy(cert, header, sizeof(header));
    info.selected_leaf = cert + 16;
    info.wots.wots_sig = witness;
    info.wots.wots_sign_leaf = 0;
    info.wots.wots_steps = steps;
    set_layer_addr(tree_addr, SPX_D - 1);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    copy_subtree_addr(info.wots.leaf_addr, tree_addr);
    copy_subtree_addr(info.wots.pk_addr, tree_addr);
    set_type(info.wots.pk_addr, SPX_ADDR_TYPE_WOTSPK);
    treehashx1(sk + 3 * SPX_N, cert + 16 + SPX_N, &ctx, 0, 0,
        SPX_TREE_HEIGHT, issuer_leaf, tree_addr, &info);
    memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);
    return 0;
}

// Samples issuer keys and captures the fixed WOTS leaf during key generation.
int sphincs_issuer_wots_keypair(uint8_t *pk, uint8_t *sk,
    uint8_t *cert, size_t cert_len, uint8_t *witness, size_t witness_len) {
    uint8_t seed[3 * SPX_N];
    randombytes(seed, sizeof(seed));
    int result = sphincs_issuer_wots_seed_keypair(pk, sk, cert, cert_len,
        witness, witness_len, seed);
    memset(seed, 0, sizeof(seed));
    return result;
}

// Implements issuer wots generate.
int sphincs_issuer_wots_generate(uint8_t *cert, size_t cert_len,
    uint8_t *witness, size_t witness_len, const uint8_t *pk, const uint8_t *sk)
{
    if (cert_len != sphincs_issuer_wots_certificate_bytes()
        || witness_len != SPX_WOTS_BYTES || memcmp(pk, sk + 2 * SPX_N, 2 * SPX_N)) return -1;
    spx_ctx ctx = {0};
    uint32_t waddr[8] = {0}, taddr[8] = {0};
    uint8_t sig[SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N];
    uint8_t msg[SPX_N] = {0}, endpoints[SPX_WOTS_BYTES];
    const uint8_t header[16] = {'D','A','A','W','O','T','S',1,
        SPX_N, SPX_WOTS_LEN, SPX_D, SPX_TREE_HEIGHT,0,0,0,0};
    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);
    initialize_hash_function(&ctx);
    set_layer_addr(taddr, SPX_D - 1);
    set_type(taddr, SPX_ADDR_TYPE_HASHTREE);
    copy_subtree_addr(waddr, taddr);
    set_type(waddr, SPX_ADDR_TYPE_WOTS);
    merkle_sign(sig, msg, &ctx, waddr, taddr, 0);
    if (memcmp(msg, pk + SPX_N, SPX_N)) return -1;
    memset(msg, 0, sizeof(msg));
    wots_pk_from_sig(endpoints, sig, msg, &ctx, waddr);
    uint32_t paddr[8] = {0};
    copy_keypair_addr(paddr, waddr);
    set_type(paddr, SPX_ADDR_TYPE_WOTSPK);
    memcpy(cert, header, sizeof(header));
    thash(cert + 16, endpoints, SPX_WOTS_LEN, &ctx, paddr);
    memcpy(cert + 16 + SPX_N, sig + SPX_WOTS_BYTES, SPX_TREE_HEIGHT * SPX_N);
    set_type(waddr, SPX_ADDR_TYPE_WOTSPRF);
    set_hash_addr(waddr, 0);
    for (unsigned int i = 0; i < SPX_WOTS_LEN; ++i) {
        set_chain_addr(waddr, i);
        prf_addr(witness + i * SPX_N, &ctx, waddr);
    }
    return sphincs_issuer_wots_verify(cert, cert_len, pk)
        || sphincs_issuer_wots_relation(cert, cert_len, pk, witness, witness_len) ? -1 : 0;
}

// Implements issuer wots capability test.
int sphincs_issuer_wots_capability_test(const uint8_t *cert, const uint8_t *pk,
    const uint8_t *witness)
{
    spx_ctx ctx = {0};
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    uint8_t *sig = malloc(SPX_BYTES);
    if (!sig) return -1;
    int result = -1;
    for (unsigned int trial = 0; trial < 2; ++trial) {
        uint8_t msg[32] = {0}, digest[SPX_FORS_MSG_BYTES], root[SPX_N];
        uint8_t endpoints[SPX_WOTS_BYTES], leaf[SPX_N];
        uint64_t tree = 0;
        uint32_t index = 0;
        msg[0] = (uint8_t)trial;
        memset(sig, 0x63 + trial, SPX_BYTES);
        unsigned int counter;
        for (counter = 0; counter < (1u << 20); ++counter) {
            ull_to_bytes(sig, SPX_N, counter);
            hash_message(digest, &tree, &index, sig, pk, msg, sizeof(msg), &ctx);
            if ((tree >> (SPX_TREE_HEIGHT * (SPX_D - 2))) == bytes_to_ull(cert + 12, 4)) break;
        }
        if (counter == (1u << 20)) goto cleanup;
        uint32_t waddr[8] = {0}, paddr[8] = {0}, taddr[8] = {0};
        set_tree_addr(waddr, tree);
        set_keypair_addr(waddr, index);
        set_type(waddr, SPX_ADDR_TYPE_WOTS);
        uint8_t *cursor = sig + SPX_N;
        fors_pk_from_sig(root, cursor, digest, &ctx, waddr);
        cursor += SPX_FORS_BYTES;
        for (unsigned int layer = 0; layer < SPX_D - 1; ++layer) {
            memset(waddr, 0, sizeof(waddr));
            memset(paddr, 0, sizeof(paddr));
            memset(taddr, 0, sizeof(taddr));
            set_layer_addr(taddr, layer);
            set_tree_addr(taddr, tree);
            set_type(taddr, SPX_ADDR_TYPE_HASHTREE);
            copy_subtree_addr(waddr, taddr);
            set_keypair_addr(waddr, index);
            set_type(waddr, SPX_ADDR_TYPE_WOTS);
            copy_keypair_addr(paddr, waddr);
            set_type(paddr, SPX_ADDR_TYPE_WOTSPK);
            wots_pk_from_sig(endpoints, cursor, root, &ctx, waddr);
            cursor += SPX_WOTS_BYTES;
            thash(leaf, endpoints, SPX_WOTS_LEN, &ctx, paddr);
            compute_root(root, leaf, index, 0, cursor, SPX_TREE_HEIGHT, &ctx, taddr);
            cursor += SPX_TREE_HEIGHT * SPX_N;
            index = tree & ((1u << SPX_TREE_HEIGHT) - 1);
            tree >>= SPX_TREE_HEIGHT;
        }
        unsigned int lengths[SPX_WOTS_LEN];
        chain_lengths(lengths, root);
        memset(waddr, 0, sizeof(waddr));
        set_layer_addr(waddr, SPX_D - 1);
        set_keypair_addr(waddr, index);
        set_type(waddr, SPX_ADDR_TYPE_WOTS);
        for (unsigned int i = 0; i < SPX_WOTS_LEN; ++i) {
            set_chain_addr(waddr, i);
            memcpy(cursor + i * SPX_N, witness + i * SPX_N, SPX_N);
            for (unsigned int j = 0; j < lengths[i]; ++j) {
                set_hash_addr(waddr, j);
                thash(cursor + i * SPX_N, cursor + i * SPX_N, 1, &ctx, waddr);
            }
        }
        memcpy(cursor + SPX_WOTS_BYTES, cert + 16 + SPX_N, SPX_TREE_HEIGHT * SPX_N);
        if (crypto_sign_verify(sig, SPX_BYTES, msg, sizeof(msg), pk) != 0) goto cleanup;
    }
    result = 0;
cleanup:

    memset(sig, 0, SPX_BYTES);
    free(sig);
    return result;
}
#else

// Implements issuer wots generate.
int sphincs_issuer_wots_generate(uint8_t *cert, size_t cert_len, uint8_t *witness,
    size_t witness_len, const uint8_t *pk, const uint8_t *sk) { return -1; }

// Implements issuer wots capability test.
int sphincs_issuer_wots_capability_test(const uint8_t *cert, const uint8_t *pk,
    const uint8_t *witness) { return -1; }
#endif
