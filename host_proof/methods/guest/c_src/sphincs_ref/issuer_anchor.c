#include "issuer_anchor.h"

#include <string.h>

#include "address.h"
#include "hash.h"
#include "merkle.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

#define ANCHOR_HEADER_BYTES 16u
#define ANCHOR_KIND_SPHINCS 1u
#define ANCHOR_WOTS_CHAINS 2u
#define ANCHOR_TOP_LEAF 0u

static const uint8_t anchor_magic[8] = {'D', 'A', 'A', 'A', 'N', 'C', '2', 0};

/* Returns the byte length of the fixed top-layer WOTS signature and path. */
static size_t top_signature_bytes(void) {
    return (size_t)SPX_WOTS_BYTES + (size_t)SPX_TREE_HEIGHT * SPX_N;
}

/* Returns the serialized size of a SPHINCS+ issuer-anchor certificate. */
size_t sphincs_issuer_anchor_certificate_bytes(void) {
    return ANCHOR_HEADER_BYTES + top_signature_bytes();
}

/* Serializes the parameter-bound SPHINCS+ anchor header. */
static void write_header(uint8_t out[ANCHOR_HEADER_BYTES]) {
    memcpy(out, anchor_magic, sizeof(anchor_magic));
    out[8] = ANCHOR_KIND_SPHINCS;
    out[9] = SPX_N;
    out[10] = SPX_WOTS_LEN;
    out[11] = SPX_D;
    out[12] = SPX_TREE_HEIGHT;
    out[13] = ANCHOR_WOTS_CHAINS;
    out[14] = ANCHOR_TOP_LEAF;
    out[15] = 0;
}

/* Checks that a certificate header and length match the compiled parameters. */
static int valid_header(const uint8_t *certificate, size_t certificate_len) {
    uint8_t expected[ANCHOR_HEADER_BYTES];
    if (certificate == NULL ||
        certificate_len != sphincs_issuer_anchor_certificate_bytes())
        return 0;
    write_header(expected);
    return memcmp(certificate, expected, sizeof(expected)) == 0;
}

/* Constructs the fixed top-layer WOTS and XMSS addresses used by Setup. */
static void top_addresses(uint32_t wots_addr[8], uint32_t tree_addr[8]) {
    memset(wots_addr, 0, 8 * sizeof(uint32_t));
    memset(tree_addr, 0, 8 * sizeof(uint32_t));
    set_layer_addr(tree_addr, SPX_D - 1u);
    set_tree_addr(tree_addr, 0);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, ANCHOR_TOP_LEAF);
    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
}

/* Generates the deterministic top-WOTS certificate bound to the issuer root. */
int sphincs_issuer_anchor_generate(uint8_t *certificate,
                                   size_t certificate_len,
                                   const uint8_t *pk,
                                   const uint8_t *sk) {
    uint8_t message[SPX_N] = {0};
    uint32_t wots_addr[8], tree_addr[8];
    spx_ctx ctx;

    if (certificate == NULL || pk == NULL || sk == NULL ||
        certificate_len != sphincs_issuer_anchor_certificate_bytes() ||
        memcmp(sk + 2 * SPX_N, pk, 2 * SPX_N) != 0)
        return -1;

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    top_addresses(wots_addr, tree_addr);

    write_header(certificate);
    merkle_sign(certificate + ANCHOR_HEADER_BYTES, message, &ctx,
                wots_addr, tree_addr, ANCHOR_TOP_LEAF);
    return memcmp(message, pk + SPX_N, SPX_N) == 0 ? 0 : -1;
}

/* Publicly reconstructs the top WOTS leaf and checks its path to PK.root. */
int sphincs_issuer_anchor_verify(const uint8_t *certificate,
                                 size_t certificate_len,
                                 const uint8_t *pk) {
    uint8_t message[SPX_N] = {0};
    uint8_t wots_pk[SPX_WOTS_BYTES], leaf[SPX_N], root[SPX_N];
    uint32_t wots_addr[8], tree_addr[8], wots_pk_addr[8] = {0};
    spx_ctx ctx;

    if (pk == NULL || !valid_header(certificate, certificate_len)) return -1;
    memcpy(ctx.pub_seed, pk, SPX_N);
    memset(ctx.sk_seed, 0, SPX_N);
    initialize_hash_function(&ctx);
    top_addresses(wots_addr, tree_addr);
    copy_keypair_addr(wots_pk_addr, wots_addr);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    const uint8_t *signature = certificate + ANCHOR_HEADER_BYTES;
    wots_pk_from_sig(wots_pk, signature, message, &ctx, wots_addr);
    thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);
    compute_root(root, leaf, ANCHOR_TOP_LEAF, 0,
                 signature + SPX_WOTS_BYTES, SPX_TREE_HEIGHT,
                 &ctx, tree_addr);
    return memcmp(root, pk + SPX_N, SPX_N) == 0 ? 0 : -1;
}

/* Exports the dual-chain seed relation consumed by the VOLEith prover. */
int sphincs_issuer_anchor_relation(uint8_t seed[SPX_N],
                                   uint8_t seeded_state[32],
                                   uint8_t compressed_addresses[44],
                                   uint8_t anchor_values[2 * SPX_N],
                                   const uint8_t *certificate,
                                   size_t certificate_len,
                                   const uint8_t *pk,
                                   const uint8_t *sk) {
    uint8_t expected[SPX_N];
    uint32_t address[8] = {0};
    spx_ctx ctx;

    if (seed == NULL || seeded_state == NULL || compressed_addresses == NULL ||
        anchor_values == NULL || pk == NULL || sk == NULL ||
        !valid_header(certificate, certificate_len) ||
        memcmp(sk + 2 * SPX_N, pk, 2 * SPX_N) != 0 ||
        sphincs_issuer_anchor_verify(certificate, certificate_len, pk) != 0)
        return -1;

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    set_layer_addr(address, SPX_D - 1u);
    set_tree_addr(address, 0);
    set_keypair_addr(address, ANCHOR_TOP_LEAF);
    set_hash_addr(address, 0);
    set_type(address, SPX_ADDR_TYPE_WOTSPRF);

    const uint8_t *wots_signature = certificate + ANCHOR_HEADER_BYTES;
    for (uint32_t chain = 0; chain < ANCHOR_WOTS_CHAINS; ++chain) {
        set_chain_addr(address, chain);
        prf_addr(expected, &ctx, address);
        if (memcmp(expected, wots_signature + (size_t)chain * SPX_N,
                   SPX_N) != 0)
            return -1;
        memcpy(compressed_addresses + (size_t)chain * 22u, address, 22);
        memcpy(anchor_values + (size_t)chain * SPX_N,
               wots_signature + (size_t)chain * SPX_N, SPX_N);
    }

    memcpy(seed, sk, SPX_N);
    memcpy(seeded_state, ctx.state_seeded, 32);
    return 0;
}
