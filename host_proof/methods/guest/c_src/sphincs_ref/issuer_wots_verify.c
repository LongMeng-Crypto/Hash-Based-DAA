#include <string.h>
#include "params.h"
#include "context.h"
#include "hash.h"
#include "address.h"
#include "thash.h"
#include "utils.h"
#include "sha2.h"
#include "issuer_wots.h"

#define HEADER_BYTES 16

#ifdef DAA_WOTS_SUPPORTED

// Implements issuer wots certificate bytes.
size_t sphincs_issuer_wots_certificate_bytes(void)
{
    return HEADER_BYTES + (1 + SPX_TREE_HEIGHT) * SPX_N;
}

// Implements issuer wots witness bytes.
size_t sphincs_issuer_wots_witness_bytes(void)
{
    return SPX_WOTS_BYTES;
}

// Implements certificate header.
static int certificate_header(const uint8_t *cert, size_t len)
{
    const uint8_t header[12] = {'D','A','A','W','O','T','S',1,
        SPX_N, SPX_WOTS_LEN, SPX_D, SPX_TREE_HEIGHT};
    return len == sphincs_issuer_wots_certificate_bytes()
        && memcmp(cert, header, sizeof(header)) == 0
        && bytes_to_ull(cert + 12, 4) < (1u << SPX_TREE_HEIGHT);
}

// Implements issuer wots verify.
int sphincs_issuer_wots_verify(const uint8_t *cert, size_t len, const uint8_t *pk)
{
    if (!certificate_header(cert, len)) return -1;
    spx_ctx ctx = {0};
    uint32_t addr[8] = {0};
    uint8_t root[SPX_N];
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    set_layer_addr(addr, SPX_D - 1);
    set_type(addr, SPX_ADDR_TYPE_HASHTREE);
    compute_root(root, cert + HEADER_BYTES, (uint32_t)bytes_to_ull(cert + 12, 4),
        0, cert + HEADER_BYTES + SPX_N, SPX_TREE_HEIGHT, &ctx, addr);
    return memcmp(root, pk + SPX_N, SPX_N) == 0 ? 0 : -1;
}

// Implements issuer wots relation.
int sphincs_issuer_wots_relation(const uint8_t *cert, size_t len,
    const uint8_t *pk, const uint8_t *witness, size_t witness_len)
{
    if (!certificate_header(cert, len) || witness_len != SPX_WOTS_BYTES) return -1;
    spx_ctx ctx = {0};
    uint32_t addr[8] = {0};
    uint8_t endpoints[SPX_WOTS_BYTES], leaf[SPX_N];
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);
    set_layer_addr(addr, SPX_D - 1);
    set_keypair_addr(addr, (uint32_t)bytes_to_ull(cert + 12, 4));
    set_type(addr, SPX_ADDR_TYPE_WOTS);
    for (unsigned int i = 0; i < SPX_WOTS_LEN; ++i) {
        set_chain_addr(addr, i);
        sha256_zk_wots_fixed_chain(endpoints + i * SPX_N, ctx.state_seeded,
            (const uint8_t *)addr, witness + i * SPX_N, 0);
    }

    uint32_t pk_addr[8] = {0};
    copy_keypair_addr(pk_addr, addr);
    set_type(pk_addr, SPX_ADDR_TYPE_WOTSPK);
    thash(leaf, endpoints, SPX_WOTS_LEN, &ctx, pk_addr);
    return memcmp(leaf, cert + HEADER_BYTES, SPX_N) == 0 ? 0 : -1;
}
#else

// Implements issuer wots certificate bytes.
size_t sphincs_issuer_wots_certificate_bytes(void) { return 0; }

// Implements issuer wots witness bytes.
size_t sphincs_issuer_wots_witness_bytes(void) { return 0; }

// Implements issuer wots verify.
int sphincs_issuer_wots_verify(const uint8_t *cert, size_t len, const uint8_t *pk) { return -1; }

// Implements issuer wots relation.
int sphincs_issuer_wots_relation(const uint8_t *cert, size_t len, const uint8_t *pk,
    const uint8_t *witness, size_t witness_len) { return -1; }
#endif
