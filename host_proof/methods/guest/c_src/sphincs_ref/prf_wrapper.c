#include <string.h>
#include "hash.h"
#include "context.h"
#include "params.h"
#ifdef SPX_SHA2
#include "sha2.h"
#endif

// Implements prf one.
void sphincs_prf_one(
    unsigned char       *out,
    const unsigned char *pk_seed,
    const unsigned char *sk_seed,
    const unsigned char *adrs_bytes
) {
    spx_ctx ctx;
    memcpy(ctx.pub_seed, pk_seed, SPX_N);
    memcpy(ctx.sk_seed,  sk_seed, SPX_N);

#ifdef SPX_SHA2

    {
        uint8_t block[SPX_SHA256_BLOCK_BYTES];
        memcpy(block, pk_seed, SPX_N);
        memset(block + SPX_N, 0, SPX_SHA256_BLOCK_BYTES - SPX_N);
        sha256_inc_init(ctx.state_seeded);
        sha256_inc_blocks(ctx.state_seeded, block, 1);
    }
#else

    initialize_hash_function(&ctx);
#endif

    prf_addr(out, &ctx, (const uint32_t *)adrs_bytes);
}
