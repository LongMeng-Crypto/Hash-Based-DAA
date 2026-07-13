#include <string.h>
#include "hash.h"
#include "context.h"
#include "params.h"
#ifdef SPX_SHA2
#include "sha2.h"
#endif

/*
 * Compute one FORS PRF call:
 *   out = prf_addr(SK.seed, PK.seed, ADRS)
 *
 * out       : SPX_N bytes (sk_i output)
 * pk_seed   : SPX_N bytes (PK.seed)
 * sk_seed   : SPX_N bytes (SK.seed)  -- secret witness
 * adrs_bytes: 32 bytes (raw uint32_t[8] address in memory order)
 *
 * For the SHA-2 backend we initialize ONLY the SHA-256 state instead of
 * calling initialize_hash_function().  prf_addr() only reads state_seeded
 * (SHA-256) and never state_seeded_512, so the SHA-512 init that
 * initialize_hash_function() performs for n>=24 is pure waste inside the
 * zkVM guest where SHA-512 has no hardware syscall and runs in software.
 * This makes lambda=192 and lambda=256 as fast as lambda=128 for this proof.
 */
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
    /* Build one 64-byte SHA-256 block: PK.seed || zeros(64 - SPX_N).
     * sha256_inc_blocks processes exactly 64 bytes per block (inblocks=1). */
    {
        uint8_t block[SPX_SHA256_BLOCK_BYTES];
        memcpy(block, pk_seed, SPX_N);
        memset(block + SPX_N, 0, SPX_SHA256_BLOCK_BYTES - SPX_N);
        sha256_inc_init(ctx.state_seeded);
        sha256_inc_blocks(ctx.state_seeded, block, 1);
    }
#else
    /* For shake / haraka backends there is no state_seeded_512 issue;
     * fall back to the normal initialization path. */
    initialize_hash_function(&ctx);
#endif

    prf_addr(out, &ctx, (const uint32_t *)adrs_bytes);
}
