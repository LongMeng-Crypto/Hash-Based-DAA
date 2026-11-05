#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"
#include "sha2.h"

#if SPX_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);
#endif

// Implements thash.
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    if (inblocks == 1) {
    } else if (inblocks == 2) {
    } else {
    }

#if SPX_SHA512
    if (inblocks > 1) {
	thash_512(out, in, inblocks, ctx, addr);
        return;
    }
#endif

#if defined(DAA_SHA256_SYSCALL) && SPX_N == 16 && !SPX_SHA512
    sha256_seeded_thash_128s_simple(out, ctx->state_seeded, addr, in, inblocks);
    return;
#endif

    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t sha2_state[40];
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}

#if SPX_SHA512
// Implements thash 512.
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    uint8_t sha2_state[72];
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha512_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    memcpy(out, outbuf, SPX_N);
}
#endif
