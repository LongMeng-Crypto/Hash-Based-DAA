#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"

#include "haraka.h"

// Implements thash.
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    SPX_VLA(uint8_t, buf, SPX_ADDR_BYTES + inblocks*SPX_N);
    unsigned char outbuf[32];
    unsigned char buf_tmp[64];

    if (inblocks == 1) {

        memset(buf_tmp, 0, 64);
        memcpy(buf_tmp, addr, 32);
        memcpy(buf_tmp + SPX_ADDR_BYTES, in, SPX_N);

        haraka512(outbuf, buf_tmp, ctx);
        memcpy(out, outbuf, SPX_N);
    } else {

        memcpy(buf, addr, 32);
        memcpy(buf + SPX_ADDR_BYTES, in, inblocks * SPX_N);

        haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks*SPX_N, ctx);
    }
}
