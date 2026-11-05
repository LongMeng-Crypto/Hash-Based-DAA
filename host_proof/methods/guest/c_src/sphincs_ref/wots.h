#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>

#include "params.h"
#include "context.h"

#define wots_pk_from_sig SPX_NAMESPACE(wots_pk_from_sig)
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8]);

#define chain_lengths SPX_NAMESPACE(chain_lengths)
void chain_lengths(unsigned int *lengths, const unsigned char *msg);

#endif
