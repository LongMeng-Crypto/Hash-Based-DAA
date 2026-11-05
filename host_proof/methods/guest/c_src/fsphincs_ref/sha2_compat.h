#ifndef FSPHINCS_SHA2_COMPAT_H
#define FSPHINCS_SHA2_COMPAT_H

#include <stddef.h>
#include <stdint.h>

void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

void sha256_inc_init(uint8_t *state);

void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);

void sha256_inc_finalize(uint8_t *out, uint8_t *state,
                         const uint8_t *in, size_t inlen);

void sha512_inc_init(uint8_t *state);

void sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);

void sha512_inc_finalize(uint8_t *out, uint8_t *state,
                         const uint8_t *in, size_t inlen);

#endif
