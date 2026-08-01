#ifndef SPX_SHA2_H
#define SPX_SHA2_H

#include "params.h"

#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

#define SPX_SHA512_BLOCK_BYTES 128
#define SPX_SHA512_OUTPUT_BYTES 64

#if SPX_SHA256_OUTPUT_BYTES < SPX_N
    #error Linking against SHA-256 with N larger than 32 bytes is not supported
#endif

#define SPX_SHA256_ADDR_BYTES 22

#include <stddef.h>
#include <stdint.h>

void sha256_inc_init(uint8_t *state);
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

void sha512_inc_init(uint8_t *state);
void sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sha512_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
void sha512(uint8_t *out, const uint8_t *in, size_t inlen);

#define mgf1_256 SPX_NAMESPACE(mgf1_256)
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define mgf1_512 SPX_NAMESPACE(mgf1_512)
void mgf1_512(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define seed_state SPX_NAMESPACE(seed_state)
void seed_state(spx_ctx *ctx);

#ifdef SPHINCS_OPT_128S
void sha256_seeded_thash_128s_simple(uint8_t *out,
                                     const uint8_t *seeded_state,
                                     const uint32_t addr[8],
                                     const uint8_t *in,
                                     unsigned int inblocks);
void sha256_seeded_thash1_zk_wots_fast_128(uint8_t *out,
                                           const uint8_t *seeded_state,
                                           const uint8_t *addr,
                                           const uint8_t in[16]);
void sha256_zk_wots_fixed_chain(uint8_t *out,
                                const uint8_t seeded_state[32],
                                const uint8_t addr[32],
                                const uint8_t *sig_elem,
                                unsigned int start);
void sha256_wots_variable_pk_from_sig(uint8_t *pk,
                                      const uint8_t seeded_state[32],
                                      const uint8_t addr[32],
                                      const uint8_t *sig,
                                      const unsigned int *lengths);
#endif


#endif
