#ifndef FSPHINCS_SHA2_COMPAT_H
#define FSPHINCS_SHA2_COMPAT_H

#include <stddef.h>
#include <stdint.h>

/* Shared sphincs_ref SHA-2 ABI, without importing its parameter/context types. */

/* Hashes an arbitrary byte string with SHA-256. */
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);
/* Initializes the incremental SHA-256 chaining state and byte counter. */
void sha256_inc_init(uint8_t *state);
/* Compresses complete SHA-256 blocks into an incremental state. */
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
/* Pads the remaining bytes and returns the full SHA-256 digest. */
void sha256_inc_finalize(uint8_t *out, uint8_t *state,
                         const uint8_t *in, size_t inlen);

/* Initializes the incremental SHA-512 chaining state and byte counter. */
void sha512_inc_init(uint8_t *state);
/* Compresses complete SHA-512 blocks into an incremental state. */
void sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
/* Pads the remaining bytes and returns the full SHA-512 digest. */
void sha512_inc_finalize(uint8_t *out, uint8_t *state,
                         const uint8_t *in, size_t inlen);

#endif
