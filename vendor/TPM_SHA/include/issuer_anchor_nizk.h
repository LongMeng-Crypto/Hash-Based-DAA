/* SPDX-License-Identifier: MIT */
#ifndef DAA_ISSUER_ANCHOR_NIZK_H
#define DAA_ISSUER_ANCHOR_NIZK_H

#include <stddef.h>
#include <stdint.h>

#include "tpm_sha.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum daa_issuer_anchor_kind {
  DAA_ISSUER_ANCHOR_SPHINCS = 1,
  DAA_ISSUER_ANCHOR_FSPHINCS = 4,
} daa_issuer_anchor_kind;

/* Prepares and caches the requested issuer-anchor circuit. */
int daa_issuer_anchor_prepare(daa_tpm_sha_level level,
                              daa_tpm_sha_profile profile,
                              daa_issuer_anchor_kind kind);
/* Returns circuit and proof-size statistics for one profile. */
int daa_issuer_anchor_stats(daa_tpm_sha_level level,
                            daa_tpm_sha_profile profile,
                            daa_issuer_anchor_kind kind,
                            daa_tpm_sha_stats* stats_out);
/* Returns the exact serialized proof size, or zero on error. */
size_t daa_issuer_anchor_proof_bytes(daa_tpm_sha_level level,
                                     daa_tpm_sha_profile profile,
                                     daa_issuer_anchor_kind kind);

/* public_a/public_b are:
 *   SPHINCS+: 32-byte seeded SHA state and two distinct 22-byte FORS PRF addresses;
 *   F-SPHINCS+: empty public_a and one (128) or two (192/256) 16-byte root leaf addresses.
 * F-SPHINCS+ kind 4 proves S_root with compact addresses; former kinds 2/3 are rejected.
 * The root seed is the shared 32-byte private witness; addresses/outputs are public.
 */
/* Generates a context-bound proof for the supplied public anchor statement. */
int daa_issuer_anchor_prove(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    daa_issuer_anchor_kind kind,
    const uint8_t* seed, size_t seed_len,
    const uint8_t* public_a, size_t public_a_len,
    const uint8_t* public_b, size_t public_b_len,
    const uint8_t* anchor_value, size_t anchor_value_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* randomness, size_t randomness_len,
    uint8_t* proof_out, size_t* proof_len);

/* Verifies a context-bound proof against its public anchor statement. */
int daa_issuer_anchor_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    daa_issuer_anchor_kind kind,
    const uint8_t* public_a, size_t public_a_len,
    const uint8_t* public_b, size_t public_b_len,
    const uint8_t* anchor_value, size_t anchor_value_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* proof, size_t proof_len);

/* Returns the thread-local diagnostic for the most recent API call. */
const char* daa_issuer_anchor_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
