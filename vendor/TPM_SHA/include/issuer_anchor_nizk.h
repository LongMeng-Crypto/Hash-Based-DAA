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
  DAA_ISSUER_ANCHOR_FSPHINCS = 2,
} daa_issuer_anchor_kind;

int daa_issuer_anchor_prepare(daa_tpm_sha_level level,
                              daa_tpm_sha_profile profile,
                              daa_issuer_anchor_kind kind);
int daa_issuer_anchor_stats(daa_tpm_sha_level level,
                            daa_tpm_sha_profile profile,
                            daa_issuer_anchor_kind kind,
                            daa_tpm_sha_stats* stats_out);
size_t daa_issuer_anchor_proof_bytes(daa_tpm_sha_level level,
                                     daa_tpm_sha_profile profile,
                                     daa_issuer_anchor_kind kind);

/* public_a/public_b are:
 *   SPHINCS+: 32-byte seeded SHA state and two 22-byte WOTS+ addresses;
 *   F-SPHINCS+: two 32-byte node addresses and two 32-byte leaf addresses.
 */
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

int daa_issuer_anchor_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    daa_issuer_anchor_kind kind,
    const uint8_t* public_a, size_t public_a_len,
    const uint8_t* public_b, size_t public_b_len,
    const uint8_t* anchor_value, size_t anchor_value_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* proof, size_t proof_len);

const char* daa_issuer_anchor_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
