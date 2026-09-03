/* SPDX-License-Identifier: MIT */
#ifndef DAA_TPM_SHA_H
#define DAA_TPM_SHA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum daa_tpm_sha_level {
  DAA_TPM_SHA_128 = 128,
  DAA_TPM_SHA_192 = 192,
  DAA_TPM_SHA_256 = 256,
} daa_tpm_sha_level;

typedef enum daa_tpm_sha_profile {
  DAA_TPM_SHA_SMALL = 1,
  DAA_TPM_SHA_FAST = 2,
} daa_tpm_sha_profile;

typedef enum daa_tpm_sha_status {
  DAA_TPM_SHA_OK = 0,
  DAA_TPM_SHA_INVALID_ARGUMENT = 1,
  DAA_TPM_SHA_BUFFER_TOO_SMALL = 2,
  DAA_TPM_SHA_INTERNAL_ERROR = 3,
} daa_tpm_sha_status;

typedef struct daa_tpm_sha_stats {
  size_t private_input_bits;
  size_t public_input_bits;
  size_t output_bits;
  size_t and_gates;
  size_t xor_gates;
  size_t total_nodes;
  size_t proof_bytes;
} daa_tpm_sha_stats;

size_t daa_tpm_sha_key_bytes(daa_tpm_sha_level level);
size_t daa_tpm_sha_digest_bytes(daa_tpm_sha_level level);

/* Lazily constructs and prepares both circuits for level. */
int daa_tpm_sha_prepare(daa_tpm_sha_level level, daa_tpm_sha_profile profile);
int daa_tpm_sha_join_stats(daa_tpm_sha_level level,
                           daa_tpm_sha_profile profile,
                           daa_tpm_sha_stats* stats_out);
int daa_tpm_sha_sign_stats(daa_tpm_sha_level level,
                           daa_tpm_sha_profile profile,
                           daa_tpm_sha_stats* stats_out);
size_t daa_tpm_sha_join_proof_bytes(daa_tpm_sha_level level,
                                    daa_tpm_sha_profile profile);
size_t daa_tpm_sha_sign_proof_bytes(daa_tpm_sha_level level,
                                    daa_tpm_sha_profile profile);

int daa_tpm_sha_evaluate_join(
    daa_tpm_sha_level level,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* gid, size_t gid_len,
    uint8_t* et_out, size_t et_len);

int daa_tpm_sha_evaluate_sign(
    daa_tpm_sha_level level,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* s, size_t s_len,
    const uint8_t* lid, size_t lid_len,
    const uint8_t* gid, size_t gid_len,
    uint8_t* slt_out, size_t slt_len,
    uint8_t* et_out, size_t et_len,
    uint8_t* hk_out, size_t hk_len);

/*
 * proof_len is in/out: on entry it is proof_out capacity; on return it is the
 * exact required/written length. Passing proof_out=NULL is a size query and
 * returns DAA_TPM_SHA_BUFFER_TOO_SMALL with proof_len set.
 * randomness must contain exactly 32 caller-provided bytes.
 */
int daa_tpm_sha_join_prove(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* et, size_t et_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* randomness, size_t randomness_len,
    uint8_t* proof_out, size_t* proof_len);

int daa_tpm_sha_join_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* et, size_t et_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* proof, size_t proof_len);

/* et is an internal wire: only lid, gid, slt and hk form the public statement. */
int daa_tpm_sha_sign_prove(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* s, size_t s_len,
    const uint8_t* lid, size_t lid_len,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* slt, size_t slt_len,
    const uint8_t* hk, size_t hk_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* randomness, size_t randomness_len,
    uint8_t* proof_out, size_t* proof_len);

int daa_tpm_sha_sign_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* lid, size_t lid_len,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* slt, size_t slt_len,
    const uint8_t* hk, size_t hk_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* proof, size_t proof_len);

/*
 * Chen et al. 2023 comparison relation, reimplemented here with SHA-2:
 *   slt = H(0x01 || sk  || lid)
 *   sst = H(0x04 || sk  || sid)
 *   et  = H(0x02 || sk  || gid)
 *   hk  = H(0x05 || sst)
 *   cet = H(0x06 || sst || et)
 * Only sk is private. sid, gid, lid, slt, hk and cet form the public
 * statement; sst and et are internal wires. These entry points are separate
 * from the DAA integration above, which continues to use Ours-3H.
 */
int daa_tpm_sha_chen23_prepare(daa_tpm_sha_level level,
                               daa_tpm_sha_profile profile);
int daa_tpm_sha_chen23_sign_stats(daa_tpm_sha_level level,
                                  daa_tpm_sha_profile profile,
                                  daa_tpm_sha_stats* stats_out);
size_t daa_tpm_sha_chen23_sign_proof_bytes(daa_tpm_sha_level level,
                                           daa_tpm_sha_profile profile);

int daa_tpm_sha_chen23_evaluate_sign(
    daa_tpm_sha_level level,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* sid, size_t sid_len,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* lid, size_t lid_len,
    uint8_t* slt_out, size_t slt_len,
    uint8_t* sst_out, size_t sst_len,
    uint8_t* et_out, size_t et_len,
    uint8_t* hk_out, size_t hk_len,
    uint8_t* cet_out, size_t cet_len);

int daa_tpm_sha_chen23_sign_prove(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* sid, size_t sid_len,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* lid, size_t lid_len,
    const uint8_t* slt, size_t slt_len,
    const uint8_t* hk, size_t hk_len,
    const uint8_t* cet, size_t cet_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* randomness, size_t randomness_len,
    uint8_t* proof_out, size_t* proof_len);

int daa_tpm_sha_chen23_sign_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* sid, size_t sid_len,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* lid, size_t lid_len,
    const uint8_t* slt, size_t slt_len,
    const uint8_t* hk, size_t hk_len,
    const uint8_t* cet, size_t cet_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* proof, size_t proof_len);

/* Error text is thread-local and remains valid until the next API call. */
const char* daa_tpm_sha_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
