/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_192s.h"
#include "aes.h"
#include "compat.h"
#include "faest_impl.h"
#include "instances.h"
#include "owf.h"
#include "parameters.h"
#include "randomness.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

// AES block size is always 128-bit = 16 bytes
#define AES128_BLK_BYTES 16

// KEY_BYTES: size of sk_u and s (LAMBDA/8 bytes)
#define KEY_BYTES (192 / 8)

/*
  TPM-credential layout:

  AES-128 (LAMBDA=128):  3 AES-128 calls
    slt  = AES128_{sk_u}(lid)           (16 bytes)
    et_u = AES128_{sk_u}(gid)           (16 bytes, transient — NOT stored in sk)
    hk   = AES128_{s}(et_u)             (16 bytes)

    pk = lid(16) || gid(16) || slt(16) || hk(16)   = 64 bytes
    sk = lid(16) || gid(16) || sk_u(16) || s(16)   = 64 bytes

  AES-192 (LAMBDA=192):  6 AES-192 calls (beta=2 pattern)
    slt  = AES192_{sk_u}(lid) || AES192_{sk_u}(lid⊕1)     (32 bytes)
    et_u = AES192_{sk_u}(gid) || AES192_{sk_u}(gid⊕1)     (32 bytes, transient)
    hk   = AES192_{s}(et_u[0:16]) || AES192_{s}(et_u[16:32]) (32 bytes)

    pk = lid(16) || gid(16) || slt(32) || hk(32)   = 96 bytes
    sk = lid(16) || gid(16) || sk_u(24) || s(24)   = 80 bytes

  AES-256 (LAMBDA=256):  6 AES-256 calls (beta=2 pattern)
    slt  = AES256_{sk_u}(lid) || AES256_{sk_u}(lid⊕1)     (32 bytes)
    et_u = AES256_{sk_u}(gid) || AES256_{sk_u}(gid⊕1)     (32 bytes, transient)
    hk   = AES256_{s}(et_u[0:16]) || AES256_{s}(et_u[16:32]) (32 bytes)

    pk = lid(16) || gid(16) || slt(32) || hk(32)   = 96 bytes
    sk = lid(16) || gid(16) || sk_u(32) || s(32)   = 96 bytes
*/

// ---- public key layout: lid || gid || slt || hk ----
#define PK_LID(pk)    (pk)
#define PK_GID(pk)    (&(pk)[AES128_BLK_BYTES])
#define PK_SLT(pk)    (&(pk)[2 * AES128_BLK_BYTES])
#define PK_HK(pk)     (&(pk)[2 * AES128_BLK_BYTES + 2 * AES128_BLK_BYTES])

// FAEST "OWF view" of the public key:
#define PK_INPUT(pk)  (pk)                             // lid || gid  (2 x 16 bytes)
#define PK_OUTPUT(pk) (&(pk)[2 * AES128_BLK_BYTES])   // slt || hk

// ---- secret key layout: (lid||gid) || (sk_u||s) ----
#define SK_INPUT(sk)  (sk)                             // lid || gid  (2 x 16 bytes)
#define SK_SKU(sk)    (&(sk)[2 * AES128_BLK_BYTES])   // sk_u  (KEY_BYTES)
#define SK_S(sk)      (&(sk)[2 * AES128_BLK_BYTES + KEY_BYTES])  // s (KEY_BYTES)

// Keep legacy naming for bit restriction check:
#define SK_KEY(sk)    SK_SKU(sk)

// Sanity checks
static_assert(96 == 32 + 64, "invalid public key size");
// sk stores OWF input (lid||gid = 2*16) + sk_u (KEY_BYTES) + s (KEY_BYTES)
static_assert(80 == 32 + 2 * (192 / 8), "invalid secret key size");

static_assert(32  == 2 * AES128_BLK_BYTES, "OWF_INPUT_SIZE must be 2 x 16 bytes (lid||gid)");
// PK_SIZE = lid(16)+gid(16) + slt(BETA*16)+hk(BETA*16)
static_assert(96 == 2 * AES128_BLK_BYTES + 2 * 2 * AES128_BLK_BYTES, "PK_SIZE mismatch");
static_assert(80 == 2 * AES128_BLK_BYTES + 2 * (192 / 8), "SK_SIZE mismatch");

// ---------- TPM OWF helpers (dispatch on LAMBDA) ----------

// Compute slt = AES_{sk_u}(lid) (+ second block for LAMBDA >= 192)
static inline void tpm_owf_slt(const uint8_t* sk_u, const uint8_t* lid, uint8_t* slt_out) {
#if 192 == 256
  owf_256(sk_u, lid, slt_out);  // AES256_{sk_u}(lid) || AES256_{sk_u}(lid⊕1)
#elif 192 == 192
  owf_192(sk_u, lid, slt_out);  // AES192_{sk_u}(lid) || AES192_{sk_u}(lid⊕1)
#else
  owf_128(sk_u, lid, slt_out);  // AES128_{sk_u}(lid)
#endif
}

// Compute et_u = AES_{sk_u}(gid) (+ second block for LAMBDA >= 192)
static inline void tpm_owf_etu(const uint8_t* sk_u, const uint8_t* gid, uint8_t* etu_out) {
#if 192 == 256
  owf_256(sk_u, gid, etu_out);  // AES256_{sk_u}(gid) || AES256_{sk_u}(gid⊕1)
#elif 192 == 192
  owf_192(sk_u, gid, etu_out);  // AES192_{sk_u}(gid) || AES192_{sk_u}(gid⊕1)
#else
  owf_128(sk_u, gid, etu_out);  // AES128_{sk_u}(gid)
#endif
}

// Compute hk = AES_{s}(et_u) (et_u treated as 1 or 2 independent AES-128 blocks)
static inline void tpm_owf_hk(const uint8_t* s, const uint8_t* et_u, uint8_t* hk_out) {
#if 192 == 256
  // AES256_{s}(et_u[0:16]) || AES256_{s}(et_u[16:32])
  // Two independent 16-byte blocks under same 256-bit key — use ECB
  generic_aes_ecb_t ctx;
  generic_aes_ecb_new(&ctx, s, 256);
  generic_aes_ecb_encrypt(&ctx, hk_out, et_u, 2);
  generic_aes_ecb_free(&ctx);
#elif 192 == 192
  // AES192_{s}(et_u[0:16]) || AES192_{s}(et_u[16:32])
  // Two independent 16-byte blocks under same 192-bit key — use ECB
  generic_aes_ecb_t ctx;
  generic_aes_ecb_new(&ctx, s, 192);
  generic_aes_ecb_encrypt(&ctx, hk_out, et_u, 2);
  generic_aes_ecb_free(&ctx);
#else
  owf_128(s, et_u, hk_out);   // AES128_{s}(et_u)
#endif
}

// et_u is always BETA*16 bytes (two AES-128 output blocks for BETA=2)
#define ETU_BYTES (2 * AES128_BLK_BYTES)

// Compute both outputs when et_u is already available. This avoids
// recomputing AES_{sk_u}(gid) during private-key unpacking.
static inline void tpm_credential_eval_outputs_with_etu(const uint8_t* sk, const uint8_t* et_u,
                                                        uint8_t* slt_out, uint8_t* hk_out) {
  const uint8_t* lid = SK_INPUT(sk);
  tpm_owf_slt(SK_SKU(sk), lid, slt_out);
  tpm_owf_hk(SK_S(sk), et_u, hk_out);
}

// Compute both outputs: slt and hk (et_u is transient)
static inline void tpm_credential_eval_outputs(const uint8_t* sk, uint8_t* slt_out, uint8_t* hk_out) {
  const uint8_t* gid = SK_INPUT(sk) + AES128_BLK_BYTES;

  // et_u computed transiently on stack (BETA*16 bytes)
  uint8_t et_u[ETU_BYTES];

  tpm_owf_etu(SK_SKU(sk), gid, et_u);
  tpm_credential_eval_outputs_with_etu(sk, et_u, slt_out, hk_out);

  faest_explicit_bzero(et_u, sizeof(et_u));
}

int FAEST_CALLING_CONVENTION faest_192s_keygen(uint8_t* pk, uint8_t* sk) {
  if (!pk || !sk) {
    return -1;
  }

  // Sample sk_u with FAEST’s “first two bits not both 1” restriction
  bool done = false;
  while (!done) {
    rand_bytes(SK_SKU(sk), KEY_BYTES);
    done = (ptr_get_bit(SK_SKU(sk), 0) & ptr_get_bit(SK_SKU(sk), 1)) == 0;
    faest_declassify(&done, sizeof(done));
  }

  // Sample s (unrestricted)
  rand_bytes(SK_S(sk), KEY_BYTES);

  // Sample public inputs (lid||gid) and store in sk for API-compatibility
  rand_bytes(SK_INPUT(sk), 2 * AES128_BLK_BYTES);
  faest_declassify(SK_INPUT(sk), 2 * AES128_BLK_BYTES);

  // Fill pk inputs (lid || gid)
  memcpy(PK_LID(pk), SK_INPUT(sk), 2 * AES128_BLK_BYTES);

  // Compute pk outputs: slt || hk (et_u computed transiently inside)
  tpm_credential_eval_outputs(sk, PK_SLT(pk), PK_HK(pk));

  // declassify public key
  faest_declassify(pk, 96);
  return 0;
}

int FAEST_CALLING_CONVENTION faest_192s_unpack_private_key(faest_192s_unpacked_private_key_t* unpacked_sk, const uint8_t* sk) {
  if (!unpacked_sk || !sk) {
    return -1;
  }

  // OWF input = lid||gid (2 x 16 bytes)
  memcpy(unpacked_sk->owf_input, SK_INPUT(sk), sizeof(unpacked_sk->owf_input));

  // Compute et_u transiently: AES_{sk_u}(gid) [ETU_BYTES = BETA*16 output bytes]
  const uint8_t* gid = SK_INPUT(sk) + AES128_BLK_BYTES;
  uint8_t et_u[ETU_BYTES];
  tpm_owf_etu(SK_SKU(sk), gid, et_u);

  // Pack owf_key = sk_u(KEY_BYTES) || et_u(ETU_BYTES) || s(KEY_BYTES)
  memcpy(unpacked_sk->owf_key,                         SK_SKU(sk), KEY_BYTES);
  memcpy(unpacked_sk->owf_key + KEY_BYTES,             et_u,       ETU_BYTES);
  memcpy(unpacked_sk->owf_key + KEY_BYTES + ETU_BYTES, SK_S(sk),   KEY_BYTES);

  // OWF output = slt||hk (slt at offset 0, hk at offset ETU_BYTES).
  // Reuse the et_u computed above instead of recomputing AES_{sk_u}(gid).
  tpm_credential_eval_outputs_with_etu(sk, et_u, unpacked_sk->owf_output,
                                       unpacked_sk->owf_output + ETU_BYTES);
  faest_declassify(unpacked_sk->owf_output, sizeof(unpacked_sk->owf_output));
  faest_explicit_bzero(et_u, sizeof(et_u));

  const faest_paramset_t* params = faest_get_paramset(FAEST_192S);

  /*
  * TPM-credential witness extension:
  *   owf_key   = sk_u || et_u || s   (3 * KEY_BYTES)
  *   owf_input = lid  || gid         (2 * 16 bytes)
  *
  * aes_extend_witness() builds the witness for the ZK proof.
  * et_u is in owf_key[KEY_BYTES..2*KEY_BYTES] and will be appended
  * to the witness tail so the verifier can link the chained AES calls.
  */
  aes_extend_witness(unpacked_sk->witness, unpacked_sk->owf_key, unpacked_sk->owf_input, params);

  return 0;
}

int FAEST_CALLING_CONVENTION faest_192s_validate_keypair(const uint8_t* pk, const uint8_t* sk) {
  if (!sk || !pk) {
    return -1;
  }

  // Check the bit restriction on sk_u
  if ((ptr_get_bit(SK_SKU(sk), 0) & ptr_get_bit(SK_SKU(sk), 1)) != 0) {
    return 1;
  }

  // Recompute pk = lid||gid||slt||hk and compare (et_u computed transiently inside)
  uint8_t pk_check[96];
  memcpy(PK_INPUT(pk_check), SK_INPUT(sk), 2 * AES128_BLK_BYTES);
  tpm_credential_eval_outputs(sk, PK_SLT(pk_check), PK_HK(pk_check));

  return faest_timingsafe_bcmp(pk_check, pk, sizeof(pk_check)) == 0 ? 0 : 2;
}

int FAEST_CALLING_CONVENTION faest_192s_sign_with_randomness(const uint8_t* sk, const uint8_t* message, size_t message_len, const uint8_t* rho, size_t rho_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_192S_SIGNATURE_SIZE ||
      (!rho && rho_len) || (!message && message_len)) {
    return -1;
  }

  faest_192s_unpacked_private_key_t unpacked_sk;
  int ret = faest_192s_unpack_private_key(&unpacked_sk, sk);
  if (ret) {
    faest_192s_clear_unpacked_private_key(&unpacked_sk);
    return ret;
  }

  ret = faest_192s_unpacked_sign_with_randomness(&unpacked_sk, message, message_len, rho, rho_len, signature, signature_len);
  faest_192s_clear_unpacked_private_key(&unpacked_sk);
  return ret;
}

int FAEST_CALLING_CONVENTION faest_192s_sign(const uint8_t* sk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_192S_SIGNATURE_SIZE ||
      (!message && message_len)) {
    return -1;
  }

  uint8_t rho[FAEST_192S_LAMBDA / 8];
  rand_bytes(rho, sizeof(rho));

  return faest_192s_sign_with_randomness(sk, message, message_len, rho, sizeof(rho), signature, signature_len);
}

int FAEST_CALLING_CONVENTION faest_192s_unpacked_sign(const faest_192s_unpacked_private_key_t* sk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_192S_SIGNATURE_SIZE || (!message && message_len)) {
    return -1;
  }

  uint8_t rho[FAEST_192S_LAMBDA / 8];
  rand_bytes(rho, sizeof(rho));

  return faest_192s_unpacked_sign_with_randomness(sk, message, message_len, rho, sizeof(rho), signature, signature_len);
}

int FAEST_CALLING_CONVENTION faest_192s_unpacked_sign_with_randomness(const faest_192s_unpacked_private_key_t* sk, const uint8_t* message, size_t message_len, const uint8_t* rho, size_t rho_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_192S_SIGNATURE_SIZE || (!message && message_len)) {
    return -1;
  }

  const faest_paramset_t* params = faest_get_paramset(FAEST_192S);
  faest_sign(signature, message, message_len, sk->owf_key, sk->owf_input, sk->owf_output, sk->witness, rho, rho_len, params);
  *signature_len = FAEST_192S_SIGNATURE_SIZE;

  return 0;
}

int FAEST_CALLING_CONVENTION faest_192s_verify(const uint8_t* pk, const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len) {
  if (!pk || !signature || signature_len != FAEST_192S_SIGNATURE_SIZE || (!message && message_len)) {
    return -1;
  }

  const faest_paramset_t* params = faest_get_paramset(FAEST_192S);
  return faest_verify(message, message_len, signature, PK_INPUT(pk), PK_OUTPUT(pk), params);
}

void FAEST_CALLING_CONVENTION faest_192s_clear_private_key(uint8_t* key) {
  faest_explicit_bzero(key, FAEST_192S_PRIVATE_KEY_SIZE);
}

void FAEST_CALLING_CONVENTION faest_192s_clear_unpacked_private_key(faest_192s_unpacked_private_key_t* key) {
  faest_explicit_bzero(key, sizeof(*key));
}

// vim: ft=c
