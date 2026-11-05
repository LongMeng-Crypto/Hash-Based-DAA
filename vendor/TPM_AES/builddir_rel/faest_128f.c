/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_128f.h"
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

#define AES128_BLK_BYTES 16

#define KEY_BYTES (128 / 8)

#define PK_LID(pk)    (pk)
#define PK_GID(pk)    (&(pk)[AES128_BLK_BYTES])
#define PK_SLT(pk)    (&(pk)[2 * AES128_BLK_BYTES])
#define PK_HK(pk)     (&(pk)[2 * AES128_BLK_BYTES + 1 * AES128_BLK_BYTES])

#define PK_INPUT(pk)  (pk)
#define PK_OUTPUT(pk) (&(pk)[2 * AES128_BLK_BYTES])

#define SK_INPUT(sk)  (sk)
#define SK_SKU(sk)    (&(sk)[2 * AES128_BLK_BYTES])
#define SK_S(sk)      (&(sk)[2 * AES128_BLK_BYTES + KEY_BYTES])

#define SK_KEY(sk)    SK_SKU(sk)

static_assert(64 == 32 + 32, "invalid public key size");

static_assert(64 == 32 + 2 * (128 / 8), "invalid secret key size");

static_assert(32  == 2 * AES128_BLK_BYTES, "OWF_INPUT_SIZE must be 2 x 16 bytes (lid||gid)");

static_assert(64 == 2 * AES128_BLK_BYTES + 2 * 1 * AES128_BLK_BYTES, "PK_SIZE mismatch");
static_assert(64 == 2 * AES128_BLK_BYTES + 2 * (128 / 8), "SK_SIZE mismatch");

// Implements owf slt.
static inline void tpm_owf_slt(const uint8_t* sk_u, const uint8_t* lid, uint8_t* slt_out) {
#if 128 == 256
  owf_256(sk_u, lid, slt_out);
#elif 128 == 192
  owf_192(sk_u, lid, slt_out);
#else
  owf_128(sk_u, lid, slt_out);
#endif
}

// Implements owf etu.
static inline void tpm_owf_etu(const uint8_t* sk_u, const uint8_t* gid, uint8_t* etu_out) {
#if 128 == 256
  owf_256(sk_u, gid, etu_out);
#elif 128 == 192
  owf_192(sk_u, gid, etu_out);
#else
  owf_128(sk_u, gid, etu_out);
#endif
}

// Implements owf hk.
static inline void tpm_owf_hk(const uint8_t* s, const uint8_t* et_u, uint8_t* hk_out) {
#if 128 == 256

  generic_aes_ecb_t ctx;
  generic_aes_ecb_new(&ctx, s, 256);
  generic_aes_ecb_encrypt(&ctx, hk_out, et_u, 2);
  generic_aes_ecb_free(&ctx);
#elif 128 == 192

  generic_aes_ecb_t ctx;
  generic_aes_ecb_new(&ctx, s, 192);
  generic_aes_ecb_encrypt(&ctx, hk_out, et_u, 2);
  generic_aes_ecb_free(&ctx);
#else
  owf_128(s, et_u, hk_out);
#endif
}

#define ETU_BYTES (1 * AES128_BLK_BYTES)

// Implements credential eval outputs with etu.
static inline void tpm_credential_eval_outputs_with_etu(const uint8_t* sk, const uint8_t* et_u,
                                                        uint8_t* slt_out, uint8_t* hk_out) {
  const uint8_t* lid = SK_INPUT(sk);
  tpm_owf_slt(SK_SKU(sk), lid, slt_out);
  tpm_owf_hk(SK_S(sk), et_u, hk_out);
}

// Implements credential eval outputs.
static inline void tpm_credential_eval_outputs(const uint8_t* sk, uint8_t* slt_out, uint8_t* hk_out) {
  const uint8_t* gid = SK_INPUT(sk) + AES128_BLK_BYTES;

  uint8_t et_u[ETU_BYTES];

  tpm_owf_etu(SK_SKU(sk), gid, et_u);
  tpm_credential_eval_outputs_with_etu(sk, et_u, slt_out, hk_out);

  faest_explicit_bzero(et_u, sizeof(et_u));
}

// Implements faest 128f keygen.
int FAEST_CALLING_CONVENTION faest_128f_keygen(uint8_t* pk, uint8_t* sk) {
  if (!pk || !sk) {
    return -1;
  }

  bool done = false;
  while (!done) {
    rand_bytes(SK_SKU(sk), KEY_BYTES);
    done = (ptr_get_bit(SK_SKU(sk), 0) & ptr_get_bit(SK_SKU(sk), 1)) == 0;
    faest_declassify(&done, sizeof(done));
  }

  rand_bytes(SK_S(sk), KEY_BYTES);

  rand_bytes(SK_INPUT(sk), 2 * AES128_BLK_BYTES);
  faest_declassify(SK_INPUT(sk), 2 * AES128_BLK_BYTES);

  memcpy(PK_LID(pk), SK_INPUT(sk), 2 * AES128_BLK_BYTES);

  tpm_credential_eval_outputs(sk, PK_SLT(pk), PK_HK(pk));

  faest_declassify(pk, 64);
  return 0;
}

// Implements faest 128f unpack private key.
int FAEST_CALLING_CONVENTION faest_128f_unpack_private_key(faest_128f_unpacked_private_key_t* unpacked_sk, const uint8_t* sk) {
  if (!unpacked_sk || !sk) {
    return -1;
  }

  memcpy(unpacked_sk->owf_input, SK_INPUT(sk), sizeof(unpacked_sk->owf_input));

  const uint8_t* gid = SK_INPUT(sk) + AES128_BLK_BYTES;
  uint8_t et_u[ETU_BYTES];
  tpm_owf_etu(SK_SKU(sk), gid, et_u);

  memcpy(unpacked_sk->owf_key,                         SK_SKU(sk), KEY_BYTES);
  memcpy(unpacked_sk->owf_key + KEY_BYTES,             et_u,       ETU_BYTES);
  memcpy(unpacked_sk->owf_key + KEY_BYTES + ETU_BYTES, SK_S(sk),   KEY_BYTES);

  tpm_credential_eval_outputs_with_etu(sk, et_u, unpacked_sk->owf_output,
                                       unpacked_sk->owf_output + ETU_BYTES);
  faest_declassify(unpacked_sk->owf_output, sizeof(unpacked_sk->owf_output));
  faest_explicit_bzero(et_u, sizeof(et_u));

  const faest_paramset_t* params = faest_get_paramset(FAEST_128F);

  aes_extend_witness(unpacked_sk->witness, unpacked_sk->owf_key, unpacked_sk->owf_input, params);

  return 0;
}

// Implements faest 128f validate keypair.
int FAEST_CALLING_CONVENTION faest_128f_validate_keypair(const uint8_t* pk, const uint8_t* sk) {
  if (!sk || !pk) {
    return -1;
  }

  if ((ptr_get_bit(SK_SKU(sk), 0) & ptr_get_bit(SK_SKU(sk), 1)) != 0) {
    return 1;
  }

  uint8_t pk_check[64];
  memcpy(PK_INPUT(pk_check), SK_INPUT(sk), 2 * AES128_BLK_BYTES);
  tpm_credential_eval_outputs(sk, PK_SLT(pk_check), PK_HK(pk_check));

  return faest_timingsafe_bcmp(pk_check, pk, sizeof(pk_check)) == 0 ? 0 : 2;
}

// Implements faest 128f sign with randomness.
int FAEST_CALLING_CONVENTION faest_128f_sign_with_randomness(const uint8_t* sk, const uint8_t* message, size_t message_len, const uint8_t* rho, size_t rho_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_128F_SIGNATURE_SIZE ||
      (!rho && rho_len) || (!message && message_len)) {
    return -1;
  }

  faest_128f_unpacked_private_key_t unpacked_sk;
  int ret = faest_128f_unpack_private_key(&unpacked_sk, sk);
  if (ret) {
    faest_128f_clear_unpacked_private_key(&unpacked_sk);
    return ret;
  }

  ret = faest_128f_unpacked_sign_with_randomness(&unpacked_sk, message, message_len, rho, rho_len, signature, signature_len);
  faest_128f_clear_unpacked_private_key(&unpacked_sk);
  return ret;
}

// Implements faest 128f sign.
int FAEST_CALLING_CONVENTION faest_128f_sign(const uint8_t* sk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_128F_SIGNATURE_SIZE ||
      (!message && message_len)) {
    return -1;
  }

  uint8_t rho[FAEST_128F_LAMBDA / 8];
  rand_bytes(rho, sizeof(rho));

  return faest_128f_sign_with_randomness(sk, message, message_len, rho, sizeof(rho), signature, signature_len);
}

// Implements faest 128f unpacked sign.
int FAEST_CALLING_CONVENTION faest_128f_unpacked_sign(const faest_128f_unpacked_private_key_t* sk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_128F_SIGNATURE_SIZE || (!message && message_len)) {
    return -1;
  }

  uint8_t rho[FAEST_128F_LAMBDA / 8];
  rand_bytes(rho, sizeof(rho));

  return faest_128f_unpacked_sign_with_randomness(sk, message, message_len, rho, sizeof(rho), signature, signature_len);
}

// Implements faest 128f unpacked sign with randomness.
int FAEST_CALLING_CONVENTION faest_128f_unpacked_sign_with_randomness(const faest_128f_unpacked_private_key_t* sk, const uint8_t* message, size_t message_len, const uint8_t* rho, size_t rho_len, uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < FAEST_128F_SIGNATURE_SIZE || (!message && message_len)) {
    return -1;
  }

  const faest_paramset_t* params = faest_get_paramset(FAEST_128F);
  faest_sign(signature, message, message_len, sk->owf_key, sk->owf_input, sk->owf_output, sk->witness, rho, rho_len, params);
  *signature_len = FAEST_128F_SIGNATURE_SIZE;

  return 0;
}

// Implements faest 128f verify.
int FAEST_CALLING_CONVENTION faest_128f_verify(const uint8_t* pk, const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len) {
  if (!pk || !signature || signature_len != FAEST_128F_SIGNATURE_SIZE || (!message && message_len)) {
    return -1;
  }

  const faest_paramset_t* params = faest_get_paramset(FAEST_128F);
  return faest_verify(message, message_len, signature, PK_INPUT(pk), PK_OUTPUT(pk), params);
}

// Implements faest 128f clear private key.
void FAEST_CALLING_CONVENTION faest_128f_clear_private_key(uint8_t* key) {
  faest_explicit_bzero(key, FAEST_128F_PRIVATE_KEY_SIZE);
}

// Implements faest 128f clear unpacked private key.
void FAEST_CALLING_CONVENTION faest_128f_clear_unpacked_private_key(faest_128f_unpacked_private_key_t* key) {
  faest_explicit_bzero(key, sizeof(*key));
}
