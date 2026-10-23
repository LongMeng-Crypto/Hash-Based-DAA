#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "daa_faest.h"
#include "faest_128f.h"
#include "faest_128s.h"
#include "faest_192f.h"
#include "faest_192s.h"
#include "faest_256f.h"
#include "faest_256s.h"
#include "owf.h"

#define DAA_GID_BYTES 16u

// Returns the byte length of FAEST TPM tokens for a security level.
static size_t token_bytes(unsigned int lambda) {
  return lambda == 128u ? 16u : 32u;
}

// Returns the byte length of FAEST AES keys for a security level.
static size_t key_bytes(unsigned int lambda) {
  return lambda / 8u;
}

// Computes the AES OWF used for et and slt.
static void tpm_owf(unsigned int lambda,
                    const uint8_t* key,
                    const uint8_t* input,
                    uint8_t* output) {
  if (lambda == 256u) {
    owf_256(key, input, output);
  } else if (lambda == 192u) {
    owf_192(key, input, output);
  } else {
    daa_aes128_dm(key, input, output);
  }
}

// Computes hk = AES_s(et) with one block for 128-bit and two blocks otherwise.
static void tpm_hk(unsigned int lambda,
                   const uint8_t* s,
                   const uint8_t* et,
                   uint8_t* hk) {
  if (lambda == 256u) {
    generic_aes_ecb_t ctx;
    generic_aes_ecb_new(&ctx, s, 256);
    generic_aes_ecb_encrypt(&ctx, hk, et, 2);
    generic_aes_ecb_free(&ctx);
  } else if (lambda == 192u) {
    generic_aes_ecb_t ctx;
    generic_aes_ecb_new(&ctx, s, 192);
    generic_aes_ecb_encrypt(&ctx, hk, et, 2);
    generic_aes_ecb_free(&ctx);
  } else {
    daa_aes128_dm(s, et, hk);
  }
}

// Returns the byte size of a single-AES DAA join proof.
size_t daa_join_sig_bytes(unsigned int lambda, int fast) {
  return daa_faest_max_sig_size(lambda, fast);
}

// Returns the byte size of a TPM signing proof.
size_t daa_tpm_sig_bytes(unsigned int lambda, int fast) {
  if (lambda == 256u) {
    return fast ? FAEST_256F_SIGNATURE_SIZE : FAEST_256S_SIGNATURE_SIZE;
  } else if (lambda == 192u) {
    return fast ? FAEST_192F_SIGNATURE_SIZE : FAEST_192S_SIGNATURE_SIZE;
  } else {
    return fast ? FAEST_128F_SIGNATURE_SIZE : FAEST_128S_SIGNATURE_SIZE;
  }
}

// Computes one TPM OWF output for et, slt, or compatible tests.
void daa_aes_owf(unsigned int lambda,
                 const uint8_t* key,
                 const uint8_t* input,
                 uint8_t* output) {
  tpm_owf(lambda, key, input, output);
}

// Computes the TPM host hook hk = AES_s(et).
void daa_aes_hook(unsigned int lambda,
                  const uint8_t* s,
                  const uint8_t* et,
                  uint8_t* hk) {
  tpm_hk(lambda, s, et, hk);
}

// Produces a FAEST proof for the join-time single-AES relation.
int daa_join_prove(unsigned int lambda,
                   int fast,
                   const uint8_t* sk_u,
                   const uint8_t* gid,
                   const uint8_t* et,
                   const uint8_t* msg,
                   size_t msg_len,
                   uint8_t* sig,
                   size_t* sig_len) {
  return daa_faest_sign(lambda, fast, sk_u, gid, et, msg, msg_len, sig, sig_len);
}

// Verifies a FAEST proof for the join-time single-AES relation.
int daa_join_verify(unsigned int lambda,
                    int fast,
                    const uint8_t* gid,
                    const uint8_t* et,
                    const uint8_t* msg,
                    size_t msg_len,
                    const uint8_t* sig,
                    size_t sig_len) {
  return daa_faest_verify(lambda, fast, gid, et, msg, msg_len, sig, sig_len);
}

// Packs the TPM private key as lid || gid || sk_u || s.
static void pack_tpm_sk(unsigned int lambda,
                        uint8_t* sk,
                        const uint8_t* lid,
                        const uint8_t* gid,
                        const uint8_t* sk_u,
                        const uint8_t* s) {
  const size_t k = key_bytes(lambda);
  memcpy(sk, lid, DAA_GID_BYTES);
  memcpy(sk + DAA_GID_BYTES, gid, DAA_GID_BYTES);
  memcpy(sk + 2u * DAA_GID_BYTES, sk_u, k);
  memcpy(sk + 2u * DAA_GID_BYTES + k, s, k);
}

// Packs the TPM public key as lid || gid || slt || hk.
static void pack_tpm_pk(uint8_t* pk,
                        const uint8_t* lid,
                        const uint8_t* gid,
                        const uint8_t* slt,
                        const uint8_t* hk,
                        size_t token_len) {
  memcpy(pk, lid, DAA_GID_BYTES);
  memcpy(pk + DAA_GID_BYTES, gid, DAA_GID_BYTES);
  memcpy(pk + 2u * DAA_GID_BYTES, slt, token_len);
  memcpy(pk + 2u * DAA_GID_BYTES + token_len, hk, token_len);
}

// Signs with the selected TPM FAEST parameter set.
static int tpm_sign_dispatch(unsigned int lambda,
                             int fast,
                             const uint8_t* sk,
                             const uint8_t* msg,
                             size_t msg_len,
                             uint8_t* sig,
                             size_t* sig_len) {
  if (lambda == 256u) {
    return fast ? faest_256f_sign(sk, msg, msg_len, sig, sig_len)
                : faest_256s_sign(sk, msg, msg_len, sig, sig_len);
  } else if (lambda == 192u) {
    return fast ? faest_192f_sign(sk, msg, msg_len, sig, sig_len)
                : faest_192s_sign(sk, msg, msg_len, sig, sig_len);
  } else {
    return fast ? faest_128f_sign(sk, msg, msg_len, sig, sig_len)
                : faest_128s_sign(sk, msg, msg_len, sig, sig_len);
  }
}

// Verifies with the selected TPM FAEST parameter set.
static int tpm_verify_dispatch(unsigned int lambda,
                               int fast,
                               const uint8_t* pk,
                               const uint8_t* msg,
                               size_t msg_len,
                               const uint8_t* sig,
                               size_t sig_len) {
  if (lambda == 256u) {
    return fast ? faest_256f_verify(pk, msg, msg_len, sig, sig_len)
                : faest_256s_verify(pk, msg, msg_len, sig, sig_len);
  } else if (lambda == 192u) {
    return fast ? faest_192f_verify(pk, msg, msg_len, sig, sig_len)
                : faest_192s_verify(pk, msg, msg_len, sig, sig_len);
  } else {
    return fast ? faest_128f_verify(pk, msg, msg_len, sig, sig_len)
                : faest_128s_verify(pk, msg, msg_len, sig, sig_len);
  }
}

// Produces a FAEST proof for the sign-time TPM relation.
int daa_tpm_prove(unsigned int lambda,
                  int fast,
                  const uint8_t* lid,
                  const uint8_t* gid,
                  const uint8_t* sk_u,
                  const uint8_t* s,
                  const uint8_t* msg,
                  size_t msg_len,
                  uint8_t* et_out,
                  uint8_t* slt_out,
                  uint8_t* hk_out,
                  uint8_t* sig,
                  size_t* sig_len) {
  uint8_t sk[96];
  pack_tpm_sk(lambda, sk, lid, gid, sk_u, s);

  tpm_owf(lambda, sk_u, gid, et_out);
  tpm_owf(lambda, sk_u, lid, slt_out);
  tpm_hk(lambda, s, et_out, hk_out);

  return tpm_sign_dispatch(lambda, fast, sk, msg, msg_len, sig, sig_len);
}

// Verifies a FAEST proof for the sign-time TPM relation.
int daa_tpm_verify(unsigned int lambda,
                   int fast,
                   const uint8_t* lid,
                   const uint8_t* gid,
                   const uint8_t* slt,
                   const uint8_t* hk,
                   const uint8_t* msg,
                   size_t msg_len,
                   const uint8_t* sig,
                   size_t sig_len) {
  uint8_t pk[96];
  pack_tpm_pk(pk, lid, gid, slt, hk, token_bytes(lambda));
  return tpm_verify_dispatch(lambda, fast, pk, msg, msg_len, sig, sig_len);
}
