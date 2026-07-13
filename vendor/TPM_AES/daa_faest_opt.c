/*
 * daa_faest_opt.c — optimized wrappers for DAA original-FAEST proofs.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "daa_faest_opt.h"

#include "aes.h"
#include "compat.h"
#include "daa_faest.h"
#include "faest_impl.h"
#include "instances.h"

#include <stdlib.h>
#include <string.h>

static const faest_paramset_t* select_params(unsigned int lambda, int fast) {
  switch (lambda) {
  case 192: return faest_get_paramset(fast ? DAA_FAEST_192F : DAA_FAEST_192S);
  case 256: return faest_get_paramset(fast ? DAA_FAEST_256F : DAA_FAEST_256S);
  default: return faest_get_paramset(fast ? DAA_FAEST_128F : DAA_FAEST_128S);
  }
}

static size_t witness_bytes_for(unsigned int lambda, int fast) {
  const faest_paramset_t* params = select_params(lambda, fast);
  return params ? (size_t)params->l / 8 : 0;
}

int daa_faest_scratch_init(daa_faest_scratch_t* scratch, unsigned int lambda, int fast) {
  if (!scratch) return -1;
  scratch->witness = NULL;
  scratch->witness_bytes = 0;
  const size_t witness_bytes = witness_bytes_for(lambda, fast);
  if (!witness_bytes) return -1;
  scratch->witness = malloc(witness_bytes);
  if (!scratch->witness) return -1;
  scratch->witness_bytes = witness_bytes;
  return 0;
}

void daa_faest_scratch_clear(daa_faest_scratch_t* scratch) {
  if (!scratch) return;
  if (scratch->witness) {
    faest_explicit_bzero(scratch->witness, scratch->witness_bytes);
    free(scratch->witness);
  }
  scratch->witness = NULL;
  scratch->witness_bytes = 0;
}

int daa_faest_sign_with_scratch(unsigned int lambda, int fast,
                                const uint8_t* sk_u, const uint8_t* gid,
                                const uint8_t* et_u,
                                const uint8_t* msg, size_t msglen,
                                uint8_t* sig, size_t* sig_len,
                                daa_faest_scratch_t* scratch) {
  if (!sk_u || !gid || !et_u || !sig || !sig_len || !scratch || !scratch->witness) return -1;
  const faest_paramset_t* params = select_params(lambda, fast);
  if (!params) return -1;
  const size_t witness_bytes = (size_t)params->l / 8;
  if (scratch->witness_bytes < witness_bytes) return -1;

  aes_extend_witness(scratch->witness, sk_u, gid, params);
  faest_sign(sig, msg, msglen, sk_u, gid, et_u, scratch->witness, NULL, 0, params);
  *sig_len = (size_t)params->sig_size;
  return 0;
}

int daa_faest_sign_fused(unsigned int lambda, int fast,
                         const uint8_t* sk_u, const uint8_t* gid,
                         uint8_t* et_u_out,
                         const uint8_t* msg, size_t msglen,
                         uint8_t* sig, size_t* sig_len,
                         daa_faest_scratch_t* scratch) {
  if (!et_u_out) return -1;
  daa_faest_owf(lambda, sk_u, gid, et_u_out);
  return daa_faest_sign_with_scratch(lambda, fast, sk_u, gid, et_u_out, msg, msglen, sig, sig_len,
                                     scratch);
}

#define DEFINE_FIXED_ENTRY(NAME, LAMBDA, FAST)                                                     \
int daa_faest_##NAME##_1aes_sign_fused(const uint8_t* sk_u, const uint8_t* gid,                   \
                                       uint8_t* et_u_out, const uint8_t* msg, size_t msglen,       \
                                       uint8_t* sig, size_t* sig_len,                              \
                                       daa_faest_scratch_t* scratch) {                              \
  return daa_faest_sign_fused((LAMBDA), (FAST), sk_u, gid, et_u_out, msg, msglen, sig, sig_len,    \
                              scratch);                                                           \
}                                                                                                  \
int daa_faest_##NAME##_1aes_verify(const uint8_t* gid, const uint8_t* et_u,                       \
                                   const uint8_t* msg, size_t msglen,                              \
                                   const uint8_t* sig, size_t sig_len) {                           \
  return daa_faest_verify((LAMBDA), (FAST), gid, et_u, msg, msglen, sig, sig_len);                 \
}

DEFINE_FIXED_ENTRY(128s, 128, 0)
DEFINE_FIXED_ENTRY(128f, 128, 1)
DEFINE_FIXED_ENTRY(192s, 192, 0)
DEFINE_FIXED_ENTRY(192f, 192, 1)
DEFINE_FIXED_ENTRY(256s, 256, 0)
DEFINE_FIXED_ENTRY(256f, 256, 1)
