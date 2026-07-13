/*
 * daa_faest.c — Original single-AES FAEST for the DAA Joining Protocol
 *
 * Each public function dispatches to a per-variant static helper that holds
 * ONE known faest_paramset_t pointer.  This mirrors how faest_128s.c calls
 * faest_get_paramset(FAEST_128S) from a single call site, giving the LTO
 * pass the same opportunity to specialise faest_sign/faest_verify with
 * compile-time-constant loop bounds.
 *
 * OWF: uses owf_128/192/256 from owf.c (AES-NI accelerated).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "daa_faest.h"
#include "aes.h"
#include "compat.h"
#include "faest_impl.h"
#include "instances.h"
#include "owf.h"
#include "randomness.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* ----------------------------------------------------------------------- */
/* Per-variant sign helpers — one static function per paramset.            */
/* The compiler (with LTO) sees a single known params pointer at each site  */
/* and can specialise faest_sign with folded loop bounds.                   */
/* ----------------------------------------------------------------------- */

#define DEFINE_SIGN(ID)                                                          \
static int sign_##ID(const uint8_t* sk_u, const uint8_t* gid,                   \
                     const uint8_t* et_u,                                        \
                     const uint8_t* msg, size_t msglen,                          \
                     uint8_t* sig, size_t* sig_len) {                            \
  const faest_paramset_t* params = faest_get_paramset(ID);                       \
  const size_t witness_bytes = (size_t)params->l / 8;                           \
  uint8_t* witness = malloc(witness_bytes);                                      \
  if (!witness) return -1;                                                       \
  aes_extend_witness(witness, sk_u, gid, params);                                \
  faest_sign(sig, msg, msglen, sk_u, gid, et_u, witness, NULL, 0, params);      \
  *sig_len = (size_t)params->sig_size;                                           \
  faest_explicit_bzero(witness, witness_bytes);                                  \
  free(witness);                                                                 \
  return 0;                                                                      \
}

#define DEFINE_VERIFY(ID)                                                        \
static int verify_##ID(const uint8_t* gid, const uint8_t* et_u,                 \
                       const uint8_t* msg, size_t msglen,                        \
                       const uint8_t* sig, size_t sig_len) {                     \
  const faest_paramset_t* params = faest_get_paramset(ID);                       \
  if (sig_len != (size_t)params->sig_size) return -1;                            \
  return faest_verify(msg, msglen, sig, gid, et_u, params);                      \
}

DEFINE_SIGN(DAA_FAEST_128S)
DEFINE_SIGN(DAA_FAEST_128F)
DEFINE_SIGN(DAA_FAEST_192S)
DEFINE_SIGN(DAA_FAEST_192F)
DEFINE_SIGN(DAA_FAEST_256S)
DEFINE_SIGN(DAA_FAEST_256F)

DEFINE_VERIFY(DAA_FAEST_128S)
DEFINE_VERIFY(DAA_FAEST_128F)
DEFINE_VERIFY(DAA_FAEST_192S)
DEFINE_VERIFY(DAA_FAEST_192F)
DEFINE_VERIFY(DAA_FAEST_256S)
DEFINE_VERIFY(DAA_FAEST_256F)

/* ----------------------------------------------------------------------- */

size_t daa_faest_max_sig_size(unsigned int lambda, int fast) {
  switch (lambda) {
  case 192: return fast ? DAA_FAEST_192F_SIG_SIZE : DAA_FAEST_192S_SIG_SIZE;
  case 256: return fast ? DAA_FAEST_256F_SIG_SIZE : DAA_FAEST_256S_SIG_SIZE;
  default:  return fast ? DAA_FAEST_128F_SIG_SIZE : DAA_FAEST_128S_SIG_SIZE;
  }
}

size_t daa_faest_etu_bytes(unsigned int lambda) {
  return (lambda == 128) ? 16u : 32u;
}

/* ----------------------------------------------------------------------- */

void daa_faest_owf(unsigned int lambda, const uint8_t* sk_u,
                   const uint8_t* gid, uint8_t* et_u_out) {
  switch (lambda) {
  case 256: owf_256(sk_u, gid, et_u_out); break;
  case 192: owf_192(sk_u, gid, et_u_out); break;
  default:  owf_128(sk_u, gid, et_u_out); break;
  }
}

/* ----------------------------------------------------------------------- */

int daa_faest_sign(unsigned int lambda, int fast,
                   const uint8_t* sk_u, const uint8_t* gid, const uint8_t* et_u,
                   const uint8_t* msg, size_t msglen,
                   uint8_t* sig, size_t* sig_len) {
  switch (lambda) {
  case 192:
    return fast
      ? sign_DAA_FAEST_192F(sk_u, gid, et_u, msg, msglen, sig, sig_len)
      : sign_DAA_FAEST_192S(sk_u, gid, et_u, msg, msglen, sig, sig_len);
  case 256:
    return fast
      ? sign_DAA_FAEST_256F(sk_u, gid, et_u, msg, msglen, sig, sig_len)
      : sign_DAA_FAEST_256S(sk_u, gid, et_u, msg, msglen, sig, sig_len);
  default:
    return fast
      ? sign_DAA_FAEST_128F(sk_u, gid, et_u, msg, msglen, sig, sig_len)
      : sign_DAA_FAEST_128S(sk_u, gid, et_u, msg, msglen, sig, sig_len);
  }
}

/* ----------------------------------------------------------------------- */

int daa_faest_verify(unsigned int lambda, int fast,
                     const uint8_t* gid, const uint8_t* et_u,
                     const uint8_t* msg, size_t msglen,
                     const uint8_t* sig, size_t sig_len) {
  switch (lambda) {
  case 192:
    return fast
      ? verify_DAA_FAEST_192F(gid, et_u, msg, msglen, sig, sig_len)
      : verify_DAA_FAEST_192S(gid, et_u, msg, msglen, sig, sig_len);
  case 256:
    return fast
      ? verify_DAA_FAEST_256F(gid, et_u, msg, msglen, sig, sig_len)
      : verify_DAA_FAEST_256S(gid, et_u, msg, msglen, sig, sig_len);
  default:
    return fast
      ? verify_DAA_FAEST_128F(gid, et_u, msg, msglen, sig, sig_len)
      : verify_DAA_FAEST_128S(gid, et_u, msg, msglen, sig, sig_len);
  }
}
