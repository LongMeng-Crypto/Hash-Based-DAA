/*
 * daa_aes_profile.c — A/B benchmark for DAA original FAEST and TPM-AES paths.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "daa_faest.h"
#include "daa_faest_opt.h"
#include "randomness.h"

#include "faest_128s.h"
#include "faest_128f.h"
#include "faest_192s.h"
#include "faest_192f.h"
#include "faest_256s.h"
#include "faest_256f.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec * 1e-3;
}

static void die_step(const char* variant, const char* step, int ret) {
  fprintf(stderr, "[%s] %s failed: %d\n", variant, step, ret);
  abort();
}

static unsigned int read_iters(int argc, char** argv) {
  if (argc < 2) return 100;
  char* end = NULL;
  unsigned long v = strtoul(argv[1], &end, 10);
  return (end && *end == '\0' && v > 0) ? (unsigned int)v : 100;
}

static void bench_original_variant(const char* name, unsigned int lambda, int fast,
                                   unsigned int iters) {
  const size_t key_bytes = lambda / 8;
  const size_t etu_bytes = daa_faest_etu_bytes(lambda);
  const size_t sig_bytes = daa_faest_max_sig_size(lambda, fast);

  uint8_t gid[16];
  uint8_t* sk = malloc(key_bytes);
  uint8_t* et = malloc(etu_bytes);
  uint8_t* sig = malloc(sig_bytes);
  uint8_t* sig_opt = malloc(sig_bytes);
  if (!sk || !et || !sig || !sig_opt) abort();
  rand_bytes(gid, sizeof(gid));
  rand_bytes(sk, key_bytes);
  sk[0] &= ~(uint8_t)0x01u;

  daa_faest_scratch_t scratch;
  if (daa_faest_scratch_init(&scratch, lambda, fast) != 0) abort();

  double owf_us = 0.0, baseline_sign_us = 0.0, opt_sign_us = 0.0;
  double baseline_verify_us = 0.0, opt_verify_us = 0.0;
  for (unsigned int i = 0; i < iters; ++i) {
    size_t sig_len = 0, sig_opt_len = 0;
    double t0 = now_us();
    daa_faest_owf(lambda, sk, gid, et);
    double t1 = now_us();
    if (daa_faest_sign(lambda, fast, sk, gid, et, NULL, 0, sig, &sig_len) != 0) abort();
    double t2 = now_us();
    if (daa_faest_verify(lambda, fast, gid, et, NULL, 0, sig, sig_len) != 0) abort();
    double t3 = now_us();

    if (daa_faest_sign_fused(lambda, fast, sk, gid, et, NULL, 0, sig_opt, &sig_opt_len,
                             &scratch) != 0) abort();
    double t4 = now_us();
    if (daa_faest_verify(lambda, fast, gid, et, NULL, 0, sig_opt, sig_opt_len) != 0) abort();
    double t5 = now_us();

    owf_us += t1 - t0;
    baseline_sign_us += t2 - t1;
    baseline_verify_us += t3 - t2;
    opt_sign_us += t4 - t3;
    opt_verify_us += t5 - t4;
  }

  const double b_ms = baseline_sign_us / iters / 1000.0;
  const double o_ms = opt_sign_us / iters / 1000.0;
  printf("%-10s %9.3f %13.3f %13.3f %12.2fx %13.3f %11.3f %9zu\n",
         name, owf_us / iters, b_ms, o_ms, b_ms / o_ms,
         baseline_verify_us / iters / 1000.0, opt_verify_us / iters / 1000.0, sig_bytes);

  daa_faest_scratch_clear(&scratch);
  free(sk); free(et); free(sig); free(sig_opt);
}

#define BENCH_TPM_VARIANT(NAME, PREFIX, PK_SIZE, SK_SIZE, SIG_SIZE, UNPACKED_TYPE)                 \
static void bench_tpm_##PREFIX(unsigned int iters) {                                                \
  uint8_t pk[PK_SIZE];                                                                              \
  uint8_t sk[SK_SIZE];                                                                              \
  uint8_t sig[SIG_SIZE];                                                                            \
  uint8_t sig_unpacked[SIG_SIZE];                                                                   \
  size_t sig_len = sizeof(sig);                                                                     \
  size_t sig_unpacked_len = sizeof(sig_unpacked);                                                   \
  int ret = PREFIX##_keygen(pk, sk); if (ret != 0) die_step(NAME, "keygen", ret);                                                        \
  double normal_sign_us = 0.0, verify_us = 0.0;                                                     \
  for (unsigned int i = 0; i < iters; ++i) {                                                        \
    sig_len = sizeof(sig);                                                                          \
    double t0 = now_us();                                                                           \
    ret = PREFIX##_sign(sk, NULL, 0, sig, &sig_len); if (ret != 0) die_step(NAME, "sign", ret);                                    \
    double t1 = now_us();                                                                           \
    ret = PREFIX##_verify(pk, NULL, 0, sig, sig_len); if (ret != 0) die_step(NAME, "verify", ret);                                   \
    double t2 = now_us();                                                                           \
    normal_sign_us += t1 - t0;                                                                      \
    verify_us += t2 - t1;                                                                           \
  }                                                                                                 \
  UNPACKED_TYPE unpacked;                                                                           \
  double t_unpack0 = now_us();                                                                      \
  ret = PREFIX##_unpack_private_key(&unpacked, sk); if (ret != 0) die_step(NAME, "unpack", ret);                                    \
  double t_unpack1 = now_us();                                                                      \
  double unpacked_sign_us = 0.0;                                                                    \
  for (unsigned int i = 0; i < iters; ++i) {                                                        \
    sig_unpacked_len = sizeof(sig_unpacked);                                                        \
    double t0 = now_us();                                                                           \
    ret = PREFIX##_unpacked_sign(&unpacked, NULL, 0, sig_unpacked, &sig_unpacked_len); if (ret != 0) die_step(NAME, "unpacked_sign", ret);  \
    double t1 = now_us();                                                                           \
    ret = PREFIX##_verify(pk, NULL, 0, sig_unpacked, sig_unpacked_len); if (ret != 0) die_step(NAME, "unpacked_verify", ret);                 \
    unpacked_sign_us += t1 - t0;                                                                    \
  }                                                                                                 \
  PREFIX##_clear_unpacked_private_key(&unpacked);                                                   \
  const double n_ms = normal_sign_us / iters / 1000.0;                                              \
  const double u_ms = unpacked_sign_us / iters / 1000.0;                                            \
  printf("%-10s %13.3f %15.3f %15.3f %12.2fx %13.3f %9u\n",                                      \
         NAME, (t_unpack1 - t_unpack0) / 1000.0, n_ms, u_ms, n_ms / u_ms,                           \
         verify_us / iters / 1000.0, (unsigned int)SIG_SIZE);                                      \
}

BENCH_TPM_VARIANT("128s", faest_128s, FAEST_128S_PUBLIC_KEY_SIZE, FAEST_128S_PRIVATE_KEY_SIZE,
                  FAEST_128S_SIGNATURE_SIZE, faest_128s_unpacked_private_key_t)
BENCH_TPM_VARIANT("128f", faest_128f, FAEST_128F_PUBLIC_KEY_SIZE, FAEST_128F_PRIVATE_KEY_SIZE,
                  FAEST_128F_SIGNATURE_SIZE, faest_128f_unpacked_private_key_t)
BENCH_TPM_VARIANT("192s", faest_192s, FAEST_192S_PUBLIC_KEY_SIZE, FAEST_192S_PRIVATE_KEY_SIZE,
                  FAEST_192S_SIGNATURE_SIZE, faest_192s_unpacked_private_key_t)
BENCH_TPM_VARIANT("192f", faest_192f, FAEST_192F_PUBLIC_KEY_SIZE, FAEST_192F_PRIVATE_KEY_SIZE,
                  FAEST_192F_SIGNATURE_SIZE, faest_192f_unpacked_private_key_t)
BENCH_TPM_VARIANT("256s", faest_256s, FAEST_256S_PUBLIC_KEY_SIZE, FAEST_256S_PRIVATE_KEY_SIZE,
                  FAEST_256S_SIGNATURE_SIZE, faest_256s_unpacked_private_key_t)
BENCH_TPM_VARIANT("256f", faest_256f, FAEST_256F_PUBLIC_KEY_SIZE, FAEST_256F_PRIVATE_KEY_SIZE,
                  FAEST_256F_SIGNATURE_SIZE, faest_256f_unpacked_private_key_t)

int main(int argc, char** argv) {
  const unsigned int iters = read_iters(argc, argv);
  printf("DAA AES proof optimization profile (iterations=%u)\n\n", iters);

  printf("Original DAA FAEST / 1-AES wrapper\n");
  printf("%-10s %9s %13s %13s %12s %13s %11s %9s\n",
         "Variant", "OWF(us)", "base sign", "opt sign", "speedup", "base verify", "opt verify", "sig(B)");
  bench_original_variant("128s", 128, 0, iters);
  bench_original_variant("128f", 128, 1, iters);
  bench_original_variant("192s", 192, 0, iters);
  bench_original_variant("192f", 192, 1, iters);
  bench_original_variant("256s", 256, 0, iters);
  bench_original_variant("256f", 256, 1, iters);

  printf("\nTPM-AES credential proof / generated 3-AES path\n");
  printf("%-10s %13s %15s %15s %12s %13s %9s\n",
         "Variant", "unpack(ms)", "normal sign", "reused sign", "speedup", "verify", "sig(B)");
  bench_tpm_faest_128s(iters);
  bench_tpm_faest_128f(iters);
  bench_tpm_faest_192s(iters);
  bench_tpm_faest_192f(iters);
  bench_tpm_faest_256s(iters);
  bench_tpm_faest_256f(iters);
  return 0;
}
