/* Benchmark the in-tree optimized AES VOLE proofs used by DAA Join and Sign. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "daa_faest.h"
#include "randomness.h"

#include "faest_128f.h"
#include "faest_128s.h"
#include "faest_192f.h"
#include "faest_192s.h"
#include "faest_256f.h"
#include "faest_256s.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Return a monotonic timestamp in microseconds. */
static double now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec * 1e-3;
}

/* Abort a benchmark immediately if a proof operation fails. */
static void die_step(const char* variant, const char* step, int ret) {
  fprintf(stderr, "[%s] %s failed: %d\n", variant, step, ret);
  abort();
}

/* Parse the optional positive iteration count. */
static unsigned int read_iters(int argc, char** argv) {
  if (argc < 2) return 100;
  char* end = NULL;
  const unsigned long value = strtoul(argv[1], &end, 10);
  return end && *end == '\0' && value > 0 ? (unsigned int)value : 100;
}

/* Benchmark the Join relation et = F(sk,gid), excluding input generation. */
/* Select whole comma-separated tokens, avoiding work for unrequested profiles. */
static int selected(const char* variable, const char* value) {
  const char* list = getenv(variable);
  if (!list || !*list) return 1;
  const size_t length = strlen(value);
  for (const char* p = list; *p;) {
    const char* end = strchr(p, ',');
    const size_t size = end ? (size_t)(end - p) : strlen(p);
    if (size == length && memcmp(p, value, length) == 0) return 1;
    if (!end) break;
    p = end + 1;
  }
  return 0;
}

/* Benchmark a selected Join profile with warmup outside the timed region. */
static void bench_join(const char* name, unsigned int lambda, int fast,
                       unsigned int iterations) {
  if (!selected("PARAMETERS", name) || !selected("PHASES", "join")) return;
  const size_t key_bytes = lambda / 8;
  const size_t et_bytes = daa_faest_etu_bytes(lambda);
  const size_t proof_capacity = daa_faest_max_sig_size(lambda, fast);
  uint8_t gid[16];
  uint8_t* sk = malloc(key_bytes);
  uint8_t* et = malloc(et_bytes);
  uint8_t* proof = malloc(proof_capacity);
  if (!sk || !et || !proof) abort();

  rand_bytes(gid, sizeof(gid));
  rand_bytes(sk, key_bytes);
  sk[0] &= ~(uint8_t)0x01u;
  daa_faest_owf(lambda, sk, gid, et);

  size_t proof_bytes = proof_capacity;
  int ret = daa_faest_sign(lambda, fast, sk, gid, et, NULL, 0, proof, &proof_bytes);
  if (ret != 0) die_step(name, "warmup prove", ret);
  ret = daa_faest_verify(lambda, fast, gid, et, NULL, 0, proof, proof_bytes);
  if (ret != 0) die_step(name, "warmup verify", ret);

  double prover_us = 0.0;
  double verifier_us = 0.0;
  for (unsigned int i = 0; i != iterations; ++i) {
    proof_bytes = proof_capacity;
    const double prove_begin = now_us();
    ret = daa_faest_sign(lambda, fast, sk, gid, et, NULL, 0, proof, &proof_bytes);
    const double prove_end = now_us();
    if (ret != 0) die_step(name, "prove", ret);
    ret = daa_faest_verify(lambda, fast, gid, et, NULL, 0, proof, proof_bytes);
    const double verify_end = now_us();
    if (ret != 0) die_step(name, "verify", ret);
    prover_us += prove_end - prove_begin;
    verifier_us += verify_end - prove_end;
  }

  printf("join\t%s\t%.6f\t%.6f\t%zu\n", name,
         prover_us / iterations / 1000.0,
         verifier_us / iterations / 1000.0, proof_bytes);
  free(sk);
  free(et);
  free(proof);
}

#define DEFINE_SIGN_BENCH(NAME, PREFIX, PK_SIZE, SK_SIZE, PROOF_SIZE)                     \
  static void bench_sign_##PREFIX(unsigned int iterations) {                              \
    if (!selected("PARAMETERS", NAME) || !selected("PHASES", "sign")) return;           \
    uint8_t pk[PK_SIZE];                                                                   \
    uint8_t sk[SK_SIZE];                                                                   \
    uint8_t proof[PROOF_SIZE];                                                             \
    size_t proof_bytes = sizeof(proof);                                                    \
    int ret = PREFIX##_keygen(pk, sk);                                                     \
    if (ret != 0) die_step(NAME, "keygen", ret);                                         \
    ret = PREFIX##_sign(sk, NULL, 0, proof, &proof_bytes);                                \
    if (ret != 0) die_step(NAME, "warmup prove", ret);                                   \
    ret = PREFIX##_verify(pk, NULL, 0, proof, proof_bytes);                               \
    if (ret != 0) die_step(NAME, "warmup verify", ret);                                  \
    double prover_us = 0.0;                                                                \
    double verifier_us = 0.0;                                                              \
    for (unsigned int i = 0; i != iterations; ++i) {                                      \
      proof_bytes = sizeof(proof);                                                         \
      const double prove_begin = now_us();                                                 \
      ret = PREFIX##_sign(sk, NULL, 0, proof, &proof_bytes);                              \
      const double prove_end = now_us();                                                   \
      if (ret != 0) die_step(NAME, "prove", ret);                                        \
      ret = PREFIX##_verify(pk, NULL, 0, proof, proof_bytes);                             \
      const double verify_end = now_us();                                                  \
      if (ret != 0) die_step(NAME, "verify", ret);                                       \
      prover_us += prove_end - prove_begin;                                                \
      verifier_us += verify_end - prove_end;                                               \
    }                                                                                     \
    printf("sign\t%s\t%.6f\t%.6f\t%zu\n", NAME,                                    \
           prover_us / iterations / 1000.0,                                               \
           verifier_us / iterations / 1000.0, proof_bytes);                               \
  }

DEFINE_SIGN_BENCH("128s", faest_128s, FAEST_128S_PUBLIC_KEY_SIZE,
                  FAEST_128S_PRIVATE_KEY_SIZE, FAEST_128S_SIGNATURE_SIZE)
DEFINE_SIGN_BENCH("128f", faest_128f, FAEST_128F_PUBLIC_KEY_SIZE,
                  FAEST_128F_PRIVATE_KEY_SIZE, FAEST_128F_SIGNATURE_SIZE)
DEFINE_SIGN_BENCH("192s", faest_192s, FAEST_192S_PUBLIC_KEY_SIZE,
                  FAEST_192S_PRIVATE_KEY_SIZE, FAEST_192S_SIGNATURE_SIZE)
DEFINE_SIGN_BENCH("192f", faest_192f, FAEST_192F_PUBLIC_KEY_SIZE,
                  FAEST_192F_PRIVATE_KEY_SIZE, FAEST_192F_SIGNATURE_SIZE)
DEFINE_SIGN_BENCH("256s", faest_256s, FAEST_256S_PUBLIC_KEY_SIZE,
                  FAEST_256S_PRIVATE_KEY_SIZE, FAEST_256S_SIGNATURE_SIZE)
DEFINE_SIGN_BENCH("256f", faest_256f, FAEST_256F_PUBLIC_KEY_SIZE,
                  FAEST_256F_PRIVATE_KEY_SIZE, FAEST_256F_SIGNATURE_SIZE)

/* Run every AES Join and three-function TPM signing profile. */
int main(int argc, char** argv) {
  const unsigned int iterations = read_iters(argc, argv);
  printf("phase\tparameter\tprover_ms\tverifier_ms\tproof_bytes\n");
  bench_join("128s", 128, 0, iterations);
  bench_join("128f", 128, 1, iterations);
  bench_join("192s", 192, 0, iterations);
  bench_join("192f", 192, 1, iterations);
  bench_join("256s", 256, 0, iterations);
  bench_join("256f", 256, 1, iterations);
  bench_sign_faest_128s(iterations);
  bench_sign_faest_128f(iterations);
  bench_sign_faest_192s(iterations);
  bench_sign_faest_192f(iterations);
  bench_sign_faest_256s(iterations);
  bench_sign_faest_256f(iterations);
  return 0;
}
