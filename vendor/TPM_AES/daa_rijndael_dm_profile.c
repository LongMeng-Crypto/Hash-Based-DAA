/* Benchmark Rijndael-256 Davies--Meyer Join and TPM-signing VOLE proofs. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "daa_rijndael_dm.h"
#include "randomness.h"

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

/* Abort immediately when a relation or proof check fails. */
static void die_step(const char* variant, const char* step, int ret) {
  fprintf(stderr, "[%s] %s failed: %d\n", variant, step, ret);
  abort();
}

/* Parse an optional positive iteration count. */
static unsigned int read_iters(int argc, char** argv) {
  if (argc < 2) return 20;
  char* end = NULL;
  const unsigned long value = strtoul(argv[1], &end, 10);
  return end && *end == '\0' && value > 0 ? (unsigned int)value : 20;
}

/* Check the upstream Rijndael-256 vector and full-width DM feed-forward. */
static void check_native_kat(void) {
  static const uint8_t expected[DAA_RDM_BYTES] = {
      0xe6, 0x2a, 0xbc, 0xe0, 0x69, 0x83, 0x7b, 0x65,
      0x30, 0x9b, 0xe4, 0xed, 0xa2, 0xc0, 0xe1, 0x49,
      0xfe, 0x56, 0xc0, 0x7b, 0x70, 0x82, 0xd3, 0x28,
      0x7f, 0x59, 0x2c, 0x4a, 0x49, 0x27, 0xa2, 0x77,
  };
  uint8_t key[DAA_RDM_BYTES] = {0x80};
  uint8_t input[DAA_RDM_BYTES] = {0};
  uint8_t output[DAA_RDM_BYTES];
  daa_rdm_eval(key, input, output);
  if (memcmp(output, expected, sizeof(expected)) != 0) {
    die_step("KAT", "Rijndael-256 DM", -1);
  }
}

/* Benchmark one Join profile and reject a one-byte proof mutation. */
static void bench_join(const char* name, int fast, unsigned int iterations) {
  uint8_t sk[DAA_RDM_BYTES];
  uint8_t gid[DAA_RDM_BYTES];
  uint8_t et[DAA_RDM_BYTES];
  const size_t capacity = daa_rdm_join_proof_size(fast);
  uint8_t* proof = malloc(capacity);
  size_t proof_len = capacity;
  int ret;
  if (!proof || rand_bytes(sk, sizeof(sk)) || rand_bytes(gid, sizeof(gid))) abort();
  daa_rdm_eval(sk, gid, et);

  ret = daa_rdm_join_prove(fast, sk, gid, et, NULL, 0, proof, &proof_len);
  if (ret) die_step(name, "warmup Join prove", ret);
  ret = daa_rdm_join_verify(fast, gid, et, NULL, 0, proof, proof_len);
  if (ret) die_step(name, "warmup Join verify", ret);
  et[0] ^= 1;
  if (daa_rdm_join_verify(fast, gid, et, NULL, 0, proof, proof_len) == 0) {
    die_step(name, "wrong Join et accepted", -1);
  }
  et[0] ^= 1;
  proof[0] ^= 1;
  if (daa_rdm_join_verify(fast, gid, et, NULL, 0, proof, proof_len) == 0) {
    die_step(name, "Join mutation accepted", -1);
  }
  proof[0] ^= 1;

  double prover_us = 0.0;
  double verifier_us = 0.0;
  for (unsigned int i = 0; i != iterations; ++i) {
    proof_len = capacity;
    const double begin = now_us();
    ret = daa_rdm_join_prove(fast, sk, gid, et, NULL, 0, proof, &proof_len);
    const double proved = now_us();
    if (ret) die_step(name, "Join prove", ret);
    ret = daa_rdm_join_verify(fast, gid, et, NULL, 0, proof, proof_len);
    const double verified = now_us();
    if (ret) die_step(name, "Join verify", ret);
    prover_us += proved - begin;
    verifier_us += verified - proved;
  }
  printf("join\t%s\t%.6f\t%.6f\t%zu\n", name, prover_us / iterations / 1000.0,
         verifier_us / iterations / 1000.0, proof_len);
  free(proof);
}

/* Benchmark one three-function signing profile with a hidden shared et. */
static void bench_sign(const char* name, int fast, unsigned int iterations) {
  uint8_t sk[DAA_RDM_BYTES];
  uint8_t s[DAA_RDM_BYTES];
  uint8_t lid[DAA_RDM_BYTES];
  uint8_t gid[DAA_RDM_BYTES];
  uint8_t slt[DAA_RDM_BYTES];
  uint8_t et[DAA_RDM_BYTES];
  uint8_t hk[DAA_RDM_BYTES];
  const size_t capacity = daa_rdm_sign_proof_size(fast);
  uint8_t* proof = malloc(capacity);
  size_t proof_len = capacity;
  int ret;
  if (!proof || rand_bytes(sk, sizeof(sk)) || rand_bytes(s, sizeof(s)) ||
      rand_bytes(lid, sizeof(lid)) || rand_bytes(gid, sizeof(gid))) abort();
  daa_rdm_eval(sk, lid, slt);
  daa_rdm_eval(sk, gid, et);
  daa_rdm_eval(s, et, hk);

  ret = daa_rdm_sign_prove(fast, sk, s, lid, gid, slt, hk, NULL, 0, proof, &proof_len);
  if (ret) die_step(name, "warmup Sign prove", ret);
  ret = daa_rdm_sign_verify(fast, lid, gid, slt, hk, NULL, 0, proof, proof_len);
  if (ret) die_step(name, "warmup Sign verify", ret);
  hk[0] ^= 1;
  if (daa_rdm_sign_verify(fast, lid, gid, slt, hk, NULL, 0, proof, proof_len) == 0) {
    die_step(name, "wrong Sign hk accepted", -1);
  }
  hk[0] ^= 1;
  proof[0] ^= 1;
  if (daa_rdm_sign_verify(fast, lid, gid, slt, hk, NULL, 0, proof, proof_len) == 0) {
    die_step(name, "Sign mutation accepted", -1);
  }
  proof[0] ^= 1;

  double prover_us = 0.0;
  double verifier_us = 0.0;
  for (unsigned int i = 0; i != iterations; ++i) {
    proof_len = capacity;
    const double begin = now_us();
    ret = daa_rdm_sign_prove(fast, sk, s, lid, gid, slt, hk, NULL, 0, proof, &proof_len);
    const double proved = now_us();
    if (ret) die_step(name, "Sign prove", ret);
    ret = daa_rdm_sign_verify(fast, lid, gid, slt, hk, NULL, 0, proof, proof_len);
    const double verified = now_us();
    if (ret) die_step(name, "Sign verify", ret);
    prover_us += proved - begin;
    verifier_us += verified - proved;
  }
  printf("sign\t%s\t%.6f\t%.6f\t%zu\n", name, prover_us / iterations / 1000.0,
         verifier_us / iterations / 1000.0, proof_len);
  free(proof);
}

/* Run the complete, independent 128s/128f Rijndael-256 DM benchmark line. */
int main(int argc, char** argv) {
  const unsigned int iterations = read_iters(argc, argv);
  check_native_kat();
  printf("phase\tparameter\tprover_ms\tverifier_ms\tproof_bytes\n");
  bench_join("128s", 0, iterations);
  bench_join("128f", 1, iterations);
  bench_sign("128s", 0, iterations);
  bench_sign("128f", 1, iterations);
  return 0;
}
