/*
 * daa_bench.c — DAA FAEST Sign/Verify micro-benchmark
 *
 * Mirrors the format of tools/bench.cpp (which uses TPM-AES compiled params).
 * Here we use the original single-AES FAEST parameter sets via daa_faest.c,
 * so the output can be compared directly with the slide:
 *
 *   Scheme      KeyGen (us)   Sign (ms)   Verify (ms)   SigSize (B)
 *
 * KeyGen here = rand_bytes(sk_u) + bit-clear + OWF (same as NIST keygen).
 * Sign = daa_faest_sign() only.
 * Verify = daa_faest_verify() only.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "daa_faest.h"
#include "randomness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec * 1e-3;
}

static void bench_variant(const char* name, unsigned int lambda, int fast,
                          unsigned int n_iter) {
  const size_t key_bytes = lambda / 8;
  const size_t etu_bytes = daa_faest_etu_bytes(lambda);
  const size_t sig_bytes = daa_faest_max_sig_size(lambda, fast);

  uint8_t  gid[16];
  uint8_t* sk_u = malloc(key_bytes);
  uint8_t* et_u = malloc(etu_bytes);
  uint8_t* sig  = malloc(sig_bytes);

  if (!sk_u || !et_u || !sig) { fprintf(stderr, "alloc failed\n"); goto done; }

  /* Fixed gid */
  rand_bytes(gid, sizeof(gid));

  double t_keygen = 0, t_sign = 0, t_verify = 0;

  for (unsigned int i = 0; i < n_iter; i++) {
    double t0, t1;
    size_t sig_len = 0;

    /* KeyGen: rand_bytes + bit-clear + OWF */
    t0 = now_us();
    rand_bytes(sk_u, key_bytes);
    sk_u[0] &= ~(uint8_t)0x01u;
    daa_faest_owf(lambda, sk_u, gid, et_u);
    t1 = now_us();
    t_keygen += (t1 - t0);

    /* Sign */
    t0 = now_us();
    int ret = daa_faest_sign(lambda, fast, sk_u, gid, et_u,
                             NULL, 0, sig, &sig_len);
    t1 = now_us();
    if (ret != 0) { fprintf(stderr, "[%s] Sign failed at iter %u\n", name, i); goto done; }
    t_sign += (t1 - t0);

    /* Verify */
    t0 = now_us();
    ret = daa_faest_verify(lambda, fast, gid, et_u, NULL, 0, sig, sig_len);
    t1 = now_us();
    if (ret != 0) { fprintf(stderr, "[%s] Verify FAILED at iter %u\n", name, i); goto done; }
    t_verify += (t1 - t0);
  }

  printf("%-12s %11.2f  %11.3f  %11.3f  %10zu\n",
         name,
         t_keygen / n_iter,           /* µs */
         t_sign   / n_iter / 1000.0,  /* ms */
         t_verify / n_iter / 1000.0,  /* ms */
         sig_bytes);

done:
  free(sk_u); free(et_u); free(sig);
}

int main(void) {
  const unsigned int N = 100;

  printf("DAA FAEST local performance (original single-AES parameter sets)\n");
  printf("Iterations: %u\n\n", N);
  printf("%-12s %11s  %11s  %11s  %10s\n",
         "Scheme", "KeyGen (us)", "Sign (ms)", "Verify (ms)", "SigSize (B)");
  printf("%-12s %11s  %11s  %11s  %10s\n",
         "------", "-----------", "---------", "-----------", "-----------");

  bench_variant("FAEST-128S", 128, 0, N);
  bench_variant("FAEST-192S", 192, 0, N);
  bench_variant("FAEST-256S", 256, 0, N);
  bench_variant("FAEST-128F", 128, 1, N);
  bench_variant("FAEST-192F", 192, 1, N);
  bench_variant("FAEST-256F", 256, 1, N);

  return 0;
}
