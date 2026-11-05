

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "daa_faest.h"
#include "random_oracle.h"
#include "randomness.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Implements now ms.
static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec * 1e-6;
}

// Hashes the operation result.
static void daa_hash(unsigned int lambda,
                     const uint8_t* in,  size_t in_len,
                     uint8_t*       out, size_t out_len) {
  H1_context_t ctx;
  H1_init(&ctx, lambda);
  H1_update(&ctx, in, in_len);
  H1_final(&ctx, out, out_len);
}

typedef struct {
  double tpm;
  double host;
  double issuer;
} bench_result_t;

// Runs bench.
static bench_result_t run_bench(unsigned int lambda, int fast, unsigned int n_iter) {
  bench_result_t res = {0.0, 0.0, 0.0};

  const size_t key_bytes = lambda / 8;
  const size_t etu_bytes = daa_faest_etu_bytes(lambda);
  const size_t sig_bytes = daa_faest_max_sig_size(lambda, fast);
  const size_t buf_bytes = etu_bytes + key_bytes;

  printf("=== FAEST-%u%s ===\n", lambda, fast ? "f" : "s");
  printf("  sk_u %zu B | gid 16 B | et_u %zu B | cr %zu B | ct %zu B | gr_u %zu B | sig %zu B\n",
         key_bytes, etu_bytes, key_bytes, key_bytes, key_bytes, sig_bytes);

  uint8_t  gid[16];
  uint8_t  mpk_buf[32];

  uint8_t* sk_u  = malloc(key_bytes);
  uint8_t* et_u  = malloc(etu_bytes);
  uint8_t* sig   = malloc(sig_bytes);
  uint8_t* cr    = malloc(key_bytes);
  uint8_t* ct_h  = malloc(key_bytes);
  uint8_t* ct_i  = malloc(key_bytes);
  uint8_t* gr_u  = malloc(key_bytes);
  uint8_t* hbuf  = malloc(buf_bytes);

  if (!sk_u || !et_u || !sig || !cr || !ct_h || !ct_i || !gr_u || !hbuf) {
    fprintf(stderr, "Allocation failed (lambda=%u)\n", lambda);
    goto cleanup;
  }

  rand_bytes(mpk_buf, sizeof(mpk_buf));
  daa_hash(lambda, mpk_buf, sizeof(mpk_buf), gid, sizeof(gid));

  for (unsigned int i = 0; i < n_iter; ++i) {
    double t0, t1;
    size_t sig_len = 0;

    t0 = now_ms();

    rand_bytes(sk_u, key_bytes);
    sk_u[0] &= ~(uint8_t)0x01u;

    daa_faest_owf(lambda, sk_u, gid, et_u);

    int ret = daa_faest_sign(lambda, fast, sk_u, gid, et_u, NULL, 0, sig, &sig_len);
    t1 = now_ms();

    if (ret != 0) {
      fprintf(stderr, "[iter %u] FAEST.Sign failed (lambda=%u)\n", i, lambda);
      goto cleanup;
    }
    res.tpm += (t1 - t0);

    t0 = now_ms();

    rand_bytes(cr, key_bytes);

    memcpy(hbuf, et_u, etu_bytes);
    memcpy(hbuf + etu_bytes, cr, key_bytes);
    daa_hash(lambda, hbuf, buf_bytes, ct_h, key_bytes);

    t1 = now_ms();
    res.host += (t1 - t0);

    t0 = now_ms();

    rand_bytes(gr_u, key_bytes);

    memcpy(hbuf,             et_u, etu_bytes);
    memcpy(hbuf + etu_bytes, cr,   key_bytes);
    daa_hash(lambda, hbuf, buf_bytes, ct_i, key_bytes);

    if (memcmp(ct_h, ct_i, key_bytes) != 0) {
      fprintf(stderr, "[iter %u] commitment mismatch (lambda=%u)\n", i, lambda);
      goto cleanup;
    }

    ret = daa_faest_verify(lambda, fast, gid, et_u, NULL, 0, sig, sig_len);
    t1 = now_ms();

    if (ret != 0) {
      fprintf(stderr, "[iter %u] FAEST.Verify FAILED (lambda=%u)\n", i, lambda);
      goto cleanup;
    }
    res.issuer += (t1 - t0);
  }

  res.tpm    /= n_iter;
  res.host   /= n_iter;
  res.issuer /= n_iter;

  printf("  TPM    (keygen+OWF+Sign):  %8.3f ms\n", res.tpm);
  printf("  Host   (cr+commit):        %8.3f ms\n", res.host);
  printf("  Issuer (gr_u+check+Verify):%8.3f ms\n", res.issuer);
  printf("  [all %u iterations passed]\n\n", n_iter);

cleanup:
  free(sk_u); free(et_u); free(sig);
  free(cr);   free(ct_h); free(ct_i);
  free(gr_u); free(hbuf);
  return res;
}

// Implements main.
int main(void) {

  const unsigned int N = 100;

  printf("DAA Joining Protocol Benchmark\n");
  printf("(SPHINCS+ steps excluded — implemented in Rust)\n");
  printf("Iterations per variant: %u\n\n", N);

  bench_result_t r128s = run_bench(128, 0, N);
  bench_result_t r128f = run_bench(128, 1, N);
  bench_result_t r192s = run_bench(192, 0, N);
  bench_result_t r192f = run_bench(192, 1, N);
  bench_result_t r256s = run_bench(256, 0, N);
  bench_result_t r256f = run_bench(256, 1, N);

  printf("+-----------+-----------------------+-----------------------+-----------------------+\n");
  printf("| Variant   | TPM  (ms)             | Host (ms)             | Issuer (ms)           |\n");
  printf("|           | keygen + OWF + Sign   | cr + H(et‖cr)        | gr_u + check + Verify |\n");
  printf("+-----------+-----------------------+-----------------------+-----------------------+\n");
  printf("| FAEST-128s| %21.3f | %21.3f | %21.3f |\n", r128s.tpm, r128s.host, r128s.issuer);
  printf("| FAEST-128f| %21.3f | %21.3f | %21.3f |\n", r128f.tpm, r128f.host, r128f.issuer);
  printf("| FAEST-192s| %21.3f | %21.3f | %21.3f |\n", r192s.tpm, r192s.host, r192s.issuer);
  printf("| FAEST-192f| %21.3f | %21.3f | %21.3f |\n", r192f.tpm, r192f.host, r192f.issuer);
  printf("| FAEST-256s| %21.3f | %21.3f | %21.3f |\n", r256s.tpm, r256s.host, r256s.issuer);
  printf("| FAEST-256f| %21.3f | %21.3f | %21.3f |\n", r256f.tpm, r256f.host, r256f.issuer);
  printf("+-----------+-----------------------+-----------------------+-----------------------+\n");
  printf("(averaged over %u iterations per variant)\n", N);

  return 0;
}
