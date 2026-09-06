#include "api.h"
#include "issuer_anchor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned rng_state = 7123;
static unsigned rng_calls = 0;
static unsigned long long rng_bytes = 0;
void randombytes(unsigned char *out, unsigned long long len) {
  rng_calls++;
  rng_bytes += len;
  for (unsigned long long i = 0; i < len; i++) {
    rng_state = 1664525 * rng_state + 1013904223;
    out[i] = rng_state >> 24;
  }
}
int main(void) {
  unsigned char pk[SPX_PK_BYTES], sk[SPX_SK_BYTES], seed[3 * SPX_N];
  for (unsigned i = 0; i < sizeof(seed); i++)
    seed[i] = i + 7;
  if (crypto_sign_seed_keypair(pk, sk, seed))
    return 1;
  size_t len = sphincs_issuer_anchor_certificate_bytes();
  unsigned char *c = malloc(len);
  if (!c)
    return 2;
  unsigned generation_rng = rng_state;
  rng_calls = 0;
  rng_bytes = 0;
  if (sphincs_issuer_anchor_generate(c, &len, pk, sk) ||
      sphincs_issuer_anchor_verify(c, len, pk))
    return 2;
  size_t expected_len = 26 + SPX_N * (2 * SPX_FORS_HEIGHT + SPX_FORS_TREES +
                                      SPX_D * SPX_WOTS_LEN + SPX_FULL_HEIGHT);
  if (len != expected_len || len != sphincs_issuer_anchor_certificate_bytes() ||
      c[6] != 5 || c[7] != 2 || rng_calls != 1 || rng_bytes != SPX_N)
    return 12;
  /* Insufficient capacity must fail before signing or writing the certificate.
   */
  size_t short_len = len - 1;
  if (!sphincs_issuer_anchor_generate(c, &short_len, pk, sk) || rng_calls != 1)
    return 13;
  unsigned char *sig = malloc(SPX_BYTES),
                *projection = malloc(sphincs_issuer_anchor_certificate_bytes());
  if (!sig || !projection)
    return 8;
  size_t slen, plen = sphincs_issuer_anchor_certificate_bytes();
  const unsigned char msg = 0x49;
  rng_state = generation_rng;
  if (crypto_sign_signature(sig, &slen, &msg, 1, sk) ||
      sphincs_issuer_anchor_from_signature(projection, &plen, pk, sig, slen) ||
      plen != len || memcmp(projection, c, len))
    return 9;
  sig[0] ^= 1;
  plen = sphincs_issuer_anchor_certificate_bytes();
  if (!sphincs_issuer_anchor_from_signature(projection, &plen, pk, sig, slen))
    return 10;
  free(sig);
  free(projection);
  unsigned char witness[SPX_N], state[32], addr[44], value[2 * SPX_N],
      state2[32], addr2[44], value2[2 * SPX_N];
  if (sphincs_issuer_anchor_relation(witness, state, addr, value, c, len, pk,
                                     sk) ||
      sphincs_issuer_anchor_statement(state2, addr2, value2, c, len, pk) ||
      memcmp(state, state2, 32) || memcmp(addr, addr2, 44) ||
      memcmp(value, value2, 2 * SPX_N) || memcmp(witness, sk, SPX_N))
    return 3;
  if (!memcmp(addr, addr + 22, 22))
    return 11;
  sk[0] ^= 1;
  if (!sphincs_issuer_anchor_relation(witness, state, addr, value, c, len, pk,
                                      sk))
    return 4;
  sk[0] ^= 1;
  if (!sphincs_issuer_anchor_verify(c, len - 1, pk) ||
      !sphincs_issuer_anchor_verify(c, len + 1, pk))
    return 5;
  for (size_t i = 0; i < len; i++) {
    c[i] ^= 1;
    int accepted = sphincs_issuer_anchor_verify(c, len, pk) == 0;
    c[i] ^= 1;
    if (accepted) {
      fprintf(stderr, "accepted mutation %zu\n", i);
      return 6;
    }
  }
  pk[0] ^= 1;
  if (!sphincs_issuer_anchor_verify(c, len, pk))
    return 7;
  printf(
      "n=%d d=%d certificate=%zu: one signature, fixed double-FORS selection, "
      "public signature projection, "
      "shared-seed double relation, distinct addresses, public statement, "
      "all-byte mutations OK\n",
      SPX_N, SPX_D, len);
  free(c);
  return 0;
}
