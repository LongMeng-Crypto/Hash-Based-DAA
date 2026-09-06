#include "api.h"
#include "issuer_anchor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned rng_state = 7123;
void randombytes(unsigned char *out, unsigned long long len) {
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
  if (!c || sphincs_issuer_anchor_generate(c, &len, pk, sk) ||
      sphincs_issuer_anchor_verify(c, len, pk))
    return 2;
  unsigned char *sig = malloc(SPX_BYTES),
                *projection = malloc(sphincs_issuer_anchor_certificate_bytes());
  if (!sig || !projection)
    return 8;
  size_t slen, plen = sphincs_issuer_anchor_certificate_bytes();
  const unsigned char msg = 0x49;
  rng_state = 7123;
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
  unsigned char witness[SPX_N], state[32], addr[22], value[SPX_N], state2[32],
      addr2[22], value2[SPX_N];
  if (sphincs_issuer_anchor_relation(witness, state, addr, value, c, len, pk,
                                     sk) ||
      sphincs_issuer_anchor_statement(state2, addr2, value2, c, len, pk) ||
      memcmp(state, state2, 32) || memcmp(addr, addr2, 22) ||
      memcmp(value, value2, SPX_N) || memcmp(witness, sk, SPX_N))
    return 3;
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
  printf("n=%d d=%d branch=%s certificate=%zu: public signature projection, "
         "seed relation, public statement, all-byte mutations OK\n",
         SPX_N, SPX_D, c[7] == 1 ? "top-wots" : "fors", len);
  free(c);
  return 0;
}
