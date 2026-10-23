/* Regression tests for feed-forward, shared witnesses, and public-input binding. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "aes.h"
#include "daa_faest.h"
#include "faest_impl.h"
#include "instances.h"
#include "owf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keep test checks active in optimized builds where assert() is disabled. */
static void require(int condition, const char* message) {
  if (!condition) { fprintf(stderr, "AES-DM regression failed: %s\n", message); exit(1); }
}

/* Compare against the FIPS AES-128 example, then apply its specified feed-forward. */
static void known_answer(void) {
  const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  const uint8_t data[16] = {0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  const uint8_t raw[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
  uint8_t output[16], inplace[16];
  daa_aes128_dm(key, data, output);
  for (unsigned i = 0; i < 16; ++i) require(output[i] == (raw[i] ^ data[i]), "DM KAT");
  memcpy(inplace, data, 16);
  daa_aes128_dm(key, inplace, inplace);
  require(memcmp(output, inplace, 16) == 0, "in-place DM");
  owf_128(key, data, output);
  require(memcmp(output, raw, 16) == 0, "generic AES must stay unchanged");
}

/* Exercise actual constraints, including malformed witnesses bypassing DAA wrappers. */
static void profile_test(int fast) {
  const faest_paramset_t* join = faest_get_paramset(fast ? DAA_FAEST_128F : DAA_FAEST_128S);
  const faest_paramset_t* sign = faest_get_paramset(fast ? FAEST_128F : FAEST_128S);
  uint8_t input[32], secret[48], output[32], raw[16], rho[16] = {0};
  memset(input, 0x45, 16); memset(input + 16, 0x76, 16);
  memset(secret, 0x20, 16); memset(secret + 32, 0x50, 16);
  daa_aes128_dm(secret, input + 16, secret + 16);
  daa_aes128_dm(secret, input, output);
  daa_aes128_dm(secret + 32, secret + 16, output + 16);
  uint8_t* witness = malloc(sign->l / 8);
  uint8_t* proof = malloc(sign->sig_size);
  require(witness && proof, "allocation");
  aes_extend_witness(witness, secret, input + 16, join);
  faest_sign(proof, NULL, 0, secret, input + 16, secret + 16, witness, rho, sizeof(rho), join);
  require(faest_verify(NULL, 0, proof, input + 16, secret + 16, join) == 0, "Join DM roundtrip");
  owf_128(secret, input + 16, raw);
  require(faest_verify(NULL, 0, proof, input + 16, raw, join) != 0, "Join rejects raw AES output");
  faest_sign(proof, NULL, 0, secret, input + 16, raw, witness, rho, sizeof(rho), join);
  require(faest_verify(NULL, 0, proof, input + 16, raw, join) != 0, "Join constrains feed-forward");
  aes_extend_witness(witness, secret, input, sign);
  faest_sign(proof, NULL, 0, secret, input, output, witness, rho, sizeof(rho), sign);
  require(faest_verify(NULL, 0, proof, input, output, sign) == 0, "Sign DM roundtrip");
  for (unsigned offset = 0; offset < sizeof(output); offset += 16) {
    output[offset] ^= 1;
    require(faest_verify(NULL, 0, proof, input, output, sign) != 0, "public slt/hk binding");
    output[offset] ^= 1;
  }
  input[16] ^= 1;
  require(faest_verify(NULL, 0, proof, input, output, sign) != 0, "gid binding");
  input[16] ^= 1;
  secret[16] ^= 1;
  aes_extend_witness(witness, secret, input, sign);
  faest_sign(proof, NULL, 0, secret, input, output, witness, rho, sizeof(rho), sign);
  require(faest_verify(NULL, 0, proof, input, output, sign) != 0, "hidden et linkage");
  free(proof); free(witness);
}

/* Validate both VOLE profiles against the same AES-128-DM relation. */
int main(void) {
  known_answer(); profile_test(0); profile_test(1);
  puts("AES-128-DM s/f: KAT, Join/Sign, feed-forward and hidden-et rejection tests: ok");
  return 0;
}
