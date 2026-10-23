/* Rijndael-256 Davies--Meyer TPM relations over the optimized 128-bit VOLE backend. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "daa_rijndael_dm.h"

#include "aes.h"
#include "compat.h"
#include "faest_impl.h"
#include "instances.h"
#include "randomness.h"

#include <stdlib.h>
#include <string.h>

/* Select the dedicated Join profile. */
static const faest_paramset_t* join_params(int fast) {
  return faest_get_paramset(fast ? DAA_RDM_JOIN_128F : DAA_RDM_JOIN_128S);
}

/* Select the dedicated TPM-signing profile. */
static const faest_paramset_t* sign_params(int fast) {
  return faest_get_paramset(fast ? DAA_RDM_SIGN_128F : DAA_RDM_SIGN_128S);
}

/* Evaluate the full-width Davies--Meyer construction. */
void daa_rdm_eval(const uint8_t key[DAA_RDM_BYTES], const uint8_t input[DAA_RDM_BYTES],
                  uint8_t output[DAA_RDM_BYTES]) {
  aes_round_keys_t round_keys;
  rijndael256_init_round_keys(&round_keys, key);
  rijndael256_encrypt_block(&round_keys, input, output);
  for (size_t i = 0; i != DAA_RDM_BYTES; ++i) {
    output[i] ^= input[i];
  }
}

/* Return the serialized Join proof size. */
size_t daa_rdm_join_proof_size(int fast) {
  return join_params(fast)->sig_size;
}

/* Return the serialized signing proof size. */
size_t daa_rdm_sign_proof_size(int fast) {
  return sign_params(fast)->sig_size;
}

/* Create a randomized VOLE proof for the Join relation. */
int daa_rdm_join_prove(int fast, const uint8_t sk[DAA_RDM_BYTES],
                       const uint8_t gid[DAA_RDM_BYTES], const uint8_t et[DAA_RDM_BYTES],
                       const uint8_t* msg, size_t msg_len, uint8_t* proof, size_t* proof_len) {
  const faest_paramset_t* params = join_params(fast);
  const size_t expected = params->sig_size;
  uint8_t rho[DAA_RDM_BYTES];
  uint8_t* witness;
  if (!proof_len || *proof_len < expected) return -1;
  witness = malloc(params->l / 8);
  if (!witness || rand_bytes(rho, sizeof(rho)) != 0) {
    free(witness);
    return -1;
  }
  aes_extend_witness(witness, sk, gid, params);
  faest_sign(proof, msg, msg_len, sk, gid, et, witness, rho, sizeof(rho), params);
  *proof_len = expected;
  faest_explicit_bzero(witness, params->l / 8);
  faest_explicit_bzero(rho, sizeof(rho));
  free(witness);
  return 0;
}

/* Verify a Join proof against its public gid and et. */
int daa_rdm_join_verify(int fast, const uint8_t gid[DAA_RDM_BYTES],
                        const uint8_t et[DAA_RDM_BYTES], const uint8_t* msg, size_t msg_len,
                        const uint8_t* proof, size_t proof_len) {
  const faest_paramset_t* params = join_params(fast);
  if (proof_len != params->sig_size) return -1;
  return faest_verify(msg, msg_len, proof, gid, et, params);
}

/* Create a randomized proof for all three linked TPM-signing DM calls. */
int daa_rdm_sign_prove(int fast, const uint8_t sk[DAA_RDM_BYTES],
                       const uint8_t s[DAA_RDM_BYTES], const uint8_t lid[DAA_RDM_BYTES],
                       const uint8_t gid[DAA_RDM_BYTES], const uint8_t slt[DAA_RDM_BYTES],
                       const uint8_t hk[DAA_RDM_BYTES], const uint8_t* msg, size_t msg_len,
                       uint8_t* proof, size_t* proof_len) {
  const faest_paramset_t* params = sign_params(fast);
  const size_t expected = params->sig_size;
  uint8_t secret[3 * DAA_RDM_BYTES];
  uint8_t public_input[2 * DAA_RDM_BYTES];
  uint8_t public_output[2 * DAA_RDM_BYTES];
  uint8_t rho[DAA_RDM_BYTES];
  uint8_t* witness;
  if (!proof_len || *proof_len < expected) return -1;
  witness = malloc(params->l / 8);
  if (!witness || rand_bytes(rho, sizeof(rho)) != 0) {
    free(witness);
    return -1;
  }

  memcpy(secret, sk, DAA_RDM_BYTES);
  daa_rdm_eval(sk, gid, secret + DAA_RDM_BYTES);
  memcpy(secret + 2 * DAA_RDM_BYTES, s, DAA_RDM_BYTES);
  memcpy(public_input, lid, DAA_RDM_BYTES);
  memcpy(public_input + DAA_RDM_BYTES, gid, DAA_RDM_BYTES);
  memcpy(public_output, slt, DAA_RDM_BYTES);
  memcpy(public_output + DAA_RDM_BYTES, hk, DAA_RDM_BYTES);

  aes_extend_witness(witness, secret, public_input, params);
  faest_sign(proof, msg, msg_len, sk, public_input, public_output, witness,
             rho, sizeof(rho), params);
  *proof_len = expected;
  faest_explicit_bzero(witness, params->l / 8);
  faest_explicit_bzero(secret, sizeof(secret));
  faest_explicit_bzero(rho, sizeof(rho));
  free(witness);
  return 0;
}

/* Verify the public slt and hk while et remains hidden inside the proof. */
int daa_rdm_sign_verify(int fast, const uint8_t lid[DAA_RDM_BYTES],
                        const uint8_t gid[DAA_RDM_BYTES], const uint8_t slt[DAA_RDM_BYTES],
                        const uint8_t hk[DAA_RDM_BYTES], const uint8_t* msg, size_t msg_len,
                        const uint8_t* proof, size_t proof_len) {
  const faest_paramset_t* params = sign_params(fast);
  uint8_t public_input[2 * DAA_RDM_BYTES];
  uint8_t public_output[2 * DAA_RDM_BYTES];
  if (proof_len != params->sig_size) return -1;
  memcpy(public_input, lid, DAA_RDM_BYTES);
  memcpy(public_input + DAA_RDM_BYTES, gid, DAA_RDM_BYTES);
  memcpy(public_output, slt, DAA_RDM_BYTES);
  memcpy(public_output + DAA_RDM_BYTES, hk, DAA_RDM_BYTES);
  return faest_verify(msg, msg_len, proof, public_input, public_output, params);
}
