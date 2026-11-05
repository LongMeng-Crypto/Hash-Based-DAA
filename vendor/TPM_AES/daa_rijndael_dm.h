
#ifndef DAA_RIJNDAEL_DM_H
#define DAA_RIJNDAEL_DM_H

#include <stddef.h>
#include <stdint.h>

#define DAA_RDM_BYTES 32u

void daa_rdm_eval(const uint8_t key[DAA_RDM_BYTES], const uint8_t input[DAA_RDM_BYTES],
                  uint8_t output[DAA_RDM_BYTES]);

size_t daa_rdm_join_proof_size(int fast);
size_t daa_rdm_sign_proof_size(int fast);

int daa_rdm_join_prove(int fast, const uint8_t sk[DAA_RDM_BYTES],
                       const uint8_t gid[DAA_RDM_BYTES], const uint8_t et[DAA_RDM_BYTES],
                       const uint8_t* msg, size_t msg_len, uint8_t* proof, size_t* proof_len);
int daa_rdm_join_verify(int fast, const uint8_t gid[DAA_RDM_BYTES],
                        const uint8_t et[DAA_RDM_BYTES], const uint8_t* msg, size_t msg_len,
                        const uint8_t* proof, size_t proof_len);

int daa_rdm_sign_prove(int fast, const uint8_t sk[DAA_RDM_BYTES],
                       const uint8_t s[DAA_RDM_BYTES], const uint8_t lid[DAA_RDM_BYTES],
                       const uint8_t gid[DAA_RDM_BYTES], const uint8_t slt[DAA_RDM_BYTES],
                       const uint8_t hk[DAA_RDM_BYTES], const uint8_t* msg, size_t msg_len,
                       uint8_t* proof, size_t* proof_len);
int daa_rdm_sign_verify(int fast, const uint8_t lid[DAA_RDM_BYTES],
                        const uint8_t gid[DAA_RDM_BYTES], const uint8_t slt[DAA_RDM_BYTES],
                        const uint8_t hk[DAA_RDM_BYTES], const uint8_t* msg, size_t msg_len,
                        const uint8_t* proof, size_t proof_len);

#endif
