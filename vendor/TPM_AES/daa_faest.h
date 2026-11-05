

#ifndef DAA_FAEST_H
#define DAA_FAEST_H

#include <stddef.h>
#include <stdint.h>

#define DAA_FAEST_128F_SIG_SIZE  5924u
#define DAA_FAEST_192F_SIG_SIZE  14948u
#define DAA_FAEST_256F_SIG_SIZE  26548u
#define DAA_FAEST_128S_SIG_SIZE  4506u
#define DAA_FAEST_192S_SIG_SIZE  11260u
#define DAA_FAEST_256S_SIG_SIZE  20696u

#define DAA_FAEST_ETU_SIZE(lambda) ((lambda) == 128 ? 16u : 32u)

#ifdef __cplusplus
extern "C" {
#endif

void daa_faest_owf(unsigned int lambda, const uint8_t* sk_u,
                   const uint8_t* gid, uint8_t* et_u_out);

int daa_faest_sign(unsigned int lambda, int fast,
                   const uint8_t* sk_u, const uint8_t* gid, const uint8_t* et_u,
                   const uint8_t* msg, size_t msglen,
                   uint8_t* sig, size_t* sig_len);

int daa_faest_verify(unsigned int lambda, int fast,
                     const uint8_t* gid, const uint8_t* et_u,
                     const uint8_t* msg, size_t msglen,
                     const uint8_t* sig, size_t sig_len);

size_t daa_faest_max_sig_size(unsigned int lambda, int fast);

size_t daa_faest_etu_bytes(unsigned int lambda);

#ifdef __cplusplus
}
#endif

#endif
