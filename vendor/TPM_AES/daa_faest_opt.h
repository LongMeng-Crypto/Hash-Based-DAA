/*
 * daa_faest_opt.h — fixed-entry and scratch-buffer DAA FAEST helpers.
 *
 * These APIs keep the protocol statement unchanged. They only avoid repeated
 * allocation and let benchmark callers fuse OWF computation with witness setup.
 */

#ifndef DAA_FAEST_OPT_H
#define DAA_FAEST_OPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t* witness;
  size_t witness_bytes;
} daa_faest_scratch_t;

int daa_faest_scratch_init(daa_faest_scratch_t* scratch, unsigned int lambda, int fast);
void daa_faest_scratch_clear(daa_faest_scratch_t* scratch);

int daa_faest_sign_fused(unsigned int lambda, int fast,
                         const uint8_t* sk_u, const uint8_t* gid,
                         uint8_t* et_u_out,
                         const uint8_t* msg, size_t msglen,
                         uint8_t* sig, size_t* sig_len,
                         daa_faest_scratch_t* scratch);

int daa_faest_sign_with_scratch(unsigned int lambda, int fast,
                                const uint8_t* sk_u, const uint8_t* gid,
                                const uint8_t* et_u,
                                const uint8_t* msg, size_t msglen,
                                uint8_t* sig, size_t* sig_len,
                                daa_faest_scratch_t* scratch);

int daa_faest_128s_1aes_sign_fused(const uint8_t* sk_u, const uint8_t* gid,
                                   uint8_t* et_u_out, const uint8_t* msg,
                                   size_t msglen, uint8_t* sig, size_t* sig_len,
                                   daa_faest_scratch_t* scratch);
int daa_faest_128f_1aes_sign_fused(const uint8_t* sk_u, const uint8_t* gid,
                                   uint8_t* et_u_out, const uint8_t* msg,
                                   size_t msglen, uint8_t* sig, size_t* sig_len,
                                   daa_faest_scratch_t* scratch);
int daa_faest_192s_1aes_sign_fused(const uint8_t* sk_u, const uint8_t* gid,
                                   uint8_t* et_u_out, const uint8_t* msg,
                                   size_t msglen, uint8_t* sig, size_t* sig_len,
                                   daa_faest_scratch_t* scratch);
int daa_faest_192f_1aes_sign_fused(const uint8_t* sk_u, const uint8_t* gid,
                                   uint8_t* et_u_out, const uint8_t* msg,
                                   size_t msglen, uint8_t* sig, size_t* sig_len,
                                   daa_faest_scratch_t* scratch);
int daa_faest_256s_1aes_sign_fused(const uint8_t* sk_u, const uint8_t* gid,
                                   uint8_t* et_u_out, const uint8_t* msg,
                                   size_t msglen, uint8_t* sig, size_t* sig_len,
                                   daa_faest_scratch_t* scratch);
int daa_faest_256f_1aes_sign_fused(const uint8_t* sk_u, const uint8_t* gid,
                                   uint8_t* et_u_out, const uint8_t* msg,
                                   size_t msglen, uint8_t* sig, size_t* sig_len,
                                   daa_faest_scratch_t* scratch);

int daa_faest_128s_1aes_verify(const uint8_t* gid, const uint8_t* et_u,
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* sig, size_t sig_len);
int daa_faest_128f_1aes_verify(const uint8_t* gid, const uint8_t* et_u,
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* sig, size_t sig_len);
int daa_faest_192s_1aes_verify(const uint8_t* gid, const uint8_t* et_u,
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* sig, size_t sig_len);
int daa_faest_192f_1aes_verify(const uint8_t* gid, const uint8_t* et_u,
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* sig, size_t sig_len);
int daa_faest_256s_1aes_verify(const uint8_t* gid, const uint8_t* et_u,
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* sig, size_t sig_len);
int daa_faest_256f_1aes_verify(const uint8_t* gid, const uint8_t* et_u,
                               const uint8_t* msg, size_t msglen,
                               const uint8_t* sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* DAA_FAEST_OPT_H */
