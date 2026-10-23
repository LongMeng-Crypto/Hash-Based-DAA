/*
 * daa_faest.h — Original single-AES FAEST for the DAA Joining Protocol
 *
 * Wraps the existing faest_impl.c/faest_aes machinery with the correct
 * original-FAEST parameter sets (one AES call for lambda=128, two for 192/256).
 * These differ from the TPM-credential FAEST (3-AES chain) in ELL and OWF sizes,
 * which causes the constraint dispatch to fall through to the original FAEST paths
 * already present in faest_aes_128/192/256.c and aes.c.
 */

#ifndef DAA_FAEST_H
#define DAA_FAEST_H

#include <stddef.h>
#include <stdint.h>

/* Maximum signature sizes for the original single-AES FAEST.
 * Computed from: sig = (tau-1)*ell_hat + (lambda/8+2) + ell/8 + 2*(lambda/8)
 *                    + 3*tau*(lambda/8) + T_open*(lambda/8)
 *                    + lambda/8 + 16 + 4
 */
#define DAA_FAEST_128F_SIG_SIZE  5924u
#define DAA_FAEST_192F_SIG_SIZE  14948u
#define DAA_FAEST_256F_SIG_SIZE  26548u
#define DAA_FAEST_128S_SIG_SIZE  4506u
#define DAA_FAEST_192S_SIG_SIZE  11260u
#define DAA_FAEST_256S_SIG_SIZE  20696u

/* et_u output size in bytes (16 for lambda=128, 32 for lambda=192/256) */
#define DAA_FAEST_ETU_SIZE(lambda) ((lambda) == 128 ? 16u : 32u)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Compute et_u = OWF_{sk_u}(gid).
 *   lambda   : 128, 192, or 256
 *   sk_u     : AES key, lambda/8 bytes
 *   gid      : always 16 bytes (128-bit group identifier)
 *   et_u_out : 16 bytes (lambda=128) or 32 bytes (lambda=192/256)
 *
 * For lambda=128: et_u = AES_sk_u(gid) XOR gid (DM-v1).
 * For lambda=192/256 the legacy two plain-AES calls are unchanged:
 *   et_u[0:16] = AES_{sk_u}(gid)
 *   et_u[16:32] = AES_{sk_u}(gid XOR 1)   (LSB of first byte flipped)
 */
void daa_faest_owf(unsigned int lambda, const uint8_t* sk_u,
                   const uint8_t* gid, uint8_t* et_u_out);

/*
 * FAEST.Sign — prove knowledge of sk_u such that et_u = OWF_{sk_u}(gid).
 *
 *   lambda   : 128, 192, or 256
 *   sk_u     : AES key, lambda/8 bytes. Bit 0 is cleared internally to satisfy
 *              the FAEST grinding requirement (witness bits 0 AND 1 must not both be 1).
 *   gid      : 16 bytes (public input)
 *   et_u     : 16 or 32 bytes (public output, computed by daa_faest_owf)
 *   msg/msglen: optional message to bind the signature to (may be NULL/0)
 *   sig      : output buffer, must be at least daa_faest_max_sig_size(lambda) bytes
 *   sig_len  : set to actual bytes written on success
 *
 * Returns 0 on success, non-zero on failure.
 */
int daa_faest_sign(unsigned int lambda, int fast,
                   const uint8_t* sk_u, const uint8_t* gid, const uint8_t* et_u,
                   const uint8_t* msg, size_t msglen,
                   uint8_t* sig, size_t* sig_len);

/*
 * FAEST.Verify — verify a signature produced by daa_faest_sign.
 *
 *   lambda   : 128, 192, or 256
 *   gid      : 16 bytes (public input)
 *   et_u     : 16 or 32 bytes (public output)
 *   msg/msglen: same message used during signing
 *   sig      : signature buffer
 *   sig_len  : length of sig (must equal daa_faest_max_sig_size(lambda))
 *
 * Returns 0 on success (valid), non-zero on failure/invalid.
 */
int daa_faest_verify(unsigned int lambda, int fast,
                     const uint8_t* gid, const uint8_t* et_u,
                     const uint8_t* msg, size_t msglen,
                     const uint8_t* sig, size_t sig_len);

/* Maximum signature buffer size needed for the given lambda and variant. */
size_t daa_faest_max_sig_size(unsigned int lambda, int fast);

/* et_u size in bytes for the given lambda. */
size_t daa_faest_etu_bytes(unsigned int lambda);

#ifdef __cplusplus
}
#endif

#endif /* DAA_FAEST_H */
