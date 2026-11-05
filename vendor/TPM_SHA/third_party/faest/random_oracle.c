/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <string.h>

#include "random_oracle.h"
#include "instances.h"

// Implements h0 init.
void H0_init(H0_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, security_param);
}

// Implements h0 update.
void H0_update(H0_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

// Implements h0 final.
void H0_final(H0_context_t* ctx, uint8_t* seed, size_t seed_len, uint8_t* commitment,
              size_t commitment_len) {
  H0_final_for_squeeze(ctx);
  hash_squeeze(ctx, seed, seed_len);
  hash_squeeze(ctx, commitment, commitment_len);
  hash_clear(ctx);
}

// Implements h0 final for squeeze.
void H0_final_for_squeeze(H0_context_t* ctx) {
  const uint8_t domain_sep_H0 = 0;
  hash_update(ctx, &domain_sep_H0, sizeof(domain_sep_H0));
  hash_final(ctx);
}

// Implements h0 squeeze.
void H0_squeeze(H0_context_t* H0_ctx, uint8_t* dst, size_t len) {
  hash_squeeze(H0_ctx, dst, len);
}

// Implements h0 clear.
void H0_clear(H0_context_t* H0_ctx) {
  hash_clear(H0_ctx);
}

// Implements h1 init.
void H1_init(H1_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, security_param);
}

// Implements h1 update.
void H1_update(H1_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

// Implements h1 final.
void H1_final(H1_context_t* ctx, uint8_t* digest, size_t len) {
  const uint8_t domain_sep_H1 = 1;
  hash_update(ctx, &domain_sep_H1, sizeof(domain_sep_H1));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

// Implements h2 init.
void H2_init(H2_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, security_param);
}

// Implements h2 copy.
void H2_copy(H2_context_t* new_ctx, const H2_context_t* ctx) {
  hash_copy(new_ctx, ctx);
}

// Implements h2 update.
void H2_update(H2_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

// Implements h2 update u32 le.
void H2_update_u32_le(H2_context_t* ctx, uint32_t v) {
  hash_update_uint32_le(ctx, v);
}

// Implements h2 0 final.
void H2_0_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  const uint8_t domain_sep_H2_0 = 8 + 0;
  hash_update(ctx, &domain_sep_H2_0, sizeof(domain_sep_H2_0));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

// Implements h2 1 final.
void H2_1_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  const uint8_t domain_sep_H2_1 = 8 + 1;
  hash_update(ctx, &domain_sep_H2_1, sizeof(domain_sep_H2_1));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

// Implements h2 2 final.
void H2_2_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  const uint8_t domain_sep_H2_2 = 8 + 2;
  hash_update(ctx, &domain_sep_H2_2, sizeof(domain_sep_H2_2));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

// Implements h2 3 final.
void H2_3_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  const uint8_t domain_sep_H2_3 = 8 + 3;
  hash_update(ctx, &domain_sep_H2_3, sizeof(domain_sep_H2_3));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

// Implements h3 init.
void H3_init(H3_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, security_param);
}

// Implements h3 update.
void H3_update(H3_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

// Implements h3 final.
void H3_final(H3_context_t* ctx, uint8_t* digest, size_t len, uint8_t* iv) {
  const uint8_t domain_sep_H3 = 3;
  hash_update(ctx, &domain_sep_H3, sizeof(domain_sep_H3));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_squeeze(ctx, iv, IV_SIZE);
  hash_clear(ctx);
}

// Implements h4.
void H4(uint8_t* iv, const uint8_t* pre_iv, unsigned int security_params) {
  hash_context ctx;
  hash_init(&ctx, security_params);
  hash_update(&ctx, pre_iv, IV_SIZE);
  const uint8_t domain_sep_H4 = 4;
  hash_update(&ctx, &domain_sep_H4, sizeof(domain_sep_H4));
  hash_final(&ctx);
  hash_squeeze(&ctx, iv, IV_SIZE);
  hash_clear(&ctx);
}
