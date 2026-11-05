/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef SHA3_S390_CPACF_H
#define SHA3_S390_CPACF_H

#include <string.h>
#include <stdint.h>

#include "macros.h"

typedef struct {
  uint8_t ctx[200];
  uint8_t data_block[168];
  uint8_t func;
  uint8_t data_block_size;
  uint8_t pos;
} hash_context ATTR_ALIGNED(32);

// Hashes init.
static inline void hash_init(hash_context* ctx, unsigned int security_param) {
  memset(ctx->ctx, 0, sizeof(ctx->ctx));
  memset(ctx->data_block, 0, sizeof(ctx->data_block));
  if (security_param == 128) {

    ctx->func            = 0x24;
    ctx->data_block_size = 168;
  } else {

    ctx->func            = 0x25;
    ctx->data_block_size = 136;
  }
  ctx->pos = 0;
}

// Hashes update kimd.
static inline void hash_update_kimd(hash_context* ctx, const uint8_t* data, size_t size) {

  register long func asm("0") = ctx->func;

  register uint8_t* param asm("1") = ctx->ctx;

  register const uint8_t* src asm("2") = data;

  register size_t src_size asm("3") = size;

  asm volatile("0:  .insn rre,0xb93e0000,0,%[src]\n\t"
               "    brc   1,0b\n\t"
               : [src] "+a"(src), "+d"(src_size)
               : "d"(func), "a"(param)
               : "cc", "memory");
}

// Hashes update klmd.
static inline void hash_update_klmd(hash_context* ctx, uint8_t* buffer, size_t buffer_size,
                                    const uint8_t* data, size_t size) {

  register long func asm("0") = ctx->func;

  register uint8_t* param asm("1") = ctx->ctx;

  register const uint8_t* src asm("2") = data;

  register size_t src_size asm("3") = size;

  register unsigned char* dst asm("4") = buffer;

  register long dst_size asm("5") = buffer_size;

  asm volatile("0:  .insn rre,0xb93f0000,%[dst],%[src]\n\t"
               "    brc   1,0b\n\t"
               : [src] "+a"(src), "+d"(src_size), [dst] "+a"(dst), "+d"(dst_size)
               : "d"(func), "a"(param)
               : "cc", "memory");
}

// Hashes squeeze kmld.
static inline void hash_squeeze_kmld(hash_context* ctx, uint8_t* buffer, size_t size) {
  hash_update_klmd(ctx, buffer, size, NULL, 0);
}

// Hashes update.
static inline void hash_update(hash_context* ctx, const uint8_t* data, size_t size) {

  if (ctx->pos) {
    const size_t gap       = ctx->data_block_size - ctx->pos;
    const size_t copy_size = MIN(gap, size);

    memcpy(ctx->data_block + ctx->pos, data, copy_size);
    ctx->pos += copy_size;
    data += copy_size;
    size -= copy_size;

    if (ctx->pos == ctx->data_block_size) {
      hash_update_kimd(ctx, ctx->data_block, ctx->data_block_size);
      ctx->pos = 0;
    }
  }

  if (size > ctx->data_block_size) {
    const size_t copy_size = size - (size % ctx->data_block_size);
    hash_update_kimd(ctx, data, copy_size);
    data += copy_size;
    size -= copy_size;
  }

  if (size) {
    memcpy(ctx->data_block, data, size);
    ctx->pos = size;
  }
}

// Hashes final.
static inline void hash_final(hash_context* ctx) {

  hash_update_klmd(ctx, ctx->data_block, ctx->data_block_size, ctx->data_block, ctx->pos);
  ctx->pos = 0;
}

// Hashes squeeze.
static inline void hash_squeeze(hash_context* ctx, uint8_t* buffer, size_t buflen) {

  if (ctx->pos < ctx->data_block_size) {
    const size_t gap       = ctx->data_block_size - ctx->pos;
    const size_t copy_size = MIN(gap, buflen);

    memcpy(buffer, ctx->data_block + ctx->pos, copy_size);
    ctx->pos += copy_size;
    buffer += copy_size;
    buflen -= copy_size;
  }

  if (buflen > ctx->data_block_size) {
    const size_t copy_size = buflen - (buflen % ctx->data_block_size);
    hash_squeeze_kmld(ctx, buffer, buflen);
    buffer += copy_size;
    buflen -= copy_size;
  }

  if (buflen) {
    hash_squeeze_kmld(ctx, ctx->data_block, ctx->data_block_size);
    memcpy(buffer, ctx->data_block, buflen);
    ctx->pos = buflen;
  }
}

#define hash_clear(ctx)

#endif
