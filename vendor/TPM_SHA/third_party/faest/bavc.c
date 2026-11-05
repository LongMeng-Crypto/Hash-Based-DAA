/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bavc.h"
#include "random_oracle.h"
#include "compat.h"
#include "aes.h"
#include "instances.h"
#include "universal_hashing.h"
#include "parameters.h"

#include <assert.h>
#include <string.h>

#define NODE(nodes, node, lambda_bytes) (&nodes[(node) * (lambda_bytes)])

// Implements expand seeds.
static void expand_seeds(uint8_t* nodes, const uint8_t* iv, const faest_paramset_t* params) {
  const unsigned int lambda_bytes = params->lambda / 8;

  for (unsigned int alpha = 0; alpha < params->L - 1; ++alpha) {

    prg_2_lambda(NODE(nodes, alpha, lambda_bytes), iv, alpha,
                 NODE(nodes, 2 * alpha + 1, lambda_bytes), params->lambda);
  }
}

// Generates seeds.
static uint8_t* generate_seeds(const uint8_t* root_seed, const uint8_t* iv,
                               const faest_paramset_t* params) {
  unsigned int lambda_bytes = params->lambda / 8;
  uint8_t* nodes            = calloc(2 * params->L - 1, lambda_bytes);
  assert(nodes);

  memcpy(NODE(nodes, 0, lambda_bytes), root_seed, lambda_bytes);
  expand_seeds(nodes, iv, params);

  return nodes;
}

// Implements faest leaf commit 128.
static inline void faest_leaf_commit_128(uint8_t* sd, uint8_t* com, const uint8_t* key,
                                         const uint8_t* iv, uint32_t tweak, const uint8_t* uhash) {
  uint8_t buffer[FAEST_128_LAMBDA / 8 * 4];
  prg_4_lambda(key, iv, tweak, buffer, FAEST_128_LAMBDA);
  leaf_hash_128(com, uhash, buffer);
  memcpy(sd, buffer, FAEST_128_LAMBDA / 8);
}

// Implements faest leaf commit 192.
static inline void faest_leaf_commit_192(uint8_t* sd, uint8_t* com, const uint8_t* key,
                                         const uint8_t* iv, uint32_t tweak, const uint8_t* uhash) {
  uint8_t buffer[FAEST_192_LAMBDA / 8 * 4];
  prg_4_lambda(key, iv, tweak, buffer, FAEST_192_LAMBDA);
  leaf_hash_192(com, uhash, buffer);
  memcpy(sd, buffer, FAEST_192_LAMBDA / 8);
}

// Implements faest leaf commit 256.
static inline void faest_leaf_commit_256(uint8_t* sd, uint8_t* com, const uint8_t* key,
                                         const uint8_t* iv, uint32_t tweak, const uint8_t* uhash) {
  uint8_t buffer[FAEST_256_LAMBDA / 8 * 4];
  prg_4_lambda(key, iv, tweak, buffer, FAEST_256_LAMBDA);
  leaf_hash_256(com, uhash, buffer);
  memcpy(sd, buffer, FAEST_256_LAMBDA / 8);
}

// Implements faest em leaf commit.
static inline void faest_em_leaf_commit(uint8_t* sd, uint8_t* com, const uint8_t* key,
                                        const uint8_t* iv, uint32_t tweak, unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  memcpy(sd, key, lambda_bytes);
  prg_2_lambda(key, iv, tweak, com, lambda);
}

#if defined(FAEST_TESTS)
// Implements leaf commit.
void leaf_commit(uint8_t* sd, uint8_t* com, const uint8_t* key, const uint8_t* iv, uint32_t tweak,
                 const uint8_t* uhash, const faest_paramset_t* params) {
  if (faest_is_em(params)) {
    faest_em_leaf_commit(sd, com, key, iv, tweak, params->lambda);
  } else {
    switch (params->lambda) {
    case 256: {
      faest_leaf_commit_256(sd, com, key, iv, tweak, uhash);
      break;
    }
    case 192: {
      faest_leaf_commit_192(sd, com, key, iv, tweak, uhash);
      break;
    }
    default: {
      faest_leaf_commit_128(sd, com, key, iv, tweak, uhash);
      break;
    }
    }
  }
}
#endif

// Implements pos in tree.
ATTR_PURE static inline unsigned int pos_in_tree(unsigned int i, unsigned int j,
                                                 const faest_paramset_t* params) {
  const unsigned int tmp = 1 << (params->k - 1);
  if (j < tmp) {
    return params->L - 1 + params->tau * j + i;
  }

  const unsigned int mask = tmp - 1;
  return params->L - 1 + params->tau * tmp + params->tau1 * (j & mask) + i;
}

// Implements bavc commit faest 128 loop.
static void bavc_commit_faest_128_loop(bavc_t* bavc, H0_context_t* uhash_ctx,
                                       H1_context_t* h1_com_ctx, const uint8_t* nodes,
                                       const uint8_t* iv, const faest_paramset_t* params) {
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = FAEST_128_LAMBDA / 8;
  const unsigned int com_size     = lambda_bytes * 3;

  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    uint8_t uhash[FAEST_128_LAMBDA / 8 * 3];
    H0_squeeze(uhash_ctx, uhash, sizeof(uhash));

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, FAEST_128_LAMBDA);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_leaf_commit_128(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                            NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, uhash);
      H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[FAEST_128_LAMBDA / 8 * 2];

    H1_final(&h1_ctx, hi, sizeof(hi));

    H1_update(h1_com_ctx, hi, sizeof(hi));
  }
}

// Implements bavc commit faest 192 loop.
static void bavc_commit_faest_192_loop(bavc_t* bavc, H0_context_t* uhash_ctx,
                                       H1_context_t* h1_com_ctx, const uint8_t* nodes,
                                       const uint8_t* iv, const faest_paramset_t* params) {
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = FAEST_192_LAMBDA / 8;
  const unsigned int com_size     = lambda_bytes * 3;

  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    uint8_t uhash[FAEST_192_LAMBDA / 8 * 3];
    H0_squeeze(uhash_ctx, uhash, sizeof(uhash));

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, FAEST_192_LAMBDA);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_leaf_commit_192(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                            NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, uhash);
      H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[FAEST_192_LAMBDA / 8 * 2];

    H1_final(&h1_ctx, hi, sizeof(hi));

    H1_update(h1_com_ctx, hi, sizeof(hi));
  }
}

// Implements bavc commit faest 256 loop.
static void bavc_commit_faest_256_loop(bavc_t* bavc, H0_context_t* uhash_ctx,
                                       H1_context_t* h1_com_ctx, const uint8_t* nodes,
                                       const uint8_t* iv, const faest_paramset_t* params) {
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = FAEST_256_LAMBDA / 8;
  const unsigned int com_size     = lambda_bytes * 3;

  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    uint8_t uhash[FAEST_256_LAMBDA / 8 * 3];
    H0_squeeze(uhash_ctx, uhash, sizeof(uhash));

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, FAEST_256_LAMBDA);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_leaf_commit_256(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                            NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, uhash);
      H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[FAEST_256_LAMBDA / 8 * 2];

    H1_final(&h1_ctx, hi, sizeof(hi));

    H1_update(h1_com_ctx, hi, sizeof(hi));
  }
}

// Implements bavc commit faest.
static void bavc_commit_faest(bavc_t* bavc, const uint8_t* root_key, const uint8_t* iv,
                              const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int com_size     = lambda_bytes * 3;

  H0_context_t uhash_ctx;
  H0_init(&uhash_ctx, lambda);
  H0_update(&uhash_ctx, iv, IV_SIZE);
  H0_final_for_squeeze(&uhash_ctx);

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  uint8_t* nodes = generate_seeds(root_key, iv, params);

  bavc->h   = malloc(lambda_bytes * 2);
  bavc->com = malloc(L * com_size);
  bavc->sd  = malloc(L * lambda_bytes);
  assert(bavc->h && bavc->com && bavc->sd);

  bavc->k = NODE(nodes, 0, lambda_bytes);

  assert(bavc->h);
  assert(bavc->com);
  assert(bavc->sd);
  assert(bavc->k);

  switch (lambda) {
  case 256: {
    bavc_commit_faest_256_loop(bavc, &uhash_ctx, &h1_com_ctx, nodes, iv, params);
    break;
  }
  case 192: {
    bavc_commit_faest_192_loop(bavc, &uhash_ctx, &h1_com_ctx, nodes, iv, params);
    break;
  }
  default: {
    bavc_commit_faest_128_loop(bavc, &uhash_ctx, &h1_com_ctx, nodes, iv, params);
    break;
  }
  }
  H0_clear(&uhash_ctx);

  H1_final(&h1_com_ctx, bavc->h, lambda_bytes * 2);
}

// Implements bavc commit faest em.
static void bavc_commit_faest_em(bavc_t* bavc, const uint8_t* rootKey, const uint8_t* iv,
                                 const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int com_size     = lambda_bytes * 2;

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  uint8_t* nodes = generate_seeds(rootKey, iv, params);

  bavc->h   = malloc(lambda_bytes * 2);
  bavc->com = malloc(L * com_size);
  bavc->sd  = malloc(L * lambda_bytes);
  assert(bavc->h && bavc->com && bavc->sd);

  bavc->k = NODE(nodes, 0, lambda_bytes);

  assert(bavc->h);
  assert(bavc->com);
  assert(bavc->sd);
  assert(bavc->k);

  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    H1_context_t h1_ctx;
    H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      faest_em_leaf_commit(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                           NODE(nodes, alpha, lambda_bytes), iv, i + L - 1, lambda);
      H1_update(&h1_ctx, bavc->com + offset * com_size, com_size);
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];

    H1_final(&h1_ctx, hi, lambda_bytes * 2);

    H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }

  H1_final(&h1_com_ctx, bavc->h, lambda_bytes * 2);
}

// Implements bavc commit.
void bavc_commit(bavc_t* bavc, const uint8_t* root_key, const uint8_t* iv,
                 const faest_paramset_t* params) {
  if (faest_is_em(params)) {
    bavc_commit_faest_em(bavc, root_key, iv, params);
  } else {
    bavc_commit_faest(bavc, root_key, iv, params);
  }
}

// Implements bavc open.
bool bavc_open(uint8_t* decom_i, const bavc_t* vc, const uint16_t* i_delta,
               const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = faest_is_em(params) ? (2 * lambda_bytes) : (3 * lambda_bytes);

  uint8_t* decom_i_end = decom_i + com_size * tau + params->T_open * lambda_bytes;

  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  assert(s);

  unsigned int nh = 0;

  for (unsigned int i = 0; i < tau; ++i) {
    unsigned int alpha = pos_in_tree(i, i_delta[i], params);
    ptr_set_bit(s, alpha, 1);
    ++nh;

    while (alpha > 0 && ptr_get_bit(s, (alpha - 1) / 2) == 0) {
      alpha = (alpha - 1) / 2;
      ptr_set_bit(s, alpha, 1);
      ++nh;
    }
  }

  if (nh - 2 * tau + 1 > params->T_open) {
    free(s);
    return false;
  }

  const uint8_t* com = vc->com;
  for (unsigned int i = 0; i < tau; ++i) {
    decom_i = faest_mempcpy(decom_i, com + i_delta[i] * com_size, com_size);
    com += bavc_max_node_index(i, tau_1, k) * com_size;
  }

  for (int i = L - 2; i >= 0; --i) {
    ptr_set_bit(s, i, ptr_get_bit(s, 2 * i + 1) | ptr_get_bit(s, 2 * i + 2));
    if ((ptr_get_bit(s, 2 * i + 1) ^ ptr_get_bit(s, 2 * i + 2)) == 1) {
      const unsigned int alpha = 2 * i + 1 + ptr_get_bit(s, 2 * i + 1);
      decom_i = faest_mempcpy(decom_i, NODE(vc->k, alpha, lambda_bytes), lambda_bytes);
    }
  }

  memset(decom_i, 0, decom_i_end - decom_i);

  free(s);
  return true;
}

// Implements reconstruct keys.
static bool reconstruct_keys(uint8_t* s, uint8_t* keys, const uint8_t* decom_i,
                             const uint16_t* i_delta, const uint8_t* iv,
                             const faest_paramset_t* params) {
  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int tau          = params->tau;

  const uint8_t* nodes = decom_i + (faest_is_em(params) ? 2 : 3) * tau * lambda_bytes;
  const uint8_t* end   = nodes + params->T_open * lambda_bytes;

  for (unsigned int i = 0; i < tau; ++i) {
    unsigned int alpha = pos_in_tree(i, i_delta[i], params);
    ptr_set_bit(s, alpha, 1);
  }

  for (int i = L - 2; i >= 0; --i) {
    ptr_set_bit(s, i, ptr_get_bit(s, 2 * i + 1) | ptr_get_bit(s, 2 * i + 2));
    if ((ptr_get_bit(s, 2 * i + 1) ^ ptr_get_bit(s, 2 * i + 2)) == 1) {
      if (nodes == end) {
        return false;
      }

      const unsigned int alpha = 2 * i + 1 + ptr_get_bit(s, 2 * i + 1);
      memcpy(keys + alpha * lambda_bytes, nodes, lambda_bytes);
      nodes += lambda_bytes;
    }
  }

  for (; nodes != end; ++nodes) {
    if (*nodes) {
      return false;
    }
  }

  for (unsigned int i = 0; i != L - 1; ++i) {
    if (!ptr_get_bit(s, i)) {
      prg_2_lambda(keys + i * lambda_bytes, iv, i, keys + (2 * i + 1) * lambda_bytes, lambda);
    }
  }

  return true;
}

// Implements bavc reconstruct faest 128 loop.
static void bavc_reconstruct_faest_128_loop(bavc_rec_t* bavc_rec, H0_context_t* uhash_ctx,
                                            H1_context_t* h1_com_ctx, const uint8_t* s,
                                            const uint8_t* keys, const uint8_t* decom_i,
                                            const uint8_t* iv, const faest_paramset_t* params) {

  const unsigned int L     = params->L;
  const unsigned int k     = params->k;
  const unsigned int tau   = params->tau;
  const unsigned int tau_1 = params->tau1;

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    uint8_t uhash[FAEST_128_LAMBDA / 8 * 3];
    H0_squeeze(uhash_ctx, uhash, sizeof(uhash));

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, FAEST_128_LAMBDA);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        H1_update(&h1_ctx, decom_i + i * 3 * FAEST_128_LAMBDA / 8, 3 * FAEST_128_LAMBDA / 8);
      } else {
        uint8_t com[3 * FAEST_128_LAMBDA / 8];
        faest_leaf_commit_128(bavc_rec->s + offset * FAEST_128_LAMBDA / 8, com,
                              keys + alpha * FAEST_128_LAMBDA / 8, iv, i + L - 1, uhash);
        ++offset;
        H1_update(&h1_ctx, com, sizeof(com));
      }
    }

    uint8_t hi[FAEST_128_LAMBDA / 8 * 2];
    H1_final(&h1_ctx, hi, sizeof(hi));
    H1_update(h1_com_ctx, hi, sizeof(hi));
  }
}

// Implements bavc reconstruct faest 192 loop.
static void bavc_reconstruct_faest_192_loop(bavc_rec_t* bavc_rec, H0_context_t* uhash_ctx,
                                            H1_context_t* h1_com_ctx, const uint8_t* s,
                                            const uint8_t* keys, const uint8_t* decom_i,
                                            const uint8_t* iv, const faest_paramset_t* params) {

  const unsigned int L     = params->L;
  const unsigned int k     = params->k;
  const unsigned int tau   = params->tau;
  const unsigned int tau_1 = params->tau1;

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    uint8_t uhash[FAEST_192_LAMBDA / 8 * 3];
    H0_squeeze(uhash_ctx, uhash, sizeof(uhash));

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, FAEST_192_LAMBDA);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        H1_update(&h1_ctx, decom_i + i * 3 * FAEST_192_LAMBDA / 8, 3 * FAEST_192_LAMBDA / 8);
      } else {
        uint8_t com[3 * FAEST_192_LAMBDA / 8];
        faest_leaf_commit_192(bavc_rec->s + offset * FAEST_192_LAMBDA / 8, com,
                              keys + alpha * FAEST_192_LAMBDA / 8, iv, i + L - 1, uhash);
        ++offset;
        H1_update(&h1_ctx, com, sizeof(com));
      }
    }

    uint8_t hi[FAEST_192_LAMBDA / 8 * 2];
    H1_final(&h1_ctx, hi, sizeof(hi));
    H1_update(h1_com_ctx, hi, sizeof(hi));
  }
}

// Implements bavc reconstruct faest 256 loop.
static void bavc_reconstruct_faest_256_loop(bavc_rec_t* bavc_rec, H0_context_t* uhash_ctx,
                                            H1_context_t* h1_com_ctx, const uint8_t* s,
                                            const uint8_t* keys, const uint8_t* decom_i,
                                            const uint8_t* iv, const faest_paramset_t* params) {

  const unsigned int L     = params->L;
  const unsigned int k     = params->k;
  const unsigned int tau   = params->tau;
  const unsigned int tau_1 = params->tau1;

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    uint8_t uhash[FAEST_256_LAMBDA / 8 * 3];
    H0_squeeze(uhash_ctx, uhash, sizeof(uhash));

    H1_context_t h1_ctx;
    H1_init(&h1_ctx, FAEST_256_LAMBDA);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        H1_update(&h1_ctx, decom_i + i * 3 * FAEST_256_LAMBDA / 8, 3 * FAEST_256_LAMBDA / 8);
      } else {
        uint8_t com[3 * FAEST_256_LAMBDA / 8];
        faest_leaf_commit_256(bavc_rec->s + offset * FAEST_256_LAMBDA / 8, com,
                              keys + alpha * FAEST_256_LAMBDA / 8, iv, i + L - 1, uhash);
        ++offset;
        H1_update(&h1_ctx, com, sizeof(com));
      }
    }

    uint8_t hi[FAEST_256_LAMBDA / 8 * 2];
    H1_final(&h1_ctx, hi, sizeof(hi));
    H1_update(h1_com_ctx, hi, sizeof(hi));
  }
}

// Implements bavc reconstruct faest.
static bool bavc_reconstruct_faest(bavc_rec_t* bavc_rec, const uint8_t* decom_i,
                                   const uint16_t* i_delta, const uint8_t* iv,
                                   const faest_paramset_t* params) {

  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;

  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  assert(s);
  uint8_t* keys = calloc(2 * params->L - 1, lambda_bytes);
  assert(keys);

  if (!reconstruct_keys(s, keys, decom_i, i_delta, iv, params)) {
    free(keys);
    free(s);
    return false;
  }

  H0_context_t uhash_ctx;
  H0_init(&uhash_ctx, lambda);
  H0_update(&uhash_ctx, iv, IV_SIZE);
  H0_final_for_squeeze(&uhash_ctx);

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  switch (lambda) {
  case 256: {
    bavc_reconstruct_faest_256_loop(bavc_rec, &uhash_ctx, &h1_com_ctx, s, keys, decom_i, iv,
                                    params);
    break;
  }
  case 192: {
    bavc_reconstruct_faest_192_loop(bavc_rec, &uhash_ctx, &h1_com_ctx, s, keys, decom_i, iv,
                                    params);
    break;
  }
  default: {
    bavc_reconstruct_faest_128_loop(bavc_rec, &uhash_ctx, &h1_com_ctx, s, keys, decom_i, iv,
                                    params);
    break;
  }
  }
  H0_clear(&uhash_ctx);

  H1_final(&h1_com_ctx, bavc_rec->h, lambda_bytes * 2);

  free(keys);
  free(s);
  return true;
}

// Implements bavc reconstruct faest em.
static bool bavc_reconstruct_faest_em(bavc_rec_t* bavc_rec, const uint8_t* decom_i,
                                      const uint16_t* i_delta, const uint8_t* iv,
                                      const faest_paramset_t* params) {

  const unsigned int lambda       = params->lambda;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = lambda_bytes * 2;

  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  assert(s);
  uint8_t* keys = calloc(2 * params->L - 1, lambda_bytes);
  assert(keys);

  if (!reconstruct_keys(s, keys, decom_i, i_delta, iv, params)) {
    free(keys);
    free(s);
    return false;
  }

  H1_context_t h1_com_ctx;
  H1_init(&h1_com_ctx, lambda);

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    H1_context_t h1_ctx;
    H1_init(&h1_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        H1_update(&h1_ctx, decom_i + i * com_size, com_size);
      } else {
        uint8_t com[2 * MAX_LAMBDA_BYTES];
        faest_em_leaf_commit(bavc_rec->s + offset * lambda_bytes, com, keys + alpha * lambda_bytes,
                             iv, i + L - 1, lambda);
        ++offset;
        H1_update(&h1_ctx, com, com_size);
      }
    }

    uint8_t hi[MAX_LAMBDA_BYTES * 2];
    H1_final(&h1_ctx, hi, lambda_bytes * 2);
    H1_update(&h1_com_ctx, hi, lambda_bytes * 2);
  }

  H1_final(&h1_com_ctx, bavc_rec->h, lambda_bytes * 2);

  free(keys);
  free(s);
  return true;
}

// Implements bavc reconstruct.
bool bavc_reconstruct(bavc_rec_t* bavc_rec, const uint8_t* decom_i, const uint16_t* i_delta,
                      const uint8_t* iv, const faest_paramset_t* params) {
  return faest_is_em(params) ? bavc_reconstruct_faest_em(bavc_rec, decom_i, i_delta, iv, params)
                             : bavc_reconstruct_faest(bavc_rec, decom_i, i_delta, iv, params);
}

// Implements bavc clear.
void bavc_clear(bavc_t* com) {
  free(com->sd);
  free(com->com);
  free(com->h);
  free(com->k);
}
