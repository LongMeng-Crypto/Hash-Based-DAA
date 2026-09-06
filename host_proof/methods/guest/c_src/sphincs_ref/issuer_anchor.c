#include "issuer_anchor.h"
#include "address.h"
#include "api.h"
#include "fors.h"
#include "hash.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"
#include <stdlib.h>
#include <string.h>

/* Header: magic/version/kind, n,d,len,height, selection:u16, leaf:u16,
 * tree:u64. All integers are big endian. Payload begins with the anchor. */
#define HEADER 24u
#define TOP 1u
#define FORS 2u
static const uint8_t magic[7] = {'D', 'A', 'A', 'A', 'N', 'C', 3};
static size_t top_bytes(void) {
  return HEADER + SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;
}
static size_t fors_bytes(void) {
  return HEADER + (SPX_FORS_HEIGHT + SPX_FORS_TREES) * SPX_N +
         SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;
}
size_t sphincs_issuer_anchor_certificate_bytes(void) { return fors_bytes(); }
static void header(uint8_t *c, unsigned kind, unsigned selection, unsigned leaf,
                   uint64_t tree) {
  memcpy(c, magic, 7);
  c[7] = kind;
  c[8] = SPX_N;
  c[9] = SPX_D;
  c[10] = SPX_WOTS_LEN;
  c[11] = SPX_TREE_HEIGHT;
  ull_to_bytes(c + 12, 2, selection);
  ull_to_bytes(c + 14, 2, leaf);
  ull_to_bytes(c + 16, 8, tree);
}
static int valid(const uint8_t *c, size_t len) {
  if (!c || len < HEADER || memcmp(c, magic, 7) || c[8] != SPX_N ||
      c[9] != SPX_D || c[10] != SPX_WOTS_LEN || c[11] != SPX_TREE_HEIGHT)
    return 0;
  unsigned selected = bytes_to_ull(c + 12, 2), leaf = bytes_to_ull(c + 14, 2);
  uint64_t tree = bytes_to_ull(c + 16, 8);
  if (leaf >= (1u << SPX_TREE_HEIGHT))
    return 0;
  if (c[7] == TOP)
    return len == top_bytes() && tree == 0 && selected < SPX_WOTS_LEN;
  if (c[7] != FORS || len != fors_bytes() ||
      selected >= (1u << SPX_FORS_HEIGHT))
    return 0;
#if SPX_FULL_HEIGHT - SPX_TREE_HEIGHT < 64
  if (tree >> (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT))
    return 0;
#endif
  return 1;
}
/* Reconstruct an ordinary hypertree suffix, retaining only public work. */
static void suffix_root(uint8_t root[SPX_N], const uint8_t *sig, uint64_t tree,
                        uint32_t leaf_index, unsigned first_layer,
                        const spx_ctx *ctx) {
  uint32_t wa[8] = {0}, ta[8] = {0}, pa[8] = {0};
  uint8_t endpoints[SPX_WOTS_BYTES], leaf[SPX_N];
  set_type(wa, SPX_ADDR_TYPE_WOTS);
  set_type(ta, SPX_ADDR_TYPE_HASHTREE);
  set_type(pa, SPX_ADDR_TYPE_WOTSPK);
  for (unsigned layer = first_layer; layer < SPX_D; layer++) {
    set_layer_addr(ta, layer);
    set_tree_addr(ta, tree);
    copy_subtree_addr(wa, ta);
    set_keypair_addr(wa, leaf_index);
    copy_keypair_addr(pa, wa);
    wots_pk_from_sig(endpoints, sig, root, ctx, wa);
    sig += SPX_WOTS_BYTES;
    thash(leaf, endpoints, SPX_WOTS_LEN, ctx, pa);
    compute_root(root, leaf, leaf_index, 0, sig, SPX_TREE_HEIGHT, ctx, ta);
    sig += SPX_TREE_HEIGHT * SPX_N;
    leaf_index = tree & ((1u << SPX_TREE_HEIGHT) - 1);
    tree >>= SPX_TREE_HEIGHT;
  }
}
/* Select a zero digit from the normal top signature, otherwise a FORS secret.
 * The one-byte Setup message is outside the fixed-length credential domain. */
int sphincs_issuer_anchor_generate(uint8_t *c, size_t *len, const uint8_t *pk,
                                   const uint8_t *sk) {
  if (!c || !len || !pk || !sk || *len < fors_bytes() ||
      memcmp(sk + 2 * SPX_N, pk, SPX_PK_BYTES))
    return -1;
  uint8_t *sig = malloc(SPX_BYTES);
  if (!sig)
    return -1;
  size_t slen;
  const uint8_t message = 0x49;
  int result = crypto_sign_signature(sig, &slen, &message, 1, sk);
  if (!result)
    result = sphincs_issuer_anchor_from_signature(c, len, pk, sig, slen);
  free(sig);
  return result;
}
/* This public projection is also the certificate simulator used in the
 * reduction. */
int sphincs_issuer_anchor_from_signature(uint8_t *c, size_t *len,
                                         const uint8_t *pk, const uint8_t *sig,
                                         size_t slen) {
  const uint8_t message = 0x49;
  if (!c || !len || !pk || !sig || *len < fors_bytes() ||
      crypto_sign_verify(sig, slen, &message, 1, pk))
    return -1;
  spx_ctx ctx;
  memcpy(ctx.pub_seed, pk, SPX_N);
  memset(ctx.sk_seed, 0, SPX_N);
  initialize_hash_function(&ctx);
  uint8_t md[SPX_FORS_MSG_BYTES], root[SPX_N], endpoints[SPX_WOTS_BYTES],
      leaf[SPX_N];
  uint64_t tree, original_tree;
  uint32_t idx, original_idx, wa[8] = {0}, ta[8] = {0}, pa[8] = {0};
  hash_message(md, &tree, &idx, sig, pk, &message, 1, &ctx);
  original_tree = tree;
  original_idx = idx;
  set_type(wa, SPX_ADDR_TYPE_WOTS);
  set_type(ta, SPX_ADDR_TYPE_HASHTREE);
  set_type(pa, SPX_ADDR_TYPE_WOTSPK);
  set_tree_addr(wa, tree);
  set_keypair_addr(wa, idx);
  fors_pk_from_sig(root, sig + SPX_N, md, &ctx, wa);
  const uint8_t *p = sig + SPX_N + SPX_FORS_BYTES;
  for (unsigned layer = 0; layer < SPX_D; layer++) {
    set_layer_addr(ta, layer);
    set_tree_addr(ta, tree);
    copy_subtree_addr(wa, ta);
    set_keypair_addr(wa, idx);
    copy_keypair_addr(pa, wa);
    unsigned digits[SPX_WOTS_LEN];
    chain_lengths(digits, root);
    wots_pk_from_sig(endpoints, p, root, &ctx, wa);
    if (layer == SPX_D - 1) {
      unsigned j = 0;
      while (j < SPX_WOTS_LEN && digits[j])
        j++;
#ifdef DAA_ANCHOR_TEST_FORS
      j = SPX_WOTS_LEN;
#endif
      if (j < SPX_WOTS_LEN) {
        header(c, TOP, j, idx, 0);
        memcpy(c + HEADER, p + j * SPX_N, SPX_N);
        uint8_t *out = c + HEADER + SPX_N;
        for (unsigned i = 0; i < SPX_WOTS_LEN; i++)
          if (i != j) {
            memcpy(out, endpoints + i * SPX_N, SPX_N);
            out += SPX_N;
          }
        memcpy(out, p + SPX_WOTS_BYTES, SPX_TREE_HEIGHT * SPX_N);
        *len = top_bytes();
        return 0;
      }
    }
    thash(leaf, endpoints, SPX_WOTS_LEN, &ctx, pa);
    p += SPX_WOTS_BYTES;
    compute_root(root, leaf, idx, 0, p, SPX_TREE_HEIGHT, &ctx, ta);
    p += SPX_TREE_HEIGHT * SPX_N;
    idx = tree & ((1u << SPX_TREE_HEIGHT) - 1);
    tree >>= SPX_TREE_HEIGHT;
  }
  uint32_t indices[SPX_FORS_TREES], fa[8] = {0};
  unsigned bit = 0;
  for (unsigned i = 0; i < SPX_FORS_TREES; i++) {
    indices[i] = 0;
    for (unsigned b = 0; b < SPX_FORS_HEIGHT; b++, bit++)
      indices[i] |= ((md[bit / 8] >> (bit % 8)) & 1u) << b;
  }
  header(c, FORS, indices[0], original_idx, original_tree);
  p = sig + SPX_N;
  memcpy(c + HEADER, p, (1 + SPX_FORS_HEIGHT) * SPX_N);
  uint8_t *out = c + HEADER + (1 + SPX_FORS_HEIGHT) * SPX_N;
  set_tree_addr(fa, original_tree);
  set_keypair_addr(fa, original_idx);
  set_type(fa, SPX_ADDR_TYPE_FORSTREE);
  p += (1 + SPX_FORS_HEIGHT) * SPX_N;
  for (unsigned i = 1; i < SPX_FORS_TREES; i++) {
    unsigned offset = i * (1u << SPX_FORS_HEIGHT);
    set_tree_height(fa, 0);
    set_tree_index(fa, offset + indices[i]);
    thash(leaf, p, 1, &ctx, fa);
    p += SPX_N;
    compute_root(out, leaf, indices[i], offset, p, SPX_FORS_HEIGHT, &ctx, fa);
    out += SPX_N;
    p += SPX_FORS_HEIGHT * SPX_N;
  }
  memcpy(out, p, SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
  *len = fors_bytes();
  return 0;
}
int sphincs_issuer_anchor_verify(const uint8_t *c, size_t len,
                                 const uint8_t *pk) {
  if (!pk || !valid(c, len))
    return -1;
  spx_ctx ctx;
  memcpy(ctx.pub_seed, pk, SPX_N);
  memset(ctx.sk_seed, 0, SPX_N);
  initialize_hash_function(&ctx);
  unsigned j = bytes_to_ull(c + 12, 2), idx = bytes_to_ull(c + 14, 2);
  uint64_t tree = bytes_to_ull(c + 16, 8);
  uint8_t root[SPX_N], leaf[SPX_N];
  uint32_t addr[8] = {0}, pa[8] = {0};
  set_tree_addr(addr, tree);
  set_keypair_addr(addr, idx);
  if (c[7] == TOP) {
    uint8_t endpoints[SPX_WOTS_BYTES];
    const uint8_t *p = c + HEADER + SPX_N;
    set_layer_addr(addr, SPX_D - 1);
    set_type(addr, SPX_ADDR_TYPE_WOTS);
    set_chain_addr(addr, j);
    memcpy(endpoints + j * SPX_N, c + HEADER, SPX_N);
    for (unsigned step = 0; step < SPX_WOTS_W - 1; step++) {
      set_hash_addr(addr, step);
      thash(endpoints + j * SPX_N, endpoints + j * SPX_N, 1, &ctx, addr);
    }
    for (unsigned i = 0; i < SPX_WOTS_LEN; i++)
      if (i != j) {
        memcpy(endpoints + i * SPX_N, p, SPX_N);
        p += SPX_N;
      }
    copy_keypair_addr(pa, addr);
    set_type(pa, SPX_ADDR_TYPE_WOTSPK);
    thash(leaf, endpoints, SPX_WOTS_LEN, &ctx, pa);
    uint32_t ta[8] = {0};
    set_layer_addr(ta, SPX_D - 1);
    set_type(ta, SPX_ADDR_TYPE_HASHTREE);
    compute_root(root, leaf, idx, 0, p, SPX_TREE_HEIGHT, &ctx, ta);
  } else {
    uint8_t roots[SPX_FORS_TREES * SPX_N];
    set_type(addr, SPX_ADDR_TYPE_FORSTREE);
    set_tree_height(addr, 0);
    set_tree_index(addr, j);
    thash(leaf, c + HEADER, 1, &ctx, addr);
    compute_root(roots, leaf, j, 0, c + HEADER + SPX_N, SPX_FORS_HEIGHT, &ctx,
                 addr);
    const uint8_t *p = c + HEADER + (1 + SPX_FORS_HEIGHT) * SPX_N;
    memcpy(roots + SPX_N, p, (SPX_FORS_TREES - 1) * SPX_N);
    p += (SPX_FORS_TREES - 1) * SPX_N;
    copy_keypair_addr(pa, addr);
    set_type(pa, SPX_ADDR_TYPE_FORSPK);
    thash(root, roots, SPX_FORS_TREES, &ctx, pa);
    suffix_root(root, p, tree, idx, 0, &ctx);
  }
  return memcmp(root, pk + SPX_N, SPX_N) == 0 ? 0 : -1;
}
/* Reconstruct the public PRF statement solely from the registered tuple. */
int sphincs_issuer_anchor_statement(uint8_t state[32], uint8_t address[22],
                                    uint8_t value[SPX_N], const uint8_t *c,
                                    size_t len, const uint8_t *pk) {
  if (!state || !address || !value || sphincs_issuer_anchor_verify(c, len, pk))
    return -1;
  spx_ctx ctx;
  memcpy(ctx.pub_seed, pk, SPX_N);
  memset(ctx.sk_seed, 0, SPX_N);
  initialize_hash_function(&ctx);
  uint32_t a[8] = {0};
  set_tree_addr(a, bytes_to_ull(c + 16, 8));
  set_keypair_addr(a, bytes_to_ull(c + 14, 2));
  if (c[7] == TOP) {
    set_layer_addr(a, SPX_D - 1);
    set_type(a, SPX_ADDR_TYPE_WOTSPRF);
    set_chain_addr(a, bytes_to_ull(c + 12, 2));
    set_hash_addr(a, 0);
  } else {
    set_type(a, SPX_ADDR_TYPE_FORSPRF);
    set_tree_height(a, 0);
    set_tree_index(a, bytes_to_ull(c + 12, 2));
  }
  memcpy(state, ctx.state_seeded, 32);
  memcpy(address, a, 22);
  memcpy(value, c + HEADER, SPX_N);
  return 0;
}
int sphincs_issuer_anchor_relation(uint8_t seed[SPX_N], uint8_t state[32],
                                   uint8_t address[22], uint8_t value[SPX_N],
                                   const uint8_t *c, size_t len,
                                   const uint8_t *pk, const uint8_t *sk) {
  if (!seed || !pk || !sk || memcmp(sk + 2 * SPX_N, pk, SPX_PK_BYTES) ||
      sphincs_issuer_anchor_statement(state, address, value, c, len, pk))
    return -1;
  spx_ctx ctx;
  memcpy(ctx.pub_seed, pk, SPX_N);
  memcpy(ctx.sk_seed, sk, SPX_N);
  initialize_hash_function(&ctx);
  uint32_t a[8] = {0};
  uint8_t expected[SPX_N];
  memcpy(a, address, 22);
  prf_addr(expected, &ctx, a);
  if (memcmp(expected, value, SPX_N))
    return -1;
  memcpy(seed, sk, SPX_N);
  return 0;
}
