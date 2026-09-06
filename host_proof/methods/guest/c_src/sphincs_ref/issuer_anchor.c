#include "issuer_anchor.h"
#include "address.h"
#include "api.h"
#include "hash.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"
#include <stdlib.h>
#include <string.h>

/* Header: magic/version/kind, n,d,len,height, selection[2]:u16, leaf:u16,
 * tree:u64. Big endian integers; payload begins with two n-byte anchors. */
#define HEADER 26u
#define FORS 2u
static const uint8_t magic[7] = {'D', 'A', 'A', 'A', 'N', 'C', 5};
static size_t fors_bytes(void) {
  return HEADER + (2 * SPX_FORS_HEIGHT + SPX_FORS_TREES) * SPX_N +
         SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;
}
size_t sphincs_issuer_anchor_certificate_bytes(void) { return fors_bytes(); }
static void header(uint8_t *c, const unsigned selection[2], unsigned leaf,
                   uint64_t tree) {
  memcpy(c, magic, 7);
  c[7] = FORS;
  c[8] = SPX_N;
  c[9] = SPX_D;
  c[10] = SPX_WOTS_LEN;
  c[11] = SPX_TREE_HEIGHT;
  ull_to_bytes(c + 12, 2, selection[0]);
  ull_to_bytes(c + 14, 2, selection[1]);
  ull_to_bytes(c + 16, 2, leaf);
  ull_to_bytes(c + 18, 8, tree);
}
static int valid(const uint8_t *c, size_t len) {
  if (!c || len < HEADER || memcmp(c, magic, 7) || c[8] != SPX_N ||
      c[9] != SPX_D || c[10] != SPX_WOTS_LEN || c[11] != SPX_TREE_HEIGHT)
    return 0;
  unsigned selected0 = bytes_to_ull(c + 12, 2);
  unsigned selected1 = bytes_to_ull(c + 14, 2);
  unsigned leaf = bytes_to_ull(c + 16, 2);
  if (leaf >= (1u << SPX_TREE_HEIGHT))
    return 0;
  if (c[7] != FORS || len != fors_bytes() ||
      selected0 >= (1u << SPX_FORS_HEIGHT) ||
      selected1 >= (1u << SPX_FORS_HEIGHT))
    return 0;
#if SPX_FULL_HEIGHT - SPX_TREE_HEIGHT < 64
  uint64_t tree = bytes_to_ull(c + 18, 8);
  if (tree >> (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT))
    return 0;
#endif
  return 1;
}
/* Reconstruct an ordinary hypertree suffix, retaining only public work. */
static void suffix_root(uint8_t root[SPX_N], const uint8_t *sig, uint64_t tree,
                        uint32_t leaf_index, const spx_ctx *ctx) {
  uint32_t wa[8] = {0}, ta[8] = {0}, pa[8] = {0};
  uint8_t endpoints[SPX_WOTS_BYTES], leaf[SPX_N];
  set_type(wa, SPX_ADDR_TYPE_WOTS);
  set_type(ta, SPX_ADDR_TYPE_HASHTREE);
  set_type(pa, SPX_ADDR_TYPE_WOTSPK);
  for (unsigned layer = 0; layer < SPX_D; layer++) {
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
/* The first two FORS trees in one ordinary Setup signature always provide
 * two revealed secrets. The one-byte message is outside the credential domain.
 */
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
  uint8_t md[SPX_FORS_MSG_BYTES], leaf[SPX_N];
  uint64_t tree;
  uint32_t idx;
  hash_message(md, &tree, &idx, sig, pk, &message, 1, &ctx);
  uint32_t indices[SPX_FORS_TREES], fa[8] = {0};
  unsigned bit = 0;
  for (unsigned i = 0; i < SPX_FORS_TREES; i++) {
    indices[i] = 0;
    for (unsigned b = 0; b < SPX_FORS_HEIGHT; b++, bit++)
      indices[i] |= ((md[bit / 8] >> (bit % 8)) & 1u) << b;
  }
  unsigned selected[2] = {indices[0], indices[1]};
  header(c, selected, idx, tree);
  const uint8_t *p = sig + SPX_N;
  /* Two anchors, then their paths in tree order, then the remaining roots. */
  uint8_t *out = c + HEADER + 2 * SPX_N;
  for (unsigned r = 0; r < 2; r++) {
    memcpy(c + HEADER + r * SPX_N, p, SPX_N);
    p += SPX_N;
    memcpy(out, p, SPX_FORS_HEIGHT * SPX_N);
    out += SPX_FORS_HEIGHT * SPX_N;
    p += SPX_FORS_HEIGHT * SPX_N;
  }
  set_tree_addr(fa, tree);
  set_keypair_addr(fa, idx);
  set_type(fa, SPX_ADDR_TYPE_FORSTREE);
  for (unsigned i = 2; i < SPX_FORS_TREES; i++) {
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
  unsigned selected[2] = {bytes_to_ull(c + 12, 2), bytes_to_ull(c + 14, 2)};
  unsigned idx = bytes_to_ull(c + 16, 2);
  uint64_t tree = bytes_to_ull(c + 18, 8);
  uint8_t root[SPX_N], leaf[SPX_N];
  uint32_t addr[8] = {0}, pa[8] = {0};
  set_tree_addr(addr, tree);
  set_keypair_addr(addr, idx);
  uint8_t roots[SPX_FORS_TREES * SPX_N];
  set_type(addr, SPX_ADDR_TYPE_FORSTREE);
  const uint8_t *p = c + HEADER + 2 * SPX_N;
  for (unsigned r = 0; r < 2; r++) {
    unsigned offset = r * (1u << SPX_FORS_HEIGHT);
    set_tree_height(addr, 0);
    set_tree_index(addr, offset + selected[r]);
    thash(leaf, c + HEADER + r * SPX_N, 1, &ctx, addr);
    compute_root(roots + r * SPX_N, leaf, selected[r], offset, p,
                 SPX_FORS_HEIGHT, &ctx, addr);
    p += SPX_FORS_HEIGHT * SPX_N;
  }
  memcpy(roots + 2 * SPX_N, p, (SPX_FORS_TREES - 2) * SPX_N);
  p += (SPX_FORS_TREES - 2) * SPX_N;
  copy_keypair_addr(pa, addr);
  set_type(pa, SPX_ADDR_TYPE_FORSPK);
  thash(root, roots, SPX_FORS_TREES, &ctx, pa);
  suffix_root(root, p, tree, idx, &ctx);
  return memcmp(root, pk + SPX_N, SPX_N) == 0 ? 0 : -1;
}
/* Reconstruct the public PRF statement solely from the registered tuple. */
int sphincs_issuer_anchor_statement(uint8_t state[32], uint8_t address[44],
                                    uint8_t value[2 * SPX_N], const uint8_t *c,
                                    size_t len, const uint8_t *pk) {
  if (!state || !address || !value || sphincs_issuer_anchor_verify(c, len, pk))
    return -1;
  spx_ctx ctx;
  memcpy(ctx.pub_seed, pk, SPX_N);
  memset(ctx.sk_seed, 0, SPX_N);
  initialize_hash_function(&ctx);
  memcpy(state, ctx.state_seeded, 32);
  for (unsigned r = 0; r < 2; r++) {
    uint32_t a[8] = {0};
    unsigned selected = bytes_to_ull(c + 12 + 2 * r, 2);
    set_tree_addr(a, bytes_to_ull(c + 18, 8));
    set_keypair_addr(a, bytes_to_ull(c + 16, 2));
    set_type(a, SPX_ADDR_TYPE_FORSPRF);
    set_tree_height(a, 0);
    set_tree_index(a, r * (1u << SPX_FORS_HEIGHT) + selected);
    memcpy(address + 22 * r, a, 22);
  }
  memcpy(value, c + HEADER, 2 * SPX_N);
  return 0;
}
int sphincs_issuer_anchor_relation(uint8_t seed[SPX_N], uint8_t state[32],
                                   uint8_t address[44],
                                   uint8_t value[2 * SPX_N], const uint8_t *c,
                                   size_t len, const uint8_t *pk,
                                   const uint8_t *sk) {
  if (!seed || !pk || !sk || memcmp(sk + 2 * SPX_N, pk, SPX_PK_BYTES) ||
      sphincs_issuer_anchor_statement(state, address, value, c, len, pk))
    return -1;
  spx_ctx ctx;
  memcpy(ctx.pub_seed, pk, SPX_N);
  memcpy(ctx.sk_seed, sk, SPX_N);
  initialize_hash_function(&ctx);
  for (unsigned r = 0; r < 2; r++) {
    uint32_t a[8] = {0};
    uint8_t expected[SPX_N];
    memcpy(a, address + 22 * r, 22);
    prf_addr(expected, &ctx, a);
    if (memcmp(expected, value + r * SPX_N, SPX_N))
      return -1;
  }
  memcpy(seed, sk, SPX_N);
  return 0;
}
