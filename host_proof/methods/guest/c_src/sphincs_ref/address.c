#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "utils.h"

// Sets layer addr.
void set_layer_addr(uint32_t addr[8], uint32_t layer)
{
    ((unsigned char *)addr)[SPX_OFFSET_LAYER] = (unsigned char)layer;
}

// Sets tree addr.
void set_tree_addr(uint32_t addr[8], uint64_t tree)
{
#if (SPX_TREE_HEIGHT * (SPX_D - 1)) > 64
    #error Subtree addressing is currently limited to at most 2^64 trees
#endif
    ull_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE], 8, tree );
}

// Sets type.
void set_type(uint32_t addr[8], uint32_t type)
{
    ((unsigned char *)addr)[SPX_OFFSET_TYPE] = (unsigned char)type;
}

// Implements copy subtree addr.
void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
    memcpy( out, in, SPX_OFFSET_TREE+8 );
}

// Sets keypair addr.
void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_KP_ADDR], keypair);
}

// Implements copy keypair addr.
void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
{
    memcpy( out, in, SPX_OFFSET_TREE+8 );
    memcpy( (unsigned char *)out + SPX_OFFSET_KP_ADDR, (unsigned char *)in + SPX_OFFSET_KP_ADDR, 4);
}

// Sets chain addr.
void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
    ((unsigned char *)addr)[SPX_OFFSET_CHAIN_ADDR] = (unsigned char)chain;
}

// Sets hash addr.
void set_hash_addr(uint32_t addr[8], uint32_t hash)
{
    ((unsigned char *)addr)[SPX_OFFSET_HASH_ADDR] = (unsigned char)hash;
}

// Sets tree height.
void set_tree_height(uint32_t addr[8], uint32_t tree_height)
{
    ((unsigned char *)addr)[SPX_OFFSET_TREE_HGT] = (unsigned char)tree_height;
}

// Sets tree index.
void set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE_INDEX], tree_index );
}
