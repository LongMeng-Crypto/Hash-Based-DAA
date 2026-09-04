/* SPDX-License-Identifier: MIT */
#ifndef VOLE_CIRCUITS_SHA256_CORE_HPP
#define VOLE_CIRCUITS_SHA256_CORE_HPP

#include "backend/binary_circuit.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace vole_circuits::sha2 {

constexpr std::size_t sha256_core_max_message_bytes = 550;

struct Sha256CoreStatistics {
  std::size_t schedule_multiplications = 0;
  std::size_t round_multiplications = 0;
  std::size_t feed_forward_multiplications = 0;
};

struct Sha256DigestWires {
  // SHA/FIPS order: bit zero is the most-significant bit of byte zero.
  std::vector<vole_backend::Wire> fips_bits;
};

// Build SHA-256 over already allocated wires. This function neither allocates
// inputs nor registers public outputs, so an intermediate digest can be wired
// directly into another hash in the same relation.
Sha256DigestWires build_sha256(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> message_fips_bits,
    Sha256CoreStatistics* statistics = nullptr);

/* One SHA-256 compression with a caller-supplied public/constant chaining
 * value and one already-padded 64-byte block.  This is used by protocols that
 * precompute a public prefix (for example SPHINCS+ PK.seed) and prove only the
 * secret-dependent compression. */
Sha256DigestWires build_sha256_compression(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> initial_state_fips_bits,
    std::span<const vole_backend::Wire> block_fips_bits,
    Sha256CoreStatistics* statistics = nullptr);

void add_sha256_digest_outputs(vole_backend::BinaryCircuit& circuit,
                               const Sha256DigestWires& digest);

} // namespace vole_circuits::sha2

#endif
