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

  std::vector<vole_backend::Wire> fips_bits;
};

Sha256DigestWires build_sha256(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> message_fips_bits,
    Sha256CoreStatistics* statistics = nullptr);

Sha256DigestWires build_sha256_compression(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> initial_state_fips_bits,
    std::span<const vole_backend::Wire> block_fips_bits,
    Sha256CoreStatistics* statistics = nullptr);

void add_sha256_digest_outputs(vole_backend::BinaryCircuit& circuit,
                               const Sha256DigestWires& digest);

}

#endif
