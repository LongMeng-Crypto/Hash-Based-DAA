/* SPDX-License-Identifier: MIT */
#ifndef DAA_ISSUER_ANCHOR_RELATION_HPP
#define DAA_ISSUER_ANCHOR_RELATION_HPP

#include "backend/binary_circuit.hpp"
#include "backend/security_parameters.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace daa::issuer_anchor {

enum class Kind : std::uint8_t { Sphincs = 1, FSphincs = 3 };

class Relation {
public:
  // Builds one SPHINCS+ or F-SPHINCS+ seed-anchor circuit.
  Relation(vole_backend::SecurityLevel level, Kind kind);

  // Returns the VOLEith security level used by this relation.
  vole_backend::SecurityLevel level() const { return level_; }
  // Returns the credential scheme encoded by this relation.
  Kind kind() const { return kind_; }
  // Returns the private master-seed (SPHINCS+) or root-seed (F-SPHINCS+) length.
  std::size_t seed_bytes() const;
  // Returns one anchor at 128 bits, two at 192/256 bits (SPHINCS+ always two).
  std::size_t anchors() const;
  // Returns the first public-input field length.
  std::size_t public_a_bytes() const;
  // Returns the second public-input field length.
  std::size_t public_b_bytes() const;
  // Returns the combined public anchor endpoint length.
  std::size_t anchor_bytes() const;
  // Returns the secret-dependent SHA-256 compression count.
  std::size_t compression_blocks() const;
  // Exposes the immutable binary circuit to the proof backend.
  const vole_backend::BinaryCircuit& binary_circuit() const { return circuit_; }

  // Converts the private seed to the backend bit representation.
  std::vector<std::uint8_t> private_bits(
      std::span<const std::uint8_t> seed) const;
  // Converts both public fields to the backend bit representation.
  std::vector<std::uint8_t> public_bits(
      std::span<const std::uint8_t> public_a,
      std::span<const std::uint8_t> public_b) const;
  // Converts the public anchor endpoints to circuit output bits.
  std::vector<std::uint8_t> output_bits(
      std::span<const std::uint8_t> anchor_value) const;

private:
  vole_backend::SecurityLevel level_;
  Kind kind_;
  vole_backend::BinaryCircuit circuit_;
};

} // namespace daa::issuer_anchor

#endif
