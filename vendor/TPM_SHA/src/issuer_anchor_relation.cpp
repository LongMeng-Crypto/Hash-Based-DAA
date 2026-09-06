/* SPDX-License-Identifier: MIT */

#include "issuer_anchor_relation.hpp"

#include "circuits/sha256/sha256_core.hpp"

#include <stdexcept>
#include <string>

namespace daa::issuer_anchor {
namespace {

using Wire = vole_backend::Wire;
using FipsBits = std::vector<Wire>;

// Allocates bytes as FIPS-ordered public or private circuit inputs.
FipsBits allocate_bytes(vole_backend::BinaryCircuit& circuit,
                        std::size_t bytes, bool secret) {
  FipsBits result(bytes * 8);
  for (std::size_t byte = 0; byte != bytes; ++byte)
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit) {
      const auto fips_bit = 8 * byte + (7 - storage_bit);
      result[fips_bit] = secret ? circuit.private_input() : circuit.public_input();
    }
  return result;
}

// Converts one constant byte into FIPS-ordered circuit wires.
FipsBits constant_byte(std::uint8_t value) {
  FipsBits result;
  result.reserve(8);
  for (std::size_t bit = 0; bit != 8; ++bit)
    result.push_back(((value >> (7 - bit)) & 1U) != 0
                         ? vole_backend::BinaryCircuit::one()
                         : vole_backend::BinaryCircuit::zero());
  return result;
}

// Appends a wire span without changing its bit order.
void append(FipsBits& output, std::span<const Wire> input) {
  output.insert(output.end(), input.begin(), input.end());
}

// Appends one constant byte in FIPS bit order.
void append_constant(FipsBits& output, std::uint8_t value) {
  const auto bits = constant_byte(value);
  append(output, bits);
}

// Exposes the requested leading digest bytes as circuit outputs.
void add_truncated_outputs(vole_backend::BinaryCircuit& circuit,
                           std::span<const Wire> digest_fips_bits,
                           std::size_t bytes) {
  if (digest_fips_bits.size() != 256 || bytes > 32)
    throw std::logic_error("invalid anchor digest truncation");
  for (std::size_t byte = 0; byte != bytes; ++byte)
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit)
      circuit.add_output(digest_fips_bits[8 * byte + (7 - storage_bit)]);
}

// Converts protocol bytes into the backend's least-significant-bit storage order.
std::vector<std::uint8_t> bytes_to_bits(std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> result;
  result.reserve(bytes.size() * 8);
  for (const auto byte : bytes)
    for (std::size_t bit = 0; bit != 8; ++bit)
      result.push_back(static_cast<std::uint8_t>((byte >> bit) & 1U));
  return result;
}

// Rejects an input whose serialized length does not match the relation.
void require_size(std::span<const std::uint8_t> value, std::size_t expected,
                  const char* name) {
  if (value.size() != expected)
    throw std::invalid_argument(std::string(name) + " has wrong length");
}

} // namespace

// Builds the scheme-specific seed-anchor SHA-256 relation once.
Relation::Relation(vole_backend::SecurityLevel level, Kind kind)
    : level_(level), kind_(kind) {
  const auto seed = allocate_bytes(circuit_, seed_bytes(), true);
  const auto public_a = allocate_bytes(circuit_, public_a_bytes(), false);
  const auto public_b = allocate_bytes(circuit_, public_b_bytes(), false);

  if (kind_ == Kind::Sphincs) {
    for (std::size_t node = 0; node != 2; ++node) {
      FipsBits block;
      block.reserve(512);
      append(block, std::span<const Wire>(public_b).subspan(node * 22 * 8,
                                                           22 * 8));
      append(block, seed);
      append_constant(block, 0x80);
      while (block.size() < 56 * 8) append_constant(block, 0);
      const std::uint64_t bit_length =
          static_cast<std::uint64_t>(64 + 22 + seed_bytes()) * 8;
      for (int byte = 7; byte >= 0; --byte)
        append_constant(
            block, static_cast<std::uint8_t>(bit_length >> (8 * byte)));
      if (block.size() != 512)
        throw std::logic_error("SPHINCS+ PRF padding did not form one block");
      const auto digest = vole_circuits::sha2::build_sha256_compression(
          circuit_, public_a, block);
      add_truncated_outputs(circuit_, digest.fips_bits, seed_bytes());
    }
  } else {
    for (std::size_t node = 0; node != 2; ++node) {
      FipsBits first;
      first.reserve(512);
      append(first, seed);
      append(first, std::span<const Wire>(public_a).subspan(node * 32 * 8,
                                                            32 * 8));
      const auto node_seed = vole_circuits::sha2::build_sha256(circuit_, first);
      FipsBits second;
      second.reserve(512);
      append(second, node_seed.fips_bits);
      append(second, std::span<const Wire>(public_b).subspan(node * 32 * 8,
                                                             32 * 8));
      const auto anchor = vole_circuits::sha2::build_sha256(circuit_, second);
      add_truncated_outputs(circuit_, anchor.fips_bits, 32);
    }
  }

  std::string error;
  if (!circuit_.validate(&error))
    throw std::logic_error("invalid issuer-anchor circuit: " + error);
}

// Returns the private global-seed length for the selected credential scheme.
std::size_t Relation::seed_bytes() const {
  if (kind_ == Kind::FSphincs) return 32;
  return vole_backend::security_parameters(level_).lambda_bytes;
}

// Returns the first public-input field length.
std::size_t Relation::public_a_bytes() const {
  return kind_ == Kind::Sphincs ? 32 : 64;
}

// Returns the second public-input field length.
std::size_t Relation::public_b_bytes() const {
  return kind_ == Kind::Sphincs ? 44 : 64;
}

// Returns the public anchor output length.
std::size_t Relation::anchor_bytes() const {
  return kind_ == Kind::Sphincs ? 2 * seed_bytes() : 64;
}

// Reports the number of secret-dependent SHA-256 compression blocks.
std::size_t Relation::compression_blocks() const {
  return kind_ == Kind::Sphincs ? 2 : 8;
}

// Serializes the private seed into backend input bits.
std::vector<std::uint8_t> Relation::private_bits(
    std::span<const std::uint8_t> seed) const {
  require_size(seed, seed_bytes(), "seed");
  return bytes_to_bits(seed);
}

// Serializes both public relation fields into backend input bits.
std::vector<std::uint8_t> Relation::public_bits(
    std::span<const std::uint8_t> public_a,
    std::span<const std::uint8_t> public_b) const {
  require_size(public_a, public_a_bytes(), "public_a");
  require_size(public_b, public_b_bytes(), "public_b");
  auto result = bytes_to_bits(public_a);
  const auto b = bytes_to_bits(public_b);
  result.insert(result.end(), b.begin(), b.end());
  return result;
}

// Serializes the public anchor endpoints into circuit output bits.
std::vector<std::uint8_t> Relation::output_bits(
    std::span<const std::uint8_t> anchor_value) const {
  require_size(anchor_value, anchor_bytes(), "anchor_value");
  return bytes_to_bits(anchor_value);
}

} // namespace daa::issuer_anchor
