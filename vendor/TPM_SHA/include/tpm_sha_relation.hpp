/* SPDX-License-Identifier: MIT */
#ifndef DAA_TPM_SHA_RELATION_HPP
#define DAA_TPM_SHA_RELATION_HPP

#include "backend/binary_circuit.hpp"
#include "backend/security_parameters.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace daa::tpm_sha {

enum class RelationKind : std::uint8_t { Join, OursSign, Chen23Sign };

struct Evaluation {
  std::vector<std::uint8_t> slt;
  std::vector<std::uint8_t> sst;
  std::vector<std::uint8_t> et;
  std::vector<std::uint8_t> hk;
  std::vector<std::uint8_t> cet;
};

class Relation {
public:
  Relation(vole_backend::SecurityLevel level, RelationKind kind);

  vole_backend::SecurityLevel level() const { return level_; }
  RelationKind kind() const { return kind_; }
  std::size_t key_bytes() const;
  std::size_t digest_bytes() const;
  const vole_backend::BinaryCircuit& binary_circuit() const { return circuit_; }

  std::vector<std::uint8_t> private_bits(std::span<const std::uint8_t> sk,
                                         std::span<const std::uint8_t> s = {}) const;
  std::vector<std::uint8_t> public_bits(std::span<const std::uint8_t> lid,
                                        std::span<const std::uint8_t> gid,
                                        std::span<const std::uint8_t> sid = {}) const;
  std::vector<std::uint8_t> output_bits(std::span<const std::uint8_t> slt,
                                        std::span<const std::uint8_t> et,
                                        std::span<const std::uint8_t> hk,
                                        std::span<const std::uint8_t> cet = {}) const;
  Evaluation evaluate(std::span<const std::uint8_t> sk,
                      std::span<const std::uint8_t> s,
                      std::span<const std::uint8_t> lid,
                      std::span<const std::uint8_t> gid,
                      std::span<const std::uint8_t> sid = {}) const;

private:
  vole_backend::SecurityLevel level_;
  RelationKind kind_;
  vole_backend::BinaryCircuit circuit_;
  std::vector<vole_backend::Wire> sst_wires_;
  std::vector<vole_backend::Wire> et_wires_;
};

} // namespace daa::tpm_sha

#endif
