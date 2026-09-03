/* SPDX-License-Identifier: MIT */

#include "tpm_sha_relation.hpp"

#include "circuits/sha256/sha256_core.hpp"
#include "circuits/sha2/sha512_family.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace daa::tpm_sha {
namespace {

using Wire = vole_backend::Wire;
using FipsBits = std::vector<Wire>;

constexpr std::uint8_t tag_slt = 0x01;
constexpr std::uint8_t tag_et = 0x02;
constexpr std::uint8_t tag_hk = 0x03;
constexpr std::uint8_t tag_chen23_sst = 0x04;
constexpr std::uint8_t tag_chen23_hk = 0x05;
constexpr std::uint8_t tag_chen23_cet = 0x06;

FipsBits constant_byte(std::uint8_t value) {
  FipsBits result;
  result.reserve(8);
  for (unsigned int bit = 0; bit != 8; ++bit)
    result.push_back(((value >> (7U - bit)) & 1U) != 0
                         ? vole_backend::BinaryCircuit::one()
                         : vole_backend::BinaryCircuit::zero());
  return result;
}

FipsBits allocate_bytes(vole_backend::BinaryCircuit& circuit,
                        std::size_t bytes, bool secret) {
  FipsBits result(bytes * 8);
  for (std::size_t byte = 0; byte != bytes; ++byte) {
    // Allocate inputs in the backend's packed LSB-first order, while exposing
    // them to SHA in FIPS/MSB-first order.
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit) {
      const auto fips_bit = 8 * byte + (7 - storage_bit);
      result[fips_bit] = secret ? circuit.private_input() : circuit.public_input();
    }
  }
  return result;
}

void append(FipsBits& destination, std::span<const Wire> source) {
  destination.insert(destination.end(), source.begin(), source.end());
}

FipsBits tagged_message(std::uint8_t tag, std::span<const Wire> first,
                        std::span<const Wire> second) {
  auto result = constant_byte(tag);
  result.reserve(8 + first.size() + second.size());
  append(result, first);
  append(result, second);
  return result;
}

std::size_t digest_bytes_for(vole_backend::SecurityLevel level) {
  switch (level) {
  case vole_backend::SecurityLevel::Bits128: return 32;
  case vole_backend::SecurityLevel::Bits192: return 48;
  case vole_backend::SecurityLevel::Bits256: return 64;
  }
  throw std::invalid_argument("unsupported TPM SHA security level");
}

FipsBits hash(vole_backend::BinaryCircuit& circuit,
              vole_backend::SecurityLevel level,
              std::span<const Wire> message) {
  if (level == vole_backend::SecurityLevel::Bits128)
    return vole_circuits::sha2::build_sha256(circuit, message).fips_bits;
  const auto variant = level == vole_backend::SecurityLevel::Bits192
                           ? vole_circuits::sha2::Sha512Variant::Sha384
                           : vole_circuits::sha2::Sha512Variant::Sha512;
  return vole_circuits::sha2::build_sha512_family(circuit, message, variant).fips_bits;
}

void add_digest_outputs(vole_backend::BinaryCircuit& circuit,
                        std::span<const Wire> digest_fips_bits) {
  if (digest_fips_bits.size() % 8 != 0)
    throw std::logic_error("TPM SHA digest is not byte aligned");
  for (std::size_t byte = 0; byte != digest_fips_bits.size() / 8; ++byte)
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit)
      circuit.add_output(digest_fips_bits[8 * byte + (7 - storage_bit)]);
}

std::vector<std::uint8_t> bytes_to_bits(std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> result;
  result.reserve(bytes.size() * 8);
  for (const auto byte : bytes)
    for (std::size_t bit = 0; bit != 8; ++bit)
      result.push_back(static_cast<std::uint8_t>((byte >> bit) & 1U));
  return result;
}

std::vector<std::uint8_t> bits_to_bytes(std::span<const std::uint8_t> bits) {
  if (bits.size() % 8 != 0) throw std::logic_error("TPM SHA output is not byte aligned");
  std::vector<std::uint8_t> result(bits.size() / 8, 0);
  for (std::size_t bit = 0; bit != bits.size(); ++bit)
    result[bit / 8] |= static_cast<std::uint8_t>(bits[bit] << (bit % 8));
  return result;
}

std::vector<std::uint8_t> wires_to_bytes(
    std::span<const Wire> wires, const vole_backend::Evaluation& evaluation) {
  std::vector<std::uint8_t> result((wires.size() + 7) / 8, 0);
  // wires are in FIPS order while output bytes are ordinary byte strings.
  for (std::size_t fips_bit = 0; fips_bit != wires.size(); ++fips_bit) {
    if (evaluation.wires[wires[fips_bit]])
      result[fips_bit / 8] |= static_cast<std::uint8_t>(1U << (7 - (fips_bit % 8)));
  }
  return result;
}

void require_size(std::span<const std::uint8_t> value, std::size_t expected,
                  const char* name) {
  if (value.size() != expected)
    throw std::invalid_argument(std::string(name) + " has wrong length");
}

} // namespace

Relation::Relation(vole_backend::SecurityLevel level, RelationKind kind)
    : level_(level), kind_(kind) {
  const auto key_size = key_bytes();
  const auto digest_size = digest_bytes();
  const auto sk = allocate_bytes(circuit_, key_size, true);

  if (kind_ == RelationKind::Join) {
    const auto gid = allocate_bytes(circuit_, digest_size, false);
    et_wires_ = hash(circuit_, level_, tagged_message(tag_et, sk, gid));
    add_digest_outputs(circuit_, et_wires_);
  } else if (kind_ == RelationKind::OursSign) {
    const auto s = allocate_bytes(circuit_, key_size, true);
    const auto lid = allocate_bytes(circuit_, digest_size, false);
    const auto gid = allocate_bytes(circuit_, digest_size, false);
    const auto slt = hash(circuit_, level_, tagged_message(tag_slt, sk, lid));
    et_wires_ = hash(circuit_, level_, tagged_message(tag_et, sk, gid));
    const auto hk = hash(circuit_, level_, tagged_message(tag_hk, s, et_wires_));
    add_digest_outputs(circuit_, slt);
    add_digest_outputs(circuit_, hk);
  } else {
    const auto sid = allocate_bytes(circuit_, digest_size, false);
    const auto gid = allocate_bytes(circuit_, digest_size, false);
    const auto lid = allocate_bytes(circuit_, digest_size, false);
    const auto slt = hash(circuit_, level_, tagged_message(tag_slt, sk, lid));
    sst_wires_ =
        hash(circuit_, level_, tagged_message(tag_chen23_sst, sk, sid));
    et_wires_ = hash(circuit_, level_, tagged_message(tag_et, sk, gid));
    const auto hk = hash(
        circuit_, level_,
        tagged_message(tag_chen23_hk, sst_wires_, std::span<const Wire>{}));
    const auto cet = hash(
        circuit_, level_, tagged_message(tag_chen23_cet, sst_wires_, et_wires_));
    add_digest_outputs(circuit_, slt);
    add_digest_outputs(circuit_, hk);
    add_digest_outputs(circuit_, cet);
  }

  std::string error;
  if (!circuit_.validate(&error))
    throw std::logic_error("invalid TPM SHA circuit: " + error);
}

std::size_t Relation::key_bytes() const {
  return vole_backend::security_parameters(level_).lambda_bytes;
}

std::size_t Relation::digest_bytes() const { return digest_bytes_for(level_); }

std::vector<std::uint8_t> Relation::private_bits(
    std::span<const std::uint8_t> sk, std::span<const std::uint8_t> s) const {
  require_size(sk, key_bytes(), "sk");
  if (kind_ != RelationKind::OursSign) {
    if (!s.empty()) throw std::invalid_argument("relation does not accept s");
    return bytes_to_bits(sk);
  }
  require_size(s, key_bytes(), "s");
  auto result = bytes_to_bits(sk);
  const auto s_bits = bytes_to_bits(s);
  result.insert(result.end(), s_bits.begin(), s_bits.end());
  return result;
}

std::vector<std::uint8_t> Relation::public_bits(
    std::span<const std::uint8_t> lid, std::span<const std::uint8_t> gid,
    std::span<const std::uint8_t> sid) const {
  require_size(gid, digest_bytes(), "gid");
  if (kind_ == RelationKind::Join) {
    if (!lid.empty() || !sid.empty())
      throw std::invalid_argument("Join relation only accepts gid");
    return bytes_to_bits(gid);
  }
  require_size(lid, digest_bytes(), "lid");
  if (kind_ == RelationKind::Chen23Sign) {
    require_size(sid, digest_bytes(), "sid");
    auto result = bytes_to_bits(sid);
    const auto gid_bits = bytes_to_bits(gid);
    const auto lid_bits = bytes_to_bits(lid);
    result.insert(result.end(), gid_bits.begin(), gid_bits.end());
    result.insert(result.end(), lid_bits.begin(), lid_bits.end());
    return result;
  }
  if (!sid.empty()) throw std::invalid_argument("Ours-3H does not accept sid");
  auto result = bytes_to_bits(lid);
  const auto gid_bits = bytes_to_bits(gid);
  result.insert(result.end(), gid_bits.begin(), gid_bits.end());
  return result;
}

std::vector<std::uint8_t> Relation::output_bits(
    std::span<const std::uint8_t> slt, std::span<const std::uint8_t> et,
    std::span<const std::uint8_t> hk,
    std::span<const std::uint8_t> cet) const {
  if (kind_ == RelationKind::Join) {
    if (!slt.empty() || !hk.empty() || !cet.empty())
      throw std::invalid_argument("Join relation only exposes et");
    require_size(et, digest_bytes(), "et");
    return bytes_to_bits(et);
  }
  if (!et.empty())
    throw std::invalid_argument("Sign relation keeps et internal");
  require_size(slt, digest_bytes(), "slt");
  require_size(hk, digest_bytes(), "hk");
  auto result = bytes_to_bits(slt);
  const auto hk_bits = bytes_to_bits(hk);
  result.insert(result.end(), hk_bits.begin(), hk_bits.end());
  if (kind_ == RelationKind::Chen23Sign) {
    require_size(cet, digest_bytes(), "cet");
    const auto cet_bits = bytes_to_bits(cet);
    result.insert(result.end(), cet_bits.begin(), cet_bits.end());
  } else if (!cet.empty()) {
    throw std::invalid_argument("Ours-3H does not expose cet");
  }
  return result;
}

Evaluation Relation::evaluate(std::span<const std::uint8_t> sk,
                              std::span<const std::uint8_t> s,
                              std::span<const std::uint8_t> lid,
                              std::span<const std::uint8_t> gid,
                              std::span<const std::uint8_t> sid) const {
  const auto evaluation =
      circuit_.evaluate(private_bits(sk, s), public_bits(lid, gid, sid));
  Evaluation result;
  result.et = wires_to_bytes(et_wires_, evaluation);
  if (!sst_wires_.empty())
    result.sst = wires_to_bytes(sst_wires_, evaluation);
  const auto outputs = bits_to_bytes(evaluation.outputs);
  if (kind_ == RelationKind::Join) {
    if (outputs != result.et) throw std::logic_error("Join et output wiring mismatch");
  } else if (kind_ == RelationKind::OursSign) {
    result.slt.assign(outputs.begin(), outputs.begin() + static_cast<std::ptrdiff_t>(digest_bytes()));
    result.hk.assign(outputs.begin() + static_cast<std::ptrdiff_t>(digest_bytes()), outputs.end());
  } else {
    const auto digest = static_cast<std::ptrdiff_t>(digest_bytes());
    result.slt.assign(outputs.begin(), outputs.begin() + digest);
    result.hk.assign(outputs.begin() + digest, outputs.begin() + 2 * digest);
    result.cet.assign(outputs.begin() + 2 * digest, outputs.end());
  }
  return result;
}

} // namespace daa::tpm_sha
