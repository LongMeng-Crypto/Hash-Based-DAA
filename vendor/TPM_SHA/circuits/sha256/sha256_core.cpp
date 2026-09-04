/* SPDX-License-Identifier: MIT */

#include "sha256_core.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>

namespace vole_circuits::sha2 {
namespace {

using Wire = vole_backend::Wire;
using Word = std::array<Wire, 32>;

constexpr std::array<std::uint32_t, 8> initial_state = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

constexpr std::array<std::uint32_t, 64> round_constants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

class Builder {
public:
  explicit Builder(vole_backend::BinaryCircuit& circuit) : circuit_(circuit) {}

  Wire zero() const { return vole_backend::BinaryCircuit::zero(); }
  Wire one() const { return vole_backend::BinaryCircuit::one(); }
  Wire xor_(Wire a, Wire b) { return circuit_.xor_wire(a, b); }
  Wire and_(Wire a, Wire b) {
    const auto before = circuit_.nodes().size();
    const auto result = circuit_.and_wire(a, b);
    if (circuit_.nodes().size() != before) ++multiplications_;
    return result;
  }
  std::size_t multiplications() const { return multiplications_; }

  Word constant_word(std::uint32_t value) const {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = ((value >> bit) & 1U) != 0 ? one() : zero();
    return out;
  }
  Word xor_word(const Word& a, const Word& b) {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = xor_(a[bit], b[bit]);
    return out;
  }
  Word xor_word(const Word& a, const Word& b, const Word& c) {
    return xor_word(xor_word(a, b), c);
  }
  Word rotr(const Word& value, std::size_t amount) const {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = value[(bit + amount) % value.size()];
    return out;
  }
  Word shr(const Word& value, std::size_t amount) const {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = bit + amount < value.size() ? value[bit + amount] : zero();
    return out;
  }
  Word add(const Word& a, const Word& b) {
    Word sum{};
    Wire carry = zero();
    for (std::size_t bit = 0; bit != sum.size(); ++bit) {
      const auto propagate = xor_(a[bit], b[bit]);
      sum[bit] = xor_(propagate, carry);
      if (bit + 1 != sum.size())
        carry = xor_(a[bit], and_(propagate, xor_(a[bit], carry)));
    }
    return sum;
  }
  Word choice(const Word& x, const Word& y, const Word& z) {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = xor_(z[bit], and_(x[bit], xor_(y[bit], z[bit])));
    return out;
  }
  Word majority(const Word& x, const Word& y, const Word& z) {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = xor_(x[bit], and_(xor_(x[bit], y[bit]), xor_(x[bit], z[bit])));
    return out;
  }
  Word big_sigma0(const Word& x) { return xor_word(rotr(x, 2), rotr(x, 13), rotr(x, 22)); }
  Word big_sigma1(const Word& x) { return xor_word(rotr(x, 6), rotr(x, 11), rotr(x, 25)); }
  Word small_sigma0(const Word& x) { return xor_word(rotr(x, 7), rotr(x, 18), shr(x, 3)); }
  Word small_sigma1(const Word& x) { return xor_word(rotr(x, 17), rotr(x, 19), shr(x, 10)); }

private:
  vole_backend::BinaryCircuit& circuit_;
  std::size_t multiplications_ = 0;
};

} // namespace

Sha256DigestWires build_sha256(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> message_fips_bits,
    Sha256CoreStatistics* statistics) {
  if (message_fips_bits.size() > sha256_core_max_message_bytes * 8)
    throw std::invalid_argument("SHA-256 message exceeds circuit limit");
  if (std::any_of(message_fips_bits.begin(), message_fips_bits.end(),
                  [&circuit](Wire wire) { return wire >= circuit.nodes().size(); }))
    throw std::invalid_argument("SHA-256 message wire is out of range");

  Builder b(circuit);
  Sha256CoreStatistics local{};
  const auto block_count = (message_fips_bits.size() + 1 + 64 + 511) / 512;
  std::vector<Wire> padded(block_count * 512, b.zero());
  std::copy(message_fips_bits.begin(), message_fips_bits.end(), padded.begin());
  padded[message_fips_bits.size()] = b.one();
  const auto bit_length = static_cast<std::uint64_t>(message_fips_bits.size());
  for (std::size_t bit = 0; bit != 64; ++bit)
    padded[padded.size() - 1 - bit] = ((bit_length >> bit) & 1U) ? b.one() : b.zero();

  std::array<Word, 8> chaining{};
  for (std::size_t word = 0; word != chaining.size(); ++word)
    chaining[word] = b.constant_word(initial_state[word]);

  for (std::size_t block = 0; block != block_count; ++block) {
    const auto schedule_before = b.multiplications();
    std::array<Word, 64> schedule{};
    for (std::size_t word = 0; word != 16; ++word)
      for (std::size_t fips_bit = 0; fips_bit != 32; ++fips_bit)
        schedule[word][31 - fips_bit] = padded[block * 512 + word * 32 + fips_bit];
    for (std::size_t round = 16; round != schedule.size(); ++round) {
      auto value = b.add(b.small_sigma1(schedule[round - 2]), schedule[round - 7]);
      value = b.add(value, b.small_sigma0(schedule[round - 15]));
      schedule[round] = b.add(value, schedule[round - 16]);
    }
    local.schedule_multiplications += b.multiplications() - schedule_before;

    const auto rounds_before = b.multiplications();
    auto state = chaining;
    for (std::size_t round = 0; round != schedule.size(); ++round) {
      auto t1 = b.add(state[7], b.big_sigma1(state[4]));
      t1 = b.add(t1, b.choice(state[4], state[5], state[6]));
      t1 = b.add(t1, schedule[round]);
      t1 = b.add(t1, b.constant_word(round_constants[round]));
      const auto t2 = b.add(b.big_sigma0(state[0]),
                            b.majority(state[0], state[1], state[2]));
      const auto new_a = b.add(t1, t2);
      const auto new_e = b.add(state[3], t1);
      state = {new_a, state[0], state[1], state[2], new_e, state[4], state[5], state[6]};
    }
    local.round_multiplications += b.multiplications() - rounds_before;

    const auto feed_before = b.multiplications();
    for (std::size_t word = 0; word != state.size(); ++word)
      state[word] = b.add(state[word], chaining[word]);
    local.feed_forward_multiplications += b.multiplications() - feed_before;
    chaining = state;
  }

  Sha256DigestWires digest;
  digest.fips_bits.reserve(256);
  for (const auto& word : chaining)
    for (std::size_t fips_bit = 0; fips_bit != 32; ++fips_bit)
      digest.fips_bits.push_back(word[31 - fips_bit]);
  if (statistics != nullptr) *statistics = local;
  return digest;
}

Sha256DigestWires build_sha256_compression(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> initial_state_fips_bits,
    std::span<const vole_backend::Wire> block_fips_bits,
    Sha256CoreStatistics* statistics) {
  if (initial_state_fips_bits.size() != 256)
    throw std::invalid_argument("SHA-256 initial state must contain 256 bits");
  if (block_fips_bits.size() != 512)
    throw std::invalid_argument("SHA-256 compression block must contain 512 bits");
  const auto valid_wire = [&circuit](Wire wire) {
    return wire < circuit.nodes().size();
  };
  if (!std::all_of(initial_state_fips_bits.begin(), initial_state_fips_bits.end(),
                   valid_wire) ||
      !std::all_of(block_fips_bits.begin(), block_fips_bits.end(), valid_wire))
    throw std::invalid_argument("SHA-256 compression wire is out of range");

  Builder b(circuit);
  Sha256CoreStatistics local{};
  std::array<Word, 8> chaining{};
  for (std::size_t word = 0; word != chaining.size(); ++word)
    for (std::size_t fips_bit = 0; fips_bit != 32; ++fips_bit)
      chaining[word][31 - fips_bit] =
          initial_state_fips_bits[word * 32 + fips_bit];

  const auto schedule_before = b.multiplications();
  std::array<Word, 64> schedule{};
  for (std::size_t word = 0; word != 16; ++word)
    for (std::size_t fips_bit = 0; fips_bit != 32; ++fips_bit)
      schedule[word][31 - fips_bit] = block_fips_bits[word * 32 + fips_bit];
  for (std::size_t round = 16; round != schedule.size(); ++round) {
    auto value = b.add(b.small_sigma1(schedule[round - 2]), schedule[round - 7]);
    value = b.add(value, b.small_sigma0(schedule[round - 15]));
    schedule[round] = b.add(value, schedule[round - 16]);
  }
  local.schedule_multiplications = b.multiplications() - schedule_before;

  const auto rounds_before = b.multiplications();
  auto state = chaining;
  for (std::size_t round = 0; round != schedule.size(); ++round) {
    auto t1 = b.add(state[7], b.big_sigma1(state[4]));
    t1 = b.add(t1, b.choice(state[4], state[5], state[6]));
    t1 = b.add(t1, schedule[round]);
    t1 = b.add(t1, b.constant_word(round_constants[round]));
    const auto t2 = b.add(b.big_sigma0(state[0]),
                          b.majority(state[0], state[1], state[2]));
    const auto new_a = b.add(t1, t2);
    const auto new_e = b.add(state[3], t1);
    state = {new_a, state[0], state[1], state[2],
             new_e, state[4], state[5], state[6]};
  }
  local.round_multiplications = b.multiplications() - rounds_before;

  const auto feed_before = b.multiplications();
  for (std::size_t word = 0; word != state.size(); ++word)
    state[word] = b.add(state[word], chaining[word]);
  local.feed_forward_multiplications = b.multiplications() - feed_before;

  Sha256DigestWires digest;
  digest.fips_bits.reserve(256);
  for (const auto& word : state)
    for (std::size_t fips_bit = 0; fips_bit != 32; ++fips_bit)
      digest.fips_bits.push_back(word[31 - fips_bit]);
  if (statistics != nullptr) *statistics = local;
  return digest;
}

void add_sha256_digest_outputs(vole_backend::BinaryCircuit& circuit,
                               const Sha256DigestWires& digest) {
  if (digest.fips_bits.size() != 256)
    throw std::invalid_argument("SHA-256 digest has wrong wire count");
  for (std::size_t byte = 0; byte != 32; ++byte)
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit)
      circuit.add_output(digest.fips_bits[8 * byte + (7 - storage_bit)]);
}

} // namespace vole_circuits::sha2
