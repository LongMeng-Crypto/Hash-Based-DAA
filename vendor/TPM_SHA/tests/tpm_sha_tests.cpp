/* SPDX-License-Identifier: MIT */

#include "tpm_sha.h"

extern "C" {
#include "aes.h"
#include "fields.h"
#include "instances.h"
#include "vole.h"
}

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

void check(bool condition, std::string_view message) {
  if (!condition) throw std::runtime_error(std::string(message));
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string result;
  result.reserve(2 * bytes.size());
  for (const auto byte : bytes) {
    result.push_back(hex[byte >> 4]);
    result.push_back(hex[byte & 15]);
  }
  return result;
}

std::vector<std::uint8_t> reference_hash(
    daa_tpm_sha_level level, std::span<const std::uint8_t> message) {
  const EVP_MD* md = nullptr;
  switch (level) {
  case DAA_TPM_SHA_128: md = EVP_sha256(); break;
  case DAA_TPM_SHA_192: md = EVP_sha384(); break;
  case DAA_TPM_SHA_256: md = EVP_sha512(); break;
  }
  check(md != nullptr, "unsupported reference digest");
  std::vector<std::uint8_t> result(static_cast<std::size_t>(EVP_MD_get_size(md)));
  unsigned int length = 0;
  check(EVP_Digest(message.data(), message.size(), result.data(), &length, md,
                   nullptr) == 1,
        "EVP_Digest failed");
  check(length == result.size(), "reference digest length mismatch");
  return result;
}

std::vector<std::uint8_t> tagged(std::uint8_t tag,
                                 std::span<const std::uint8_t> first,
                                 std::span<const std::uint8_t> second) {
  std::vector<std::uint8_t> message{tag};
  message.insert(message.end(), first.begin(), first.end());
  message.insert(message.end(), second.begin(), second.end());
  return message;
}

void run_level(daa_tpm_sha_level level, daa_tpm_sha_profile profile) {
  const auto key_bytes = daa_tpm_sha_key_bytes(level);
  const auto digest_bytes = daa_tpm_sha_digest_bytes(level);
  check(key_bytes != 0 && digest_bytes == 2 * key_bytes, "invalid API lengths");

  std::vector<std::uint8_t> sk(key_bytes), s(key_bytes), lid(digest_bytes),
      gid(digest_bytes), slt(digest_bytes), et(digest_bytes), hk(digest_bytes);
  for (std::size_t i = 0; i != key_bytes; ++i) {
    sk[i] = static_cast<std::uint8_t>(0x10 + i);
    s[i] = static_cast<std::uint8_t>(0x80 + i);
  }
  for (std::size_t i = 0; i != digest_bytes; ++i) {
    lid[i] = static_cast<std::uint8_t>(0x20 + 3 * i);
    gid[i] = static_cast<std::uint8_t>(0xe0 - i);
  }

  check(daa_tpm_sha_prepare(level, profile) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(daa_tpm_sha_evaluate_sign(
            level, sk.data(), sk.size(), s.data(), s.size(), lid.data(),
            lid.size(), gid.data(), gid.size(), slt.data(), slt.size(),
            et.data(), et.size(), hk.data(), hk.size()) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());

  check(slt == reference_hash(level, tagged(0x01, sk, lid)),
        "slt reference mismatch");
  check(et == reference_hash(level, tagged(0x02, sk, gid)),
        "et reference mismatch");
  check(hk == reference_hash(level, tagged(0x03, s, et)),
        "hk reference mismatch");

  std::vector<std::uint8_t> join_et(digest_bytes);
  check(daa_tpm_sha_evaluate_join(level, sk.data(), sk.size(), gid.data(),
                                  gid.size(), join_et.data(), join_et.size()) ==
            DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(join_et == et, "Join and signing et disagree");

  daa_tpm_sha_stats join_stats{}, sign_stats{};
  check(daa_tpm_sha_join_stats(level, profile, &join_stats) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(daa_tpm_sha_sign_stats(level, profile, &sign_stats) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(join_stats.private_input_bits == key_bytes * 8,
        "Join private input count mismatch");
  check(join_stats.public_input_bits == digest_bytes * 8,
        "Join public input count mismatch");
  check(join_stats.output_bits == digest_bytes * 8,
        "Join output count mismatch");
  check(sign_stats.private_input_bits == 2 * key_bytes * 8,
        "Sign private input count mismatch");
  check(sign_stats.public_input_bits == 2 * digest_bytes * 8,
        "Sign public input count mismatch");
  check(sign_stats.output_bits == 2 * digest_bytes * 8,
        "Sign output count mismatch");

  const std::array<std::uint8_t, 13> join_context{
      'D','A','A','-','J','O','I','N','-','S','H','A','1'};
  const std::array<std::uint8_t, 13> sign_context{
      'D','A','A','-','S','I','G','N','-','S','H','A','1'};
  std::array<std::uint8_t, 32> randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i)
    randomness[i] = static_cast<std::uint8_t>(i + key_bytes);

  std::vector<std::uint8_t> join_proof(join_stats.proof_bytes);
  auto join_proof_len = join_proof.size();
  check(daa_tpm_sha_join_prove(
            level, profile, sk.data(), sk.size(), gid.data(), gid.size(), et.data(),
            et.size(), join_context.data(), join_context.size(),
            randomness.data(), randomness.size(), join_proof.data(),
            &join_proof_len) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(join_proof_len == join_proof.size(), "Join proof length mismatch");
  check(daa_tpm_sha_join_verify(
            level, profile, gid.data(), gid.size(), et.data(), et.size(),
            join_context.data(), join_context.size(), join_proof.data(),
            join_proof.size()) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());

  std::vector<std::uint8_t> sign_proof(sign_stats.proof_bytes);
  auto sign_proof_len = sign_proof.size();
  check(daa_tpm_sha_sign_prove(
            level, profile, sk.data(), sk.size(), s.data(), s.size(), lid.data(),
            lid.size(), gid.data(), gid.size(), slt.data(), slt.size(),
            hk.data(), hk.size(), sign_context.data(), sign_context.size(),
            randomness.data(), randomness.size(), sign_proof.data(),
            &sign_proof_len) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(sign_proof_len == sign_proof.size(), "Sign proof length mismatch");
  check(daa_tpm_sha_sign_verify(
            level, profile, lid.data(), lid.size(), gid.data(), gid.size(), slt.data(),
            slt.size(), hk.data(), hk.size(), sign_context.data(),
            sign_context.size(), sign_proof.data(), sign_proof.size()) ==
            DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());

  check(join_proof.size() >= 8 && sign_proof.size() >= 8,
        "proof header is truncated");
  const auto level_code = level == DAA_TPM_SHA_128 ? 1U :
                          level == DAA_TPM_SHA_192 ? 2U : 3U;
  const auto profile_code = profile == DAA_TPM_SHA_SMALL ? 1U : 2U;
  check(join_proof[5] == 3 && join_proof[6] == level_code &&
            join_proof[7] == profile_code,
        "Join proof header does not bind level/profile");
  check(sign_proof[5] == 3 && sign_proof[6] == level_code &&
            sign_proof[7] == profile_code,
        "sign proof header does not bind level/profile");

  const auto join_fingerprint = reference_hash(level, join_proof);
  const auto sign_fingerprint = reference_hash(level, sign_proof);
  const std::array<std::string_view, 6> expected_join_fingerprints{
      "bc3e8ffd6fb4cc9c6504a828cc72be50e7c9536b65c2c897a0d6635e1ac89bd0",
      "41fbdf11b8626fbd5be2f6d229940bd43ae0b30d52690a60ac8e20868bab6272",
      "7dae22cce2866f8c8ff987bb60c6da8b170bd11974a2ab0db9091103cc6e67118b5c7fdb23788aab1d87e70b2a5030e4",
      "06ca1bd7d6f800e38057c3f9dd8a6cd151d397df25e1efb0bfc2e3a243891744061de4f6e271362144ac98fb6e3dfe27",
      "674da085287b3fcf9ef8fff0dc8baaac2c6981c634cee520128f1eb03860f624ce8f706bef70ba333a2b3365228dddf568c18aa941e365036a9d1161d61fa9a4",
      "3fc962d5d72ad53954db573eecaaac369142edc415835b7e68264fd212524297f8094e56fad3c497bff1b0bd5e2559607aa91b81d3234728bd743f6b57a80592",
  };
  const std::array<std::string_view, 6> expected_sign_fingerprints{
      "13f75ea8c8da1e7585200ba04bedd4f67236fcc019897bdfb8a232edd4ff683a",
      "07483810e5e627101fbdfc484c2e71b2b585e885db2eff07e1d62bf0f9c8fc31",
      "7928fdea1857776ae68e94c59f15a5a8f6bfe6e46495a45bf788edc10a74d89557a6c3b96680bef726df1a61f1e47e8c",
      "897b3e9da12c979fe683be076640b76b1ef18025acbdd3e5a25bf1650f0e03bef74f522777a2ee72929850b77e384cc9",
      "5ef097a710ce8d25afbadf6eb51e03a387259d32005f59d1d16a8d25fc8cf20c696399f659164db90dfe9463a7243e0d475e050b7a744170c9fc1a41b57badd1",
      "42822793fb91f0da5e2e99064ee0103f22549c61b86b6a435bbeafb38240c2f638c74a1dd0856fb229f73dd8fa69169ddcfe1d883f27761f37a47bd53ca8d052",
  };
  const auto level_index = level == DAA_TPM_SHA_128 ? 0U :
                           level == DAA_TPM_SHA_192 ? 1U : 2U;
  const auto kat_index = 2 * level_index +
                         (profile == DAA_TPM_SHA_SMALL ? 0U : 1U);
  check(to_hex(join_fingerprint) == expected_join_fingerprints[kat_index],
        "Join deterministic S/F KAT changed");
  check(to_hex(sign_fingerprint) == expected_sign_fingerprints[kat_index],
        "sign deterministic S/F KAT changed");

  const auto other_profile = profile == DAA_TPM_SHA_SMALL
                                 ? DAA_TPM_SHA_FAST
                                 : DAA_TPM_SHA_SMALL;
  check(daa_tpm_sha_join_verify(
            level, other_profile, gid.data(), gid.size(), et.data(), et.size(),
            join_context.data(), join_context.size(), join_proof.data(),
            join_proof.size()) != DAA_TPM_SHA_OK,
        "Join proof accepted under the wrong VOLE profile");
  check(daa_tpm_sha_sign_verify(
            level, other_profile, lid.data(), lid.size(), gid.data(), gid.size(),
            slt.data(), slt.size(), hk.data(), hk.size(), sign_context.data(),
            sign_context.size(), sign_proof.data(), sign_proof.size()) !=
            DAA_TPM_SHA_OK,
        "sign proof accepted under the wrong VOLE profile");

  auto wrong_hk = hk;
  wrong_hk[0] ^= 1;
  check(daa_tpm_sha_sign_verify(
            level, profile, lid.data(), lid.size(), gid.data(), gid.size(), slt.data(),
            slt.size(), wrong_hk.data(), wrong_hk.size(), sign_context.data(),
            sign_context.size(), sign_proof.data(), sign_proof.size()) !=
            DAA_TPM_SHA_OK,
        "tampered hk accepted");
  auto wrong_et = et;
  wrong_et.back() ^= 1;
  check(daa_tpm_sha_join_verify(
            level, profile, gid.data(), gid.size(), wrong_et.data(), wrong_et.size(),
            join_context.data(), join_context.size(), join_proof.data(),
            join_proof.size()) != DAA_TPM_SHA_OK,
        "tampered et accepted");
  auto wrong_context = sign_context;
  wrong_context[0] ^= 1;
  check(daa_tpm_sha_sign_verify(
            level, profile, lid.data(), lid.size(), gid.data(), gid.size(), slt.data(),
            slt.size(), hk.data(), hk.size(), wrong_context.data(),
            wrong_context.size(), sign_proof.data(), sign_proof.size()) !=
            DAA_TPM_SHA_OK,
        "wrong context accepted");
}

void run_bf64_kat() {
  struct Vector {
    bf64_t lhs;
    bf64_t rhs;
    bf64_t expected;
  };
  constexpr std::array<Vector, 5> vectors{{
      {0, 0, 0},
      {1, UINT64_C(0x0123456789abcdef), UINT64_C(0x0123456789abcdef)},
      {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
       UINT64_C(0x48827ab55d976fa0)},
      {UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff),
       UINT64_C(0x5555555555555513)},
      {UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000000),
       UINT64_C(0xc00000000000005a)},
  }};
  for (const auto& vector : vectors) {
    check(bf64_mul(vector.lhs, vector.rhs) == vector.expected,
          "bf64 PCLMUL KAT mismatch");
  }
}

template<std::size_t Size>
std::array<std::uint8_t, Size> field_bytes(std::string_view hex) {
  check(hex.size() == 2 * Size, "invalid finite-field KAT encoding");
  const auto nibble = [](char digit) -> std::uint8_t {
    if (digit >= '0' && digit <= '9')
      return static_cast<std::uint8_t>(digit - '0');
    if (digit >= 'a' && digit <= 'f')
      return static_cast<std::uint8_t>(digit - 'a' + 10);
    throw std::runtime_error("invalid GF(2^128) KAT digit");
  };
  std::array<std::uint8_t, Size> output{};
  for (std::size_t i = 0; i != output.size(); ++i)
    output[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4) |
                                          nibble(hex[2 * i + 1]));
  return output;
}

std::array<std::uint8_t, 16> bytes128(std::string_view hex) {
  return field_bytes<16>(hex);
}

template<std::size_t Size>
std::array<std::uint8_t, Size> reference_field_mul(
    std::array<std::uint8_t, Size> lhs,
    const std::array<std::uint8_t, Size>& rhs, std::uint64_t modulus) {
  std::array<std::uint8_t, Size> result{};
  for (std::size_t bit = 0; bit != 8 * Size; ++bit) {
    const auto mask = static_cast<std::uint8_t>(
        0U - ((rhs[bit / 8] >> (bit % 8)) & 1U));
    for (std::size_t byte = 0; byte != Size; ++byte)
      result[byte] ^= lhs[byte] & mask;
    const auto carry = static_cast<std::uint8_t>(lhs.back() >> 7);
    for (std::size_t byte = Size - 1; byte != 0; --byte)
      lhs[byte] = static_cast<std::uint8_t>(
          (lhs[byte] << 1) | (lhs[byte - 1] >> 7));
    lhs[0] = static_cast<std::uint8_t>(lhs[0] << 1);
    for (std::size_t byte = 0; byte != sizeof(modulus); ++byte) {
      lhs[byte] ^= static_cast<std::uint8_t>(modulus >> (8 * byte)) &
                   static_cast<std::uint8_t>(0U - carry);
    }
  }
  return result;
}

std::array<std::uint8_t, 16> reference_bf128_mul(
    std::array<std::uint8_t, 16> lhs,
    const std::array<std::uint8_t, 16>& rhs) {
  return reference_field_mul(lhs, rhs, UINT64_C(0x87));
}

void check_bf128_mul(const std::array<std::uint8_t, 16>& lhs_bytes,
                     const std::array<std::uint8_t, 16>& rhs_bytes,
                     const std::array<std::uint8_t, 16>& expected) {
  check(reference_bf128_mul(lhs_bytes, rhs_bytes) == expected,
        "GF(2^128) reference KAT mismatch");
  bf128_t lhs, rhs, product;
  bf128_load(&lhs, lhs_bytes.data());
  bf128_load(&rhs, rhs_bytes.data());
  bf128_mul(&product, &lhs, &rhs);
  std::array<std::uint8_t, 16> output{};
  bf128_store(output.data(), &product);
  check(output == expected, "bf128 PCLMUL KAT mismatch");

  auto inplace = lhs;
  bf128_mul_inplace(&inplace, &rhs);
  bf128_store(output.data(), &inplace);
  check(output == expected, "bf128 PCLMUL in-place KAT mismatch");
}

void run_bf128_kat() {
  check_bf128_mul(
      bytes128("00000000000000000000000000000000"),
      bytes128("00112233445566778899aabbccddeeff"),
      bytes128("00000000000000000000000000000000"));
  check_bf128_mul(
      bytes128("01000000000000000000000000000000"),
      bytes128("00112233445566778899aabbccddeeff"),
      bytes128("00112233445566778899aabbccddeeff"));
  check_bf128_mul(
      bytes128("0123456789abcdeffedcba9876543210"),
      bytes128("00112233445566778899aabbccddeeff"),
      bytes128("fdb07b41fca4d756a0e6108f04c68baf"));
  check_bf128_mul(
      bytes128("00000000000000000000000000000080"),
      bytes128("00000000000000000000000000000080"),
      bytes128("671000000000000000000000000000c0"));
  check_bf128_mul(
      bytes128("ffffffffffffffffffffffffffffffff"),
      bytes128("ffffffffffffffffffffffffffffffff"),
      bytes128("2f405555555555555555555555555555"));

  for (std::size_t vector = 0; vector != 64; ++vector) {
    std::array<std::uint8_t, 16> lhs{}, rhs{};
    for (std::size_t byte = 0; byte != lhs.size(); ++byte) {
      lhs[byte] = static_cast<std::uint8_t>(0x35 + 17 * vector + 29 * byte);
      rhs[byte] = static_cast<std::uint8_t>(0xa7 + 31 * vector + 13 * byte);
    }
    check_bf128_mul(lhs, rhs, reference_bf128_mul(lhs, rhs));
  }
  constexpr auto rhs64 = UINT64_C(0xfedcba9876543210);
  const auto lhs_bytes = bytes128("0123456789abcdeffedcba9876543210");
  std::array<std::uint8_t, 16> rhs_bytes{};
  for (std::size_t i = 0; i != 8; ++i)
    rhs_bytes[i] = static_cast<std::uint8_t>(rhs64 >> (8 * i));
  bf128_t lhs;
  bf128_load(&lhs, lhs_bytes.data());
  bf128_mul_64_inplace(&lhs, rhs64);
  std::array<std::uint8_t, 16> output{};
  bf128_store(output.data(), &lhs);
  check(output == reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x87)),
        "bf128 mixed-width PCLMUL KAT mismatch");
}

void check_bf192_mul(const std::array<std::uint8_t, 24>& lhs_bytes,
                     const std::array<std::uint8_t, 24>& rhs_bytes,
                     const std::array<std::uint8_t, 24>& expected) {
  check(reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x87)) == expected,
        "GF(2^192) reference KAT mismatch");
  bf192_t lhs, rhs, product;
  bf192_load(&lhs, lhs_bytes.data());
  bf192_load(&rhs, rhs_bytes.data());
  bf192_mul(&product, &lhs, &rhs);
  std::array<std::uint8_t, 24> output{};
  bf192_store(output.data(), &product);
  check(output == expected, "bf192 Karatsuba PCLMUL KAT mismatch");
  bf192_mul_inplace(&lhs, &rhs);
  bf192_store(output.data(), &lhs);
  check(output == expected, "bf192 Karatsuba PCLMUL in-place KAT mismatch");
}

void run_bf192_kat() {
  check_bf192_mul(
      field_bytes<24>("35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0"),
      field_bytes<24>("a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2"),
      field_bytes<24>("871b82caf5a12442a72a79ac84d30f72c8185b445ecbffcd"));
  for (std::size_t vector = 0; vector != 64; ++vector) {
    std::array<std::uint8_t, 24> lhs{}, rhs{};
    for (std::size_t byte = 0; byte != lhs.size(); ++byte) {
      lhs[byte] = static_cast<std::uint8_t>(0x29 + 19 * vector + 23 * byte);
      rhs[byte] = static_cast<std::uint8_t>(0xd3 + 11 * vector + 31 * byte);
    }
    check_bf192_mul(lhs, rhs,
                    reference_field_mul(lhs, rhs, UINT64_C(0x87)));
  }
  constexpr auto rhs64 = UINT64_C(0x0123456789abcdef);
  const auto lhs_bytes =
      field_bytes<24>("35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0");
  std::array<std::uint8_t, 24> rhs_bytes{};
  for (std::size_t i = 0; i != 8; ++i)
    rhs_bytes[i] = static_cast<std::uint8_t>(rhs64 >> (8 * i));
  bf192_t lhs;
  bf192_load(&lhs, lhs_bytes.data());
  bf192_mul_64_inplace(&lhs, rhs64);
  std::array<std::uint8_t, 24> output{};
  bf192_store(output.data(), &lhs);
  check(output == reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x87)),
        "bf192 mixed-width PCLMUL KAT mismatch");
}

void check_bf256_mul(const std::array<std::uint8_t, 32>& lhs_bytes,
                     const std::array<std::uint8_t, 32>& rhs_bytes,
                     const std::array<std::uint8_t, 32>& expected) {
  check(reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x425)) == expected,
        "GF(2^256) reference KAT mismatch");
  bf256_t lhs, rhs, product;
  bf256_load(&lhs, lhs_bytes.data());
  bf256_load(&rhs, rhs_bytes.data());
  bf256_mul(&product, &lhs, &rhs);
  std::array<std::uint8_t, 32> output{};
  bf256_store(output.data(), &product);
  check(output == expected, "bf256 Karatsuba PCLMUL KAT mismatch");
  bf256_mul_inplace(&lhs, &rhs);
  bf256_store(output.data(), &lhs);
  check(output == expected, "bf256 Karatsuba PCLMUL in-place KAT mismatch");
}

void run_bf256_kat() {
  check_bf256_mul(
      field_bytes<32>(
          "35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8"),
      field_bytes<32>(
          "a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a"),
      field_bytes<32>(
          "9435de282a539de4735d77dc6fcedeb1fa09e990d6d43f0ce95a86f03f1b48a3"));
  for (std::size_t vector = 0; vector != 64; ++vector) {
    std::array<std::uint8_t, 32> lhs{}, rhs{};
    for (std::size_t byte = 0; byte != lhs.size(); ++byte) {
      lhs[byte] = static_cast<std::uint8_t>(0x51 + 13 * vector + 37 * byte);
      rhs[byte] = static_cast<std::uint8_t>(0x9b + 29 * vector + 17 * byte);
    }
    check_bf256_mul(lhs, rhs,
                    reference_field_mul(lhs, rhs, UINT64_C(0x425)));
  }
  constexpr auto rhs64 = UINT64_C(0xa55aa55a01234567);
  const auto lhs_bytes = field_bytes<32>(
      "35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8");
  std::array<std::uint8_t, 32> rhs_bytes{};
  for (std::size_t i = 0; i != 8; ++i)
    rhs_bytes[i] = static_cast<std::uint8_t>(rhs64 >> (8 * i));
  bf256_t lhs;
  bf256_load(&lhs, lhs_bytes.data());
  bf256_mul_64_inplace(&lhs, rhs64);
  std::array<std::uint8_t, 32> output{};
  bf256_store(output.data(), &lhs);
  check(output == reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x425)),
        "bf256 mixed-width PCLMUL KAT mismatch");
}

void run_field_batch_kat() {
  constexpr auto rhs64 = UINT64_C(0x9e3779b97f4a7c15);
  {
    std::array<std::uint8_t, 16> rhs_bytes{};
    std::array<bf128_t, 3> full{}, mixed{};
    const auto rhs = field_bytes<16>("a7b4c1cedbe8f5020f1c293643505d6a");
    bf128_t rhs_field;
    bf128_load(&rhs_field, rhs.data());
    for (std::size_t byte = 0; byte != 8; ++byte)
      rhs_bytes[byte] = static_cast<std::uint8_t>(rhs64 >> (8 * byte));
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 16> input{};
      for (std::size_t byte = 0; byte != input.size(); ++byte)
        input[byte] = static_cast<std::uint8_t>(0x21 + 41 * lane + 17 * byte);
      bf128_load(&full[lane], input.data());
      mixed[lane] = full[lane];
    }
    const auto original_full = full;
    bf128_mul_3_inplace(full.data(), &rhs_field);
    bf128_mul_64_3_inplace(mixed.data(), rhs64);
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 16> input{}, output{};
      bf128_store(input.data(), &original_full[lane]);
      bf128_store(output.data(), &full[lane]);
      check(output == reference_field_mul(input, rhs, UINT64_C(0x87)),
            "bf128 batch full-width KAT mismatch");
      bf128_store(output.data(), &mixed[lane]);
      check(output == reference_field_mul(input, rhs_bytes, UINT64_C(0x87)),
            "bf128 batch mixed-width KAT mismatch");
    }
  }
  {
    std::array<std::uint8_t, 24> rhs_bytes{};
    std::array<bf192_t, 3> full{}, mixed{};
    const auto rhs =
        field_bytes<24>("a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2");
    bf192_t rhs_field;
    bf192_load(&rhs_field, rhs.data());
    for (std::size_t byte = 0; byte != 8; ++byte)
      rhs_bytes[byte] = static_cast<std::uint8_t>(rhs64 >> (8 * byte));
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 24> input{};
      for (std::size_t byte = 0; byte != input.size(); ++byte)
        input[byte] = static_cast<std::uint8_t>(0x43 + 37 * lane + 11 * byte);
      bf192_load(&full[lane], input.data());
      mixed[lane] = full[lane];
    }
    const auto original_full = full;
    bf192_mul_3_inplace(full.data(), &rhs_field);
    bf192_mul_64_3_inplace(mixed.data(), rhs64);
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 24> input{}, output{};
      bf192_store(input.data(), &original_full[lane]);
      bf192_store(output.data(), &full[lane]);
      check(output == reference_field_mul(input, rhs, UINT64_C(0x87)),
            "bf192 batch full-width KAT mismatch");
      bf192_store(output.data(), &mixed[lane]);
      check(output == reference_field_mul(input, rhs_bytes, UINT64_C(0x87)),
            "bf192 batch mixed-width KAT mismatch");
    }
  }
  {
    std::array<std::uint8_t, 32> rhs_bytes{};
    std::array<bf256_t, 3> full{}, mixed{};
    const auto rhs = field_bytes<32>(
        "a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a");
    bf256_t rhs_field;
    bf256_load(&rhs_field, rhs.data());
    for (std::size_t byte = 0; byte != 8; ++byte)
      rhs_bytes[byte] = static_cast<std::uint8_t>(rhs64 >> (8 * byte));
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 32> input{};
      for (std::size_t byte = 0; byte != input.size(); ++byte)
        input[byte] = static_cast<std::uint8_t>(0x67 + 31 * lane + 19 * byte);
      bf256_load(&full[lane], input.data());
      mixed[lane] = full[lane];
    }
    const auto original_full = full;
    bf256_mul_3_inplace(full.data(), &rhs_field);
    bf256_mul_64_3_inplace(mixed.data(), rhs64);
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 32> input{}, output{};
      bf256_store(input.data(), &original_full[lane]);
      bf256_store(output.data(), &full[lane]);
      check(output == reference_field_mul(input, rhs, UINT64_C(0x425)),
            "bf256 batch full-width KAT mismatch");
      bf256_store(output.data(), &mixed[lane]);
      check(output == reference_field_mul(input, rhs_bytes, UINT64_C(0x425)),
            "bf256 batch mixed-width KAT mismatch");
    }
  }
}

std::vector<std::uint8_t> reference_prg(
    std::span<const std::uint8_t> key,
    const std::array<std::uint8_t, 16>& iv, std::uint32_t tweak,
    unsigned int security_bits, std::size_t output_bytes) {
  auto counter = iv;
  std::uint32_t upper = static_cast<std::uint32_t>(counter[12]) |
                        (static_cast<std::uint32_t>(counter[13]) << 8) |
                        (static_cast<std::uint32_t>(counter[14]) << 16) |
                        (static_cast<std::uint32_t>(counter[15]) << 24);
  upper += tweak;
  for (unsigned int i = 0; i != 4; ++i)
    counter[12 + i] = static_cast<std::uint8_t>(upper >> (8 * i));

  generic_aes_ecb_t cipher{};
  check(generic_aes_ecb_new(&cipher, key.data(), security_bits) == 0,
        "reference AES setup failed");
  std::vector<std::uint8_t> output(output_bytes);
  std::size_t offset = 0;
  while (output_bytes - offset >= 16) {
    check(generic_aes_ecb_encrypt(&cipher, output.data() + offset,
                                  counter.data(), 1) == 0,
          "reference AES encryption failed");
    aes_increment_iv(counter.data());
    offset += 16;
  }
  if (offset != output_bytes) {
    std::array<std::uint8_t, 16> last{};
    check(generic_aes_ecb_encrypt(&cipher, last.data(), counter.data(), 1) ==
              0,
          "reference AES tail encryption failed");
    std::copy_n(last.begin(), output_bytes - offset, output.begin() + offset);
  }
  generic_aes_ecb_free(&cipher);
  return output;
}

void run_prg_kat() {
  const std::array<std::size_t, 2> lengths{128, 137};
  for (const auto security_bits : {128U, 192U, 256U}) {
    std::vector<std::uint8_t> key(security_bits / 8);
    for (std::size_t i = 0; i != key.size(); ++i)
      key[i] = static_cast<std::uint8_t>(0x31 + 7 * i);
    std::array<std::uint8_t, 16> iv{};
    for (std::size_t i = 0; i != iv.size(); ++i)
      iv[i] = static_cast<std::uint8_t>(0xa0 - 3 * i);
    for (const auto length : lengths) {
      const auto expected =
          reference_prg(key, iv, UINT32_C(0x81234567), security_bits, length);
      std::vector<std::uint8_t> actual(length);
      prg(key.data(), iv.data(), UINT32_C(0x81234567), actual.data(),
          security_bits, actual.size());
      check(actual == expected, "batched AES-CTR PRG differs from reference");
    }
  }
}

unsigned int reference_convert_to_vole(
    const std::uint8_t* iv, const std::uint8_t* seeds, bool seed_zero_bottom,
    unsigned int tree_index, unsigned int output_bytes, std::uint8_t* u,
    std::uint8_t* v, const faest_paramset_t* parameters) {
  const auto depth =
      bavc_max_node_depth(tree_index, parameters->tau1, parameters->k);
  const auto leaves =
      bavc_max_node_index(tree_index, parameters->tau1, parameters->k);
  const auto lambda_bytes = parameters->lambda / 8;
  std::vector<std::uint8_t> rows(2 * leaves * output_bytes);
  const auto row = [&](unsigned int level, unsigned int node) {
    return rows.data() + ((level % 2) * leaves + node) * output_bytes;
  };
  const auto tweak = tree_index ^ UINT32_C(0x80000000);
  if (!seed_zero_bottom)
    prg(seeds, iv, tweak, row(0, 0), parameters->lambda, output_bytes);
  for (unsigned int leaf = 1; leaf != leaves; ++leaf)
    prg(seeds + lambda_bytes * leaf, iv, tweak, row(0, leaf),
        parameters->lambda, output_bytes);

  std::fill_n(v, depth * output_bytes, UINT8_C(0));
  for (unsigned int level = 0; level != depth; ++level) {
    const auto nodes = leaves >> (level + 1);
    for (unsigned int node = 0; node != nodes; ++node) {
      for (unsigned int byte = 0; byte != output_bytes; ++byte) {
        const auto right = row(level, 2 * node + 1)[byte];
        v[level * output_bytes + byte] ^= right;
        row(level + 1, node)[byte] =
            row(level, 2 * node)[byte] ^ right;
      }
    }
  }
  if (!seed_zero_bottom && u != nullptr)
    std::copy_n(row(depth, 0), output_bytes, u);
  return depth;
}

void run_convert_to_vole_kat() {
  for (const auto parameter_id :
       {FAEST_128S, FAEST_128F, FAEST_192S, FAEST_192F, FAEST_256S,
        FAEST_256F}) {
    const auto* parameters = faest_get_paramset(parameter_id);
    check(parameters != nullptr, "missing FAEST parameter set");
    for (const auto tree_index : {0U,
                                  static_cast<unsigned int>(parameters->tau - 1)}) {
      const auto depth =
          bavc_max_node_depth(tree_index, parameters->tau1, parameters->k);
      const auto leaves =
          bavc_max_node_index(tree_index, parameters->tau1, parameters->k);
      constexpr unsigned int output_bytes = 137;
      std::array<std::uint8_t, 16> iv{};
      std::vector<std::uint8_t> seeds(
          leaves * static_cast<unsigned int>(parameters->lambda / 8));
      for (std::size_t i = 0; i != seeds.size(); ++i)
        seeds[i] = static_cast<std::uint8_t>(0x59 + 11 * i);
      std::vector<std::uint8_t> expected_u(output_bytes), actual_u(output_bytes);
      std::vector<std::uint8_t> expected_v(depth * output_bytes);
      std::vector<std::uint8_t> actual_v(depth * output_bytes);
      for (const auto seed_zero_bottom : {false, true}) {
        const auto expected_depth = reference_convert_to_vole(
            iv.data(), seeds.data(), seed_zero_bottom, tree_index,
            output_bytes, seed_zero_bottom ? nullptr : expected_u.data(),
            expected_v.data(), parameters);
        const auto actual_depth = convert_to_vole(
            iv.data(), seeds.data(), seed_zero_bottom, tree_index,
            output_bytes, seed_zero_bottom ? nullptr : actual_u.data(),
            actual_v.data(), parameters);
        check(actual_depth == expected_depth && actual_v == expected_v,
              "streaming ConvertToVOLE differs from reference");
        if (!seed_zero_bottom)
          check(actual_u == expected_u,
                "streaming ConvertToVOLE root differs from reference");
      }
    }
  }
}

} // namespace

int main() {
  try {
    run_bf64_kat();
    run_bf128_kat();
    run_bf192_kat();
    run_bf256_kat();
    run_field_batch_kat();
    run_prg_kat();
    run_convert_to_vole_kat();
    for (const auto level :
         {DAA_TPM_SHA_128, DAA_TPM_SHA_192, DAA_TPM_SHA_256}) {
      run_level(level, DAA_TPM_SHA_SMALL);
      run_level(level, DAA_TPM_SHA_FAST);
    }
    std::cout << "TPM SHA-256/384/512 S/F KAT and proof tests: ok" << std::endl;
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::cerr << "TPM SHA test failure: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
