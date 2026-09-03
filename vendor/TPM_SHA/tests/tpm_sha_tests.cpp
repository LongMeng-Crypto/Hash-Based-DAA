/* SPDX-License-Identifier: MIT */

#include "tpm_sha.h"

#include <openssl/evp.h>

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

void run_level(daa_tpm_sha_level level) {
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

  check(daa_tpm_sha_prepare(level) == DAA_TPM_SHA_OK,
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
  check(daa_tpm_sha_join_stats(level, &join_stats) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(daa_tpm_sha_sign_stats(level, &sign_stats) == DAA_TPM_SHA_OK,
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
            level, sk.data(), sk.size(), gid.data(), gid.size(), et.data(),
            et.size(), join_context.data(), join_context.size(),
            randomness.data(), randomness.size(), join_proof.data(),
            &join_proof_len) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(join_proof_len == join_proof.size(), "Join proof length mismatch");
  check(daa_tpm_sha_join_verify(
            level, gid.data(), gid.size(), et.data(), et.size(),
            join_context.data(), join_context.size(), join_proof.data(),
            join_proof.size()) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());

  std::vector<std::uint8_t> sign_proof(sign_stats.proof_bytes);
  auto sign_proof_len = sign_proof.size();
  check(daa_tpm_sha_sign_prove(
            level, sk.data(), sk.size(), s.data(), s.size(), lid.data(),
            lid.size(), gid.data(), gid.size(), slt.data(), slt.size(),
            hk.data(), hk.size(), sign_context.data(), sign_context.size(),
            randomness.data(), randomness.size(), sign_proof.data(),
            &sign_proof_len) == DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());
  check(sign_proof_len == sign_proof.size(), "Sign proof length mismatch");
  check(daa_tpm_sha_sign_verify(
            level, lid.data(), lid.size(), gid.data(), gid.size(), slt.data(),
            slt.size(), hk.data(), hk.size(), sign_context.data(),
            sign_context.size(), sign_proof.data(), sign_proof.size()) ==
            DAA_TPM_SHA_OK,
        daa_tpm_sha_last_error());

  const auto join_fingerprint = reference_hash(level, join_proof);
  const auto sign_fingerprint = reference_hash(level, sign_proof);
  const std::array<std::string_view, 3> expected_join_fingerprints{
      "a12cae5c554e9d36ae02f50fd7b240f2d19aaeaee6daefdda259dabbdbb53da5",
      "60d028eca3b04bbc12963e626a481dba6ceac2be8765993564437bce7b84ab04fc2fa02cbf1520ebe01aa72bb3be060a",
      "1b234fe6866f768a7ebe6aac4b6aeca7a719abc30822dadce4d9be89a8ee8228886ba02d7f5aecc61841c22b07b2b6721ab6b7a9f428f4cc59f4bcfb08bf8cf4"};
  const std::array<std::string_view, 3> expected_sign_fingerprints{
      "0f2dd6501624a38722d312ee18664ef3575d96c9854dfbb6e774eed152a9c040",
      "126d1d58b0e5fd2528af8201a79619a0d91eccef0c7e9c8bd23f44e5a13894d6331831844c520b739c7806249b3fcf27",
      "2d3d1299136fb3cc99630cd843c285d921cc6918c6e7c20f503c31fc109b4d8ae8eb7a6c3fe77d072ffe5d7662e322c7977aaf72ea9f44ebae207d1ec18d751f"};
  const auto kat_index = level == DAA_TPM_SHA_128 ? 0U :
                         level == DAA_TPM_SHA_192 ? 1U : 2U;
  check(to_hex(join_fingerprint) == expected_join_fingerprints[kat_index],
        "Join deterministic KAT changed");
  check(to_hex(sign_fingerprint) == expected_sign_fingerprints[kat_index],
        "Sign deterministic KAT changed");

  auto wrong_hk = hk;
  wrong_hk[0] ^= 1;
  check(daa_tpm_sha_sign_verify(
            level, lid.data(), lid.size(), gid.data(), gid.size(), slt.data(),
            slt.size(), wrong_hk.data(), wrong_hk.size(), sign_context.data(),
            sign_context.size(), sign_proof.data(), sign_proof.size()) !=
            DAA_TPM_SHA_OK,
        "tampered hk accepted");
  auto wrong_et = et;
  wrong_et.back() ^= 1;
  check(daa_tpm_sha_join_verify(
            level, gid.data(), gid.size(), wrong_et.data(), wrong_et.size(),
            join_context.data(), join_context.size(), join_proof.data(),
            join_proof.size()) != DAA_TPM_SHA_OK,
        "tampered et accepted");
  auto wrong_context = sign_context;
  wrong_context[0] ^= 1;
  check(daa_tpm_sha_sign_verify(
            level, lid.data(), lid.size(), gid.data(), gid.size(), slt.data(),
            slt.size(), hk.data(), hk.size(), wrong_context.data(),
            wrong_context.size(), sign_proof.data(), sign_proof.size()) !=
            DAA_TPM_SHA_OK,
        "wrong context accepted");
}

} // namespace

int main() {
  try {
    run_level(DAA_TPM_SHA_128);
    run_level(DAA_TPM_SHA_192);
    run_level(DAA_TPM_SHA_256);
    std::cout << "TPM SHA-256/384/512 KAT and proof tests: ok\n";
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::cerr << "TPM SHA test failure: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
