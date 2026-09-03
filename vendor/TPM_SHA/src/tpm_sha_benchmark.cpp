/* SPDX-License-Identifier: MIT */

#include "tpm_sha.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

void require(int status) {
  if (status != DAA_TPM_SHA_OK)
    throw std::runtime_error(daa_tpm_sha_last_error());
}

template <typename Function>
double average_ms(std::size_t iterations, Function&& function) {
  const auto begin = Clock::now();
  for (std::size_t i = 0; i != iterations; ++i) function(i);
  const auto end = Clock::now();
  return std::chrono::duration<double, std::milli>(end - begin).count() /
         static_cast<double>(iterations);
}

void benchmark(daa_tpm_sha_level level, daa_tpm_sha_profile profile,
               std::size_t iterations) {
  const auto key_bytes = daa_tpm_sha_key_bytes(level);
  const auto digest_bytes = daa_tpm_sha_digest_bytes(level);
  std::vector<std::uint8_t> sk(key_bytes), s(key_bytes), lid(digest_bytes),
      gid(digest_bytes), slt(digest_bytes), et(digest_bytes), hk(digest_bytes);
  for (std::size_t i = 0; i != key_bytes; ++i) {
    sk[i] = static_cast<std::uint8_t>(i + 1);
    s[i] = static_cast<std::uint8_t>(0xa0 + i);
  }
  for (std::size_t i = 0; i != digest_bytes; ++i) {
    lid[i] = static_cast<std::uint8_t>(0x31 + i);
    gid[i] = static_cast<std::uint8_t>(0xf2 - i);
  }
  std::array<std::uint8_t, 32> randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i)
    randomness[i] = static_cast<std::uint8_t>(0x40 + i);
  const std::array<std::uint8_t, 12> join_context{
      't','p','m','-','j','o','i','n','-','v','1',0};
  const std::array<std::uint8_t, 12> sign_context{
      't','p','m','-','s','i','g','n','-','v','1',0};

  const auto prepare_begin = Clock::now();
  require(daa_tpm_sha_prepare(level, profile));
  const auto prepare_ms = std::chrono::duration<double, std::milli>(
                              Clock::now() - prepare_begin).count();
  require(daa_tpm_sha_evaluate_sign(
      level, sk.data(), sk.size(), s.data(), s.size(), lid.data(), lid.size(),
      gid.data(), gid.size(), slt.data(), slt.size(), et.data(), et.size(),
      hk.data(), hk.size()));

  daa_tpm_sha_stats join_stats{}, sign_stats{};
  require(daa_tpm_sha_join_stats(level, profile, &join_stats));
  require(daa_tpm_sha_sign_stats(level, profile, &sign_stats));
  std::vector<std::uint8_t> join_proof(join_stats.proof_bytes);
  std::vector<std::uint8_t> sign_proof(sign_stats.proof_bytes);

  // Warm both prover paths before measurement.
  auto join_len = join_proof.size();
  require(daa_tpm_sha_join_prove(
      level, profile, sk.data(), sk.size(), gid.data(), gid.size(), et.data(), et.size(),
      join_context.data(), join_context.size(), randomness.data(),
      randomness.size(), join_proof.data(), &join_len));
  auto sign_len = sign_proof.size();
  require(daa_tpm_sha_sign_prove(
      level, profile, sk.data(), sk.size(), s.data(), s.size(), lid.data(), lid.size(),
      gid.data(), gid.size(), slt.data(), slt.size(), hk.data(), hk.size(),
      sign_context.data(), sign_context.size(), randomness.data(),
      randomness.size(), sign_proof.data(), &sign_len));

  const auto join_prover_ms = average_ms(iterations, [&](std::size_t i) {
    randomness[0] = static_cast<std::uint8_t>(0x40 + i);
    auto length = join_proof.size();
    require(daa_tpm_sha_join_prove(
        level, profile, sk.data(), sk.size(), gid.data(), gid.size(), et.data(),
        et.size(), join_context.data(), join_context.size(), randomness.data(),
        randomness.size(), join_proof.data(), &length));
  });
  const auto join_verifier_ms = average_ms(iterations, [&](std::size_t) {
    require(daa_tpm_sha_join_verify(
        level, profile, gid.data(), gid.size(), et.data(), et.size(),
        join_context.data(), join_context.size(), join_proof.data(),
        join_proof.size()));
  });
  const auto sign_prover_ms = average_ms(iterations, [&](std::size_t i) {
    randomness[0] = static_cast<std::uint8_t>(0x80 + i);
    auto length = sign_proof.size();
    require(daa_tpm_sha_sign_prove(
        level, profile, sk.data(), sk.size(), s.data(), s.size(), lid.data(), lid.size(),
        gid.data(), gid.size(), slt.data(), slt.size(), hk.data(), hk.size(),
        sign_context.data(), sign_context.size(), randomness.data(),
        randomness.size(), sign_proof.data(), &length));
  });
  const auto sign_verifier_ms = average_ms(iterations, [&](std::size_t) {
    require(daa_tpm_sha_sign_verify(
        level, profile, lid.data(), lid.size(), gid.data(), gid.size(), slt.data(),
        slt.size(), hk.data(), hk.size(), sign_context.data(),
        sign_context.size(), sign_proof.data(), sign_proof.size()));
  });

  std::cout << "TPM-SHA security=" << static_cast<int>(level)
            << " profile=" << (profile == DAA_TPM_SHA_SMALL ? "s" : "f")
            << " hash=SHA-" << (level == DAA_TPM_SHA_128 ? "256" :
                                level == DAA_TPM_SHA_192 ? "384" : "512")
            << " prepare_ms=" << std::fixed << std::setprecision(3) << prepare_ms
            << '\n';
  std::cout << "join and=" << join_stats.and_gates
            << " xor=" << join_stats.xor_gates
            << " prover_ms=" << join_prover_ms
            << " verifier_ms=" << join_verifier_ms
            << " proof_bytes=" << join_stats.proof_bytes << '\n';
  std::cout << "sign and=" << sign_stats.and_gates
            << " xor=" << sign_stats.xor_gates
            << " prover_ms=" << sign_prover_ms
            << " verifier_ms=" << sign_verifier_ms
            << " proof_bytes=" << sign_stats.proof_bytes << '\n';
}

} // namespace

int main(int argc, char** argv) {
  try {
    std::size_t iterations = 10;
    std::vector<daa_tpm_sha_level> levels{
        DAA_TPM_SHA_128, DAA_TPM_SHA_192, DAA_TPM_SHA_256};
    std::vector<daa_tpm_sha_profile> profiles{
        DAA_TPM_SHA_SMALL, DAA_TPM_SHA_FAST};
    for (int i = 1; i != argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--iterations" && i + 1 != argc) {
        iterations = std::stoul(argv[++i]);
        if (iterations == 0) throw std::invalid_argument("iterations must be positive");
      } else if (argument == "--security" && i + 1 != argc) {
        const std::string value = argv[++i];
        if (value == "128") levels = {DAA_TPM_SHA_128};
        else if (value == "192") levels = {DAA_TPM_SHA_192};
        else if (value == "256") levels = {DAA_TPM_SHA_256};
        else throw std::invalid_argument("security must be 128, 192, or 256");
      } else if (argument == "--profile" && i + 1 != argc) {
        const std::string value = argv[++i];
        if (value == "s" || value == "small") profiles = {DAA_TPM_SHA_SMALL};
        else if (value == "f" || value == "fast") profiles = {DAA_TPM_SHA_FAST};
        else if (value != "all")
          throw std::invalid_argument("profile must be s, f, or all");
      } else {
        throw std::invalid_argument(
            "usage: tpm_sha_benchmark [--security 128|192|256] "
            "[--profile s|f|all] [--iterations N]");
      }
    }
    for (const auto level : levels)
      for (const auto profile : profiles) benchmark(level, profile, iterations);
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::cerr << "TPM SHA benchmark failure: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
