/* SPDX-License-Identifier: MIT */

#include "tpm_sha.h"

#include "backend/generic_nizk.hpp"
#include "backend/prepared_binary_circuit.hpp"
#include "tpm_sha_relation.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>

namespace {

thread_local std::string last_error;

vole_backend::SecurityLevel level_from_c(daa_tpm_sha_level level) {
  switch (level) {
  case DAA_TPM_SHA_128: return vole_backend::SecurityLevel::Bits128;
  case DAA_TPM_SHA_192: return vole_backend::SecurityLevel::Bits192;
  case DAA_TPM_SHA_256: return vole_backend::SecurityLevel::Bits256;
  }
  throw std::invalid_argument("invalid TPM SHA security level");
}

vole_backend::VoleProfile profile_from_c(daa_tpm_sha_profile profile) {
  switch (profile) {
  case DAA_TPM_SHA_SMALL: return vole_backend::VoleProfile::Small;
  case DAA_TPM_SHA_FAST: return vole_backend::VoleProfile::Fast;
  }
  throw std::invalid_argument("invalid TPM SHA VOLE profile");
}

struct CachedRelation {
  explicit CachedRelation(vole_backend::SecurityLevel level,
                          daa::tpm_sha::RelationKind kind)
      : relation(level, kind), prepared(relation.binary_circuit()) {}
  daa::tpm_sha::Relation relation;
  vole_backend::PreparedBinaryCircuit prepared;
};

CachedRelation& join_cache(daa_tpm_sha_level level) {
  switch (level) {
  case DAA_TPM_SHA_128: {
    static CachedRelation value(vole_backend::SecurityLevel::Bits128,
                                daa::tpm_sha::RelationKind::Join);
    return value;
  }
  case DAA_TPM_SHA_192: {
    static CachedRelation value(vole_backend::SecurityLevel::Bits192,
                                daa::tpm_sha::RelationKind::Join);
    return value;
  }
  case DAA_TPM_SHA_256: {
    static CachedRelation value(vole_backend::SecurityLevel::Bits256,
                                daa::tpm_sha::RelationKind::Join);
    return value;
  }
  }
  throw std::invalid_argument("invalid TPM SHA security level");
}

CachedRelation& sign_cache(daa_tpm_sha_level level) {
  switch (level) {
  case DAA_TPM_SHA_128: {
    static CachedRelation value(vole_backend::SecurityLevel::Bits128,
                                daa::tpm_sha::RelationKind::Sign);
    return value;
  }
  case DAA_TPM_SHA_192: {
    static CachedRelation value(vole_backend::SecurityLevel::Bits192,
                                daa::tpm_sha::RelationKind::Sign);
    return value;
  }
  case DAA_TPM_SHA_256: {
    static CachedRelation value(vole_backend::SecurityLevel::Bits256,
                                daa::tpm_sha::RelationKind::Sign);
    return value;
  }
  }
  throw std::invalid_argument("invalid TPM SHA security level");
}

std::span<const std::uint8_t> input_span(const std::uint8_t* pointer,
                                         std::size_t length,
                                         const char* name) {
  if (pointer == nullptr && length != 0)
    throw std::invalid_argument(std::string(name) + " is null");
  return {pointer, length};
}

std::span<std::uint8_t> output_span(std::uint8_t* pointer,
                                    std::size_t length,
                                    const char* name) {
  if (pointer == nullptr && length != 0)
    throw std::invalid_argument(std::string(name) + " is null");
  return {pointer, length};
}

template <typename Function>
int ffi(Function&& function) noexcept {
  last_error.clear();
  try {
    function();
    return DAA_TPM_SHA_OK;
  } catch (const std::invalid_argument& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  } catch (...) {
    last_error = "unknown TPM SHA failure";
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

void copy_exact(std::span<const std::uint8_t> source,
                std::span<std::uint8_t> destination, const char* name) {
  if (destination.size() != source.size())
    throw std::invalid_argument(std::string(name) + " has wrong length");
  std::copy(source.begin(), source.end(), destination.begin());
}

vole_backend::ProverRandomness prover_randomness(
    const std::uint8_t* pointer, std::size_t length) {
  const auto bytes = input_span(pointer, length, "randomness");
  if (bytes.size() != vole_backend::ProverRandomness{}.size())
    throw std::invalid_argument("randomness must be exactly 32 bytes");
  vole_backend::ProverRandomness result{};
  std::copy(bytes.begin(), bytes.end(), result.begin());
  return result;
}

vole_backend::PublicStatement join_statement(
    const daa::tpm_sha::Relation& relation,
    std::span<const std::uint8_t> gid,
    std::span<const std::uint8_t> et) {
  return {relation.public_bits({}, gid), relation.output_bits({}, et, {})};
}

vole_backend::PublicStatement sign_statement(
    const daa::tpm_sha::Relation& relation,
    std::span<const std::uint8_t> lid,
    std::span<const std::uint8_t> gid,
    std::span<const std::uint8_t> slt,
    std::span<const std::uint8_t> hk) {
  return {relation.public_bits(lid, gid), relation.output_bits(slt, {}, hk)};
}

int write_proof(std::span<const std::uint8_t> proof,
                std::uint8_t* output, std::size_t* output_length) {
  if (output_length == nullptr) {
    last_error = "proof_len is null";
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  }
  const auto capacity = *output_length;
  *output_length = proof.size();
  if (output == nullptr || capacity < proof.size()) {
    last_error = "proof output buffer is too small";
    return DAA_TPM_SHA_BUFFER_TOO_SMALL;
  }
  std::copy(proof.begin(), proof.end(), output);
  return DAA_TPM_SHA_OK;
}

void fill_stats(const CachedRelation& cached,
                vole_backend::VoleProfile profile,
                daa_tpm_sha_stats* output) {
  if (output == nullptr) throw std::invalid_argument("stats_out is null");
  const auto stats = cached.prepared.statistics();
  output->private_input_bits = stats.private_inputs;
  output->public_input_bits = stats.public_inputs;
  output->output_bits = cached.relation.binary_circuit().outputs().size();
  output->and_gates = stats.multiplication_gates;
  output->xor_gates = stats.xor_gates;
  output->total_nodes = stats.total_nodes;
  output->proof_bytes = vole_backend::serialized_proof_bytes(
      cached.prepared, cached.relation.level(), profile);
}

} // namespace

extern "C" {

size_t daa_tpm_sha_key_bytes(daa_tpm_sha_level level) {
  last_error.clear();
  try {
    return vole_backend::security_parameters(level_from_c(level)).lambda_bytes;
  } catch (const std::exception& error) {
    last_error = error.what();
    return 0;
  }
}

size_t daa_tpm_sha_digest_bytes(daa_tpm_sha_level level) {
  last_error.clear();
  switch (level) {
  case DAA_TPM_SHA_128: return 32;
  case DAA_TPM_SHA_192: return 48;
  case DAA_TPM_SHA_256: return 64;
  }
  last_error = "invalid TPM SHA security level";
  return 0;
}

int daa_tpm_sha_prepare(daa_tpm_sha_level level, daa_tpm_sha_profile profile) {
  return ffi([&] {
    static_cast<void>(profile_from_c(profile));
    static_cast<void>(join_cache(level));
    static_cast<void>(sign_cache(level));
  });
}

int daa_tpm_sha_join_stats(daa_tpm_sha_level level,
                           daa_tpm_sha_profile profile,
                           daa_tpm_sha_stats* output) {
  return ffi([&] {
    fill_stats(join_cache(level), profile_from_c(profile), output);
  });
}

int daa_tpm_sha_sign_stats(daa_tpm_sha_level level,
                           daa_tpm_sha_profile profile,
                           daa_tpm_sha_stats* output) {
  return ffi([&] {
    fill_stats(sign_cache(level), profile_from_c(profile), output);
  });
}

size_t daa_tpm_sha_join_proof_bytes(daa_tpm_sha_level level,
                                    daa_tpm_sha_profile profile) {
  daa_tpm_sha_stats stats{};
  return daa_tpm_sha_join_stats(level, profile, &stats) == DAA_TPM_SHA_OK
             ? stats.proof_bytes : 0;
}

size_t daa_tpm_sha_sign_proof_bytes(daa_tpm_sha_level level,
                                    daa_tpm_sha_profile profile) {
  daa_tpm_sha_stats stats{};
  return daa_tpm_sha_sign_stats(level, profile, &stats) == DAA_TPM_SHA_OK
             ? stats.proof_bytes : 0;
}

int daa_tpm_sha_evaluate_join(
    daa_tpm_sha_level level, const uint8_t* sk, size_t sk_len,
    const uint8_t* gid, size_t gid_len, uint8_t* et_out, size_t et_len) {
  return ffi([&] {
    auto& relation = join_cache(level).relation;
    const auto result = relation.evaluate(input_span(sk, sk_len, "sk"), {}, {},
                                          input_span(gid, gid_len, "gid"));
    copy_exact(result.et, output_span(et_out, et_len, "et_out"), "et_out");
  });
}

int daa_tpm_sha_evaluate_sign(
    daa_tpm_sha_level level, const uint8_t* sk, size_t sk_len,
    const uint8_t* s, size_t s_len, const uint8_t* lid, size_t lid_len,
    const uint8_t* gid, size_t gid_len, uint8_t* slt_out, size_t slt_len,
    uint8_t* et_out, size_t et_len, uint8_t* hk_out, size_t hk_len) {
  return ffi([&] {
    auto& relation = sign_cache(level).relation;
    const auto result = relation.evaluate(
        input_span(sk, sk_len, "sk"), input_span(s, s_len, "s"),
        input_span(lid, lid_len, "lid"), input_span(gid, gid_len, "gid"));
    copy_exact(result.slt, output_span(slt_out, slt_len, "slt_out"), "slt_out");
    copy_exact(result.et, output_span(et_out, et_len, "et_out"), "et_out");
    copy_exact(result.hk, output_span(hk_out, hk_len, "hk_out"), "hk_out");
  });
}

int daa_tpm_sha_join_prove(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* gid, size_t gid_len, const uint8_t* et, size_t et_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* randomness, size_t randomness_len,
    uint8_t* proof_out, size_t* proof_len) {
  last_error.clear();
  try {
    auto& cached = join_cache(level);
    const auto sk_span = input_span(sk, sk_len, "sk");
    const auto statement = join_statement(
        cached.relation, input_span(gid, gid_len, "gid"),
        input_span(et, et_len, "et"));
    const auto proof = vole_backend::prove(
        cached.prepared, cached.relation.level(), profile_from_c(profile),
        cached.relation.private_bits(sk_span), statement,
        input_span(context, context_len, "context"),
        prover_randomness(randomness, randomness_len));
    return write_proof(proof, proof_out, proof_len);
  } catch (const std::invalid_argument& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  } catch (...) {
    last_error = "unknown TPM SHA failure";
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

int daa_tpm_sha_join_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* gid, size_t gid_len,
    const uint8_t* et, size_t et_len, const uint8_t* context,
    size_t context_len, const uint8_t* proof, size_t proof_len) {
  last_error.clear();
  try {
    auto& cached = join_cache(level);
    const auto statement = join_statement(
        cached.relation, input_span(gid, gid_len, "gid"),
        input_span(et, et_len, "et"));
    const bool valid = vole_backend::verify(
        cached.prepared, cached.relation.level(), profile_from_c(profile),
        statement, input_span(context, context_len, "context"),
        input_span(proof, proof_len, "proof"));
    if (!valid) last_error = "invalid TPM SHA Join proof";
    return valid ? DAA_TPM_SHA_OK : DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::invalid_argument& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

int daa_tpm_sha_sign_prove(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* s, size_t s_len, const uint8_t* lid, size_t lid_len,
    const uint8_t* gid, size_t gid_len, const uint8_t* slt, size_t slt_len,
    const uint8_t* hk, size_t hk_len, const uint8_t* context,
    size_t context_len, const uint8_t* randomness, size_t randomness_len,
    uint8_t* proof_out, size_t* proof_len) {
  last_error.clear();
  try {
    auto& cached = sign_cache(level);
    const auto statement = sign_statement(
        cached.relation, input_span(lid, lid_len, "lid"),
        input_span(gid, gid_len, "gid"), input_span(slt, slt_len, "slt"),
        input_span(hk, hk_len, "hk"));
    const auto proof = vole_backend::prove(
        cached.prepared, cached.relation.level(), profile_from_c(profile),
        cached.relation.private_bits(input_span(sk, sk_len, "sk"),
                                     input_span(s, s_len, "s")),
        statement, input_span(context, context_len, "context"),
        prover_randomness(randomness, randomness_len));
    return write_proof(proof, proof_out, proof_len);
  } catch (const std::invalid_argument& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  } catch (...) {
    last_error = "unknown TPM SHA failure";
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

int daa_tpm_sha_sign_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    const uint8_t* lid, size_t lid_len,
    const uint8_t* gid, size_t gid_len, const uint8_t* slt, size_t slt_len,
    const uint8_t* hk, size_t hk_len, const uint8_t* context,
    size_t context_len, const uint8_t* proof, size_t proof_len) {
  last_error.clear();
  try {
    auto& cached = sign_cache(level);
    const auto statement = sign_statement(
        cached.relation, input_span(lid, lid_len, "lid"),
        input_span(gid, gid_len, "gid"), input_span(slt, slt_len, "slt"),
        input_span(hk, hk_len, "hk"));
    const bool valid = vole_backend::verify(
        cached.prepared, cached.relation.level(), profile_from_c(profile),
        statement, input_span(context, context_len, "context"),
        input_span(proof, proof_len, "proof"));
    if (!valid) last_error = "invalid TPM SHA signing proof";
    return valid ? DAA_TPM_SHA_OK : DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::invalid_argument& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

const char* daa_tpm_sha_last_error(void) { return last_error.c_str(); }

} // extern "C"
