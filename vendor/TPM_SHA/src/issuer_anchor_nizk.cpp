/* SPDX-License-Identifier: MIT */

#include "issuer_anchor_nizk.h"

#include "backend/generic_nizk.hpp"
#include "backend/prepared_binary_circuit.hpp"
#include "issuer_anchor_relation.hpp"

#include <algorithm>
#include <exception>
#include <span>
#include <stdexcept>
#include <string>

namespace {

thread_local std::string anchor_last_error;

// Converts the stable C security-level enum into the backend type.
vole_backend::SecurityLevel level_from_c(daa_tpm_sha_level level) {
  switch (level) {
  case DAA_TPM_SHA_128: return vole_backend::SecurityLevel::Bits128;
  case DAA_TPM_SHA_192: return vole_backend::SecurityLevel::Bits192;
  case DAA_TPM_SHA_256: return vole_backend::SecurityLevel::Bits256;
  }
  throw std::invalid_argument("invalid issuer-anchor security level");
}

// Converts the stable C profile enum into the backend type.
vole_backend::VoleProfile profile_from_c(daa_tpm_sha_profile profile) {
  switch (profile) {
  case DAA_TPM_SHA_SMALL: return vole_backend::VoleProfile::Small;
  case DAA_TPM_SHA_FAST: return vole_backend::VoleProfile::Fast;
  }
  throw std::invalid_argument("invalid issuer-anchor VOLE profile");
}

// Converts the stable C credential-kind enum into the relation type.
daa::issuer_anchor::Kind kind_from_c(daa_issuer_anchor_kind kind) {
  switch (kind) {
  case DAA_ISSUER_ANCHOR_SPHINCS: return daa::issuer_anchor::Kind::Sphincs;
  case DAA_ISSUER_ANCHOR_FSPHINCS: return daa::issuer_anchor::Kind::FSphincs;
  }
  throw std::invalid_argument("invalid issuer-anchor credential kind");
}

// Owns one immutable relation and its prepared VOLEith circuit.
struct CachedRelation {
  // Constructs and prepares one relation for reuse by all later proofs.
  CachedRelation(vole_backend::SecurityLevel level, daa::issuer_anchor::Kind kind)
      : relation(level, kind), prepared(relation.binary_circuit()) {}
  daa::issuer_anchor::Relation relation;
  vole_backend::PreparedBinaryCircuit prepared;
};

// Returns the process-wide prepared relation for one level and scheme.
CachedRelation& cache(daa_tpm_sha_level level, daa_issuer_anchor_kind kind) {
#define ANCHOR_CACHE_CASE(C_LEVEL, CPP_LEVEL, C_KIND, CPP_KIND, NAME)          \
  if (level == C_LEVEL && kind == C_KIND) {                                   \
    static CachedRelation NAME(vole_backend::SecurityLevel::CPP_LEVEL,         \
                               daa::issuer_anchor::Kind::CPP_KIND);            \
    return NAME;                                                               \
  }
  ANCHOR_CACHE_CASE(DAA_TPM_SHA_128, Bits128, DAA_ISSUER_ANCHOR_SPHINCS,
                    Sphincs, spx128)
  ANCHOR_CACHE_CASE(DAA_TPM_SHA_192, Bits192, DAA_ISSUER_ANCHOR_SPHINCS,
                    Sphincs, spx192)
  ANCHOR_CACHE_CASE(DAA_TPM_SHA_256, Bits256, DAA_ISSUER_ANCHOR_SPHINCS,
                    Sphincs, spx256)
  ANCHOR_CACHE_CASE(DAA_TPM_SHA_128, Bits128, DAA_ISSUER_ANCHOR_FSPHINCS,
                    FSphincs, fspx128)
  ANCHOR_CACHE_CASE(DAA_TPM_SHA_192, Bits192, DAA_ISSUER_ANCHOR_FSPHINCS,
                    FSphincs, fspx192)
  ANCHOR_CACHE_CASE(DAA_TPM_SHA_256, Bits256, DAA_ISSUER_ANCHOR_FSPHINCS,
                    FSphincs, fspx256)
#undef ANCHOR_CACHE_CASE
  static_cast<void>(level_from_c(level));
  static_cast<void>(kind_from_c(kind));
  throw std::invalid_argument("unsupported issuer-anchor relation");
}

// Validates a C byte pointer and exposes it as a read-only span.
std::span<const std::uint8_t> bytes(const std::uint8_t* pointer,
                                    std::size_t length, const char* name) {
  if (pointer == nullptr && length != 0)
    throw std::invalid_argument(std::string(name) + " is null");
  return {pointer, length};
}

// Parses exactly 32 bytes of caller-provided prover randomness.
vole_backend::ProverRandomness randomness(const std::uint8_t* pointer,
                                          std::size_t length) {
  const auto input = bytes(pointer, length, "randomness");
  vole_backend::ProverRandomness result{};
  if (input.size() != result.size())
    throw std::invalid_argument("randomness must be exactly 32 bytes");
  std::copy(input.begin(), input.end(), result.begin());
  return result;
}

// Builds the public VOLEith statement from relation fields and endpoints.
vole_backend::PublicStatement statement(
    const daa::issuer_anchor::Relation& relation,
    std::span<const std::uint8_t> public_a,
    std::span<const std::uint8_t> public_b,
    std::span<const std::uint8_t> anchor_value) {
  if (relation.kind() == daa::issuer_anchor::Kind::Sphincs &&
      public_b.size() == 44 &&
      std::equal(public_b.begin(), public_b.begin() + 22, public_b.begin() + 22))
    throw std::invalid_argument("SPHINCS+ anchors require distinct PRF addresses");
  return {relation.public_bits(public_a, public_b),
          relation.output_bits(anchor_value)};
}

// Copies a serialized proof into the caller's size-checked output buffer.
int write_proof(std::span<const std::uint8_t> proof, std::uint8_t* output,
                std::size_t* output_length) {
  if (output_length == nullptr) {
    anchor_last_error = "proof_len is null";
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  }
  const auto capacity = *output_length;
  *output_length = proof.size();
  if (output == nullptr || capacity < proof.size()) {
    anchor_last_error = "proof output buffer is too small";
    return DAA_TPM_SHA_BUFFER_TOO_SMALL;
  }
  std::copy(proof.begin(), proof.end(), output);
  return DAA_TPM_SHA_OK;
}

// Translates C++ exceptions into the stable C error interface.
template <typename Function>
int ffi(Function&& function) noexcept {
  anchor_last_error.clear();
  try {
    function();
    return DAA_TPM_SHA_OK;
  } catch (const std::invalid_argument& error) {
    anchor_last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    anchor_last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  } catch (...) {
    anchor_last_error = "unknown issuer-anchor failure";
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

} // namespace

extern "C" {

// Prepares and caches the requested issuer-anchor relation.
int daa_issuer_anchor_prepare(daa_tpm_sha_level level,
                              daa_tpm_sha_profile profile,
                              daa_issuer_anchor_kind kind) {
  return ffi([&] {
    static_cast<void>(profile_from_c(profile));
    static_cast<void>(cache(level, kind));
  });
}

// Returns circuit and serialized-proof statistics for one relation/profile.
int daa_issuer_anchor_stats(daa_tpm_sha_level level,
                            daa_tpm_sha_profile profile,
                            daa_issuer_anchor_kind kind,
                            daa_tpm_sha_stats* output) {
  return ffi([&] {
    if (output == nullptr) throw std::invalid_argument("stats_out is null");
    auto& cached = cache(level, kind);
    const auto stats = cached.prepared.statistics();
    output->private_input_bits = stats.private_inputs;
    output->public_input_bits = stats.public_inputs;
    output->output_bits = cached.relation.binary_circuit().outputs().size();
    output->and_gates = stats.multiplication_gates;
    output->xor_gates = stats.xor_gates;
    output->total_nodes = stats.total_nodes;
    output->proof_bytes = vole_backend::serialized_proof_bytes(
        cached.prepared, cached.relation.level(), profile_from_c(profile));
  });
}

// Returns the exact serialized proof length, or zero on invalid parameters.
size_t daa_issuer_anchor_proof_bytes(daa_tpm_sha_level level,
                                     daa_tpm_sha_profile profile,
                                     daa_issuer_anchor_kind kind) {
  daa_tpm_sha_stats stats{};
  return daa_issuer_anchor_stats(level, profile, kind, &stats) ==
                 DAA_TPM_SHA_OK
             ? stats.proof_bytes
             : 0;
}

// Produces a context-bound VOLEith proof of the seed-anchor relation.
int daa_issuer_anchor_prove(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    daa_issuer_anchor_kind kind, const uint8_t* seed, size_t seed_len,
    const uint8_t* public_a, size_t public_a_len,
    const uint8_t* public_b, size_t public_b_len,
    const uint8_t* anchor_value, size_t anchor_value_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* random, size_t random_len,
    uint8_t* proof_out, size_t* proof_len) {
  anchor_last_error.clear();
  try {
    auto& cached = cache(level, kind);
    const auto public_statement = statement(
        cached.relation, bytes(public_a, public_a_len, "public_a"),
        bytes(public_b, public_b_len, "public_b"),
        bytes(anchor_value, anchor_value_len, "anchor_value"));
    const auto proof = vole_backend::prove(
        cached.prepared, cached.relation.level(), profile_from_c(profile),
        cached.relation.private_bits(bytes(seed, seed_len, "seed")),
        public_statement, bytes(context, context_len, "context"),
        randomness(random, random_len));
    return write_proof(proof, proof_out, proof_len);
  } catch (const std::invalid_argument& error) {
    anchor_last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    anchor_last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

// Verifies a context-bound VOLEith proof against the public anchor statement.
int daa_issuer_anchor_verify(
    daa_tpm_sha_level level, daa_tpm_sha_profile profile,
    daa_issuer_anchor_kind kind,
    const uint8_t* public_a, size_t public_a_len,
    const uint8_t* public_b, size_t public_b_len,
    const uint8_t* anchor_value, size_t anchor_value_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* proof, size_t proof_len) {
  anchor_last_error.clear();
  try {
    auto& cached = cache(level, kind);
    const auto valid = vole_backend::verify(
        cached.prepared, cached.relation.level(), profile_from_c(profile),
        statement(cached.relation,
                  bytes(public_a, public_a_len, "public_a"),
                  bytes(public_b, public_b_len, "public_b"),
                  bytes(anchor_value, anchor_value_len, "anchor_value")),
        bytes(context, context_len, "context"),
        bytes(proof, proof_len, "proof"));
    if (!valid) anchor_last_error = "invalid issuer-anchor proof";
    return valid ? DAA_TPM_SHA_OK : DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::invalid_argument& error) {
    anchor_last_error = error.what();
    return DAA_TPM_SHA_INVALID_ARGUMENT;
  } catch (const std::exception& error) {
    anchor_last_error = error.what();
    return DAA_TPM_SHA_INTERNAL_ERROR;
  }
}

// Returns the thread-local diagnostic for the most recent C API call.
const char* daa_issuer_anchor_last_error(void) {
  return anchor_last_error.c_str();
}

} // extern "C"
