/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_QUICKSILVER_HPP
#define VOLE_BACKEND_QUICKSILVER_HPP

#include "gf128.hpp"

#include <cstddef>
#include <cstdint>

namespace vole_backend::quicksilver {

struct ProverWire {
  bool value;
  Gf128 tag;
};

struct VerifierWire {
  Gf128 key;
};

VerifierWire authenticate(const ProverWire& wire, const Gf128& delta);
VerifierWire public_constant(bool value, const Gf128& delta);

struct Polynomial {
  Gf128 degree0{};
  Gf128 degree1{};
  Gf128 degree2{};
};

Polynomial multiplication_constraint(const ProverWire& x, const ProverWire& y,
                                     const ProverWire& z);

Gf128 multiplication_constraint(const VerifierWire& x, const VerifierWire& y,
                                const VerifierWire& z, const Gf128& delta);

Polynomial linear_constraint(const ProverWire& x, bool public_bit);
Gf128 linear_constraint(const VerifierWire& x, bool public_bit, const Gf128& delta);

Gf128 evaluate_proof(const Polynomial& polynomial, const Gf128& delta);
Gf128 evaluate_full(const Polynomial& polynomial, const Gf128& delta);

class ProverAccumulator {
public:
  // Implements prover accumulator.
  explicit ProverAccumulator(Gf128 challenge) : challenge_(challenge) {}
  void update(const Polynomial& constraint);
  const Polynomial& polynomial() const { return aggregate_; }
  std::size_t constraints() const { return constraints_; }

private:
  Gf128 challenge_;
  Gf128 weight_ = Gf128::from_bit(true);
  Polynomial aggregate_{};
  std::size_t constraints_ = 0;
};

class VerifierAccumulator {
public:
  // Implements verifier accumulator.
  explicit VerifierAccumulator(Gf128 challenge) : challenge_(challenge) {}
  void update(const Gf128& constraint_evaluation);
  const Gf128& evaluation() const { return aggregate_; }
  std::size_t constraints() const { return constraints_; }

private:
  Gf128 challenge_;
  Gf128 weight_ = Gf128::from_bit(true);
  Gf128 aggregate_{};
  std::size_t constraints_ = 0;
};

}

#endif
