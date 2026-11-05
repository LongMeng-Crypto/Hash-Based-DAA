/* SPDX-License-Identifier: MIT */

#include "quicksilver.hpp"

namespace vole_backend::quicksilver {

// Implements authenticate.
VerifierWire authenticate(const ProverWire& wire, const Gf128& delta) {
  return {wire.tag + delta * Gf128::from_bit(wire.value)};
}

// Implements public constant.
VerifierWire public_constant(bool value, const Gf128& delta) {
  return {delta * Gf128::from_bit(value)};
}

// Implements multiplication constraint.
Polynomial multiplication_constraint(const ProverWire& x, const ProverWire& y,
                                     const ProverWire& z) {

  return {
      x.tag * y.tag,
      x.tag * Gf128::from_bit(y.value) + y.tag * Gf128::from_bit(x.value) + z.tag,
      Gf128::from_bit((x.value && y.value) != z.value),
  };
}

// Implements multiplication constraint.
Gf128 multiplication_constraint(const VerifierWire& x, const VerifierWire& y,
                                const VerifierWire& z, const Gf128& delta) {
  return x.key * y.key + delta * z.key;
}

// Implements linear constraint.
Polynomial linear_constraint(const ProverWire& x, bool public_bit) {

  return {{}, x.tag, Gf128::from_bit(x.value != public_bit)};
}

// Implements linear constraint.
Gf128 linear_constraint(const VerifierWire& x, bool public_bit, const Gf128& delta) {
  return delta * (x.key + delta * Gf128::from_bit(public_bit));
}

// Implements evaluate proof.
Gf128 evaluate_proof(const Polynomial& polynomial, const Gf128& delta) {
  return polynomial.degree0 + delta * polynomial.degree1;
}

// Implements evaluate full.
Gf128 evaluate_full(const Polynomial& polynomial, const Gf128& delta) {
  return evaluate_proof(polynomial, delta) + (delta * delta) * polynomial.degree2;
}

void ProverAccumulator::update(const Polynomial& constraint) {
  aggregate_.degree0 += weight_ * constraint.degree0;
  aggregate_.degree1 += weight_ * constraint.degree1;
  aggregate_.degree2 += weight_ * constraint.degree2;
  weight_ = weight_ * challenge_;
  ++constraints_;
}

void VerifierAccumulator::update(const Gf128& constraint_evaluation) {
  aggregate_ += weight_ * constraint_evaluation;
  weight_ = weight_ * challenge_;
  ++constraints_;
}

}
