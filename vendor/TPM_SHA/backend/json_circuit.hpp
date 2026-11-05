/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_JSON_CIRCUIT_HPP
#define VOLE_BACKEND_JSON_CIRCUIT_HPP

#include "binary_circuit.hpp"

#include <string_view>

namespace vole_backend {

BinaryCircuit compile_json_circuit(std::string_view json);

}

#endif
