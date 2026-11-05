/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_BIT_MATRIX_TRANSPOSE_HPP
#define VOLE_BACKEND_BIT_MATRIX_TRANSPOSE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace vole_backend {

void transpose_64x64(std::array<std::uint64_t, 64>& block);

void transpose_column_block(
    std::span<std::uint8_t* const> columns, std::size_t row_offset,
    std::size_t row_count, std::span<std::uint8_t> packed_rows,
    std::size_t row_stride);

}

#endif
