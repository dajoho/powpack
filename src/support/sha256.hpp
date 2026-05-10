/**
 * @file sha256.hpp
 * @brief Declares a small in-tree SHA-256 helper used to avoid external
 * crypto dependencies during cross-builds.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace teampandory::powpack::detail {

[[nodiscard]] std::string sha256Hex(const std::vector<std::uint8_t> &data);

}  // namespace teampandory::powpack::detail
