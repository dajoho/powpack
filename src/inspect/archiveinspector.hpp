/**
 * @file archiveinspector.hpp
 * @brief Declares archive analysis helpers for `powpack i`.
 */

#pragma once

#include <filesystem>

#include "teampandory/powpack/powpack.hpp"

namespace teampandory::powpack::detail {

class ArchiveInspector {
   public:
    [[nodiscard]] ArchiveAnalysis inspectArchive(const std::filesystem::path &source) const;
};

}  // namespace teampandory::powpack::detail
