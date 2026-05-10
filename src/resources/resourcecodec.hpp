/**
 * @file resourcecodec.hpp
 * @brief Declares the internal codec used to inspect, extract, and repack
 * Actions `.res` and `.str` resource files.
 */

#pragma once

#include <filesystem>
#include <vector>

#include "teampandory/powpack/powpack.hpp"

namespace teampandory::powpack::detail {

class ResourceCodec {
   public:
    [[nodiscard]] std::vector<ResourceEntry> inspectResource(const std::filesystem::path &source) const;

    void extractResource(const std::filesystem::path &source, const std::filesystem::path &outputDirectory) const;

    void packResource(const std::filesystem::path &sourceDirectory, const std::filesystem::path &destination) const;
};

}  // namespace teampandory::powpack::detail
