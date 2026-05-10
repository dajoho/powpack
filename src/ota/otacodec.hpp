/**
 * @file otacodec.hpp
 * @brief Declares the internal codec used to inspect and extract PowKiddy
 * `PATO` OTA containers.
 */

#pragma once

#include <filesystem>
#include <vector>

#include "teampandory/powpack/powpack.hpp"

namespace teampandory::powpack::detail {

class OtaCodec {
   public:
    [[nodiscard]] std::vector<OtaEntry> inspectOta(const std::filesystem::path &source) const;

    void extractOta(const std::filesystem::path &source, const std::filesystem::path &outputDirectory) const;

    void packOta(const std::filesystem::path &sourceDirectory, const std::filesystem::path &destination) const;
};

}  // namespace teampandory::powpack::detail
