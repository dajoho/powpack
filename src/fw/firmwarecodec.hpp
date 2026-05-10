/**
 * @file firmwarecodec.hpp
 * @brief Declares the internal codec used to inspect and extract Actions `.fw`
 * firmware containers.
 */

#pragma once

#include <filesystem>
#include <vector>

#include "teampandory/powpack/powpack.hpp"

namespace teampandory::powpack::detail {

class FirmwareCodec {
   public:
    [[nodiscard]] std::vector<FirmwareEntry> inspectFirmware(const std::filesystem::path &source) const;

    void extractFirmware(const std::filesystem::path &source, const std::filesystem::path &outputDirectory) const;

    void packFirmware(const std::filesystem::path &sourceDirectory, const std::filesystem::path &destination) const;
};

}  // namespace teampandory::powpack::detail
