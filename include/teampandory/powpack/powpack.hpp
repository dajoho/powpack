/**
 * @file powpack.hpp
 * @brief Declares the public powpack API for inspecting and extracting
 * Actions/PowKiddy `.fw` and OTA `update.zip` containers.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace teampandory::powpack {

enum class ContainerFormat {
    firmware,
    ota,
    resourceRes,
    resourceStr,
};

struct FirmwareEntry {
    std::string name;
    std::string filesystem;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;

    [[nodiscard]] std::string outputFileName() const;
};

struct OtaEntry {
    std::string name;
    std::uint8_t flag = 0;
    std::uint8_t partition = 0;
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
    std::uint32_t crc = 0;

    [[nodiscard]] std::string outputFileName() const;
};

struct AnalysedEntry {
    std::string file_name;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::string sha256;
    std::string type;
    std::uint32_t crc = 0;
    std::uint8_t partition = 0;
};

struct ResourceEntry {
    std::string name;
    std::uint32_t offset = 0;
    std::uint16_t size = 0;
    std::uint8_t type = 0;
    std::string type_name;

    [[nodiscard]] std::string defaultExportName() const;
};

struct ArchiveAnalysis {
    ContainerFormat format = ContainerFormat::firmware;
    std::string container_name;
    std::uint64_t file_size = 0;
    std::string sha256;
    std::optional<std::string> version;
    std::optional<std::string> kernel_string;
    std::optional<std::string> uenv_text;
    std::vector<std::string> boot_files;
    std::vector<AnalysedEntry> entries;
};

class ArchiveTool {
   public:
    [[nodiscard]] ContainerFormat detectFormat(const std::filesystem::path &source) const;

    [[nodiscard]] std::vector<FirmwareEntry> inspectFirmware(const std::filesystem::path &source) const;

    void extractFirmware(const std::filesystem::path &source, const std::filesystem::path &outputDirectory) const;

    void packFirmware(const std::filesystem::path &sourceDirectory, const std::filesystem::path &destination) const;

    [[nodiscard]] std::vector<OtaEntry> inspectOta(const std::filesystem::path &source) const;

    void extractOta(const std::filesystem::path &source, const std::filesystem::path &outputDirectory) const;

    void packOta(const std::filesystem::path &sourceDirectory, const std::filesystem::path &destination) const;

    [[nodiscard]] std::vector<ResourceEntry> inspectResource(const std::filesystem::path &source) const;

    void extractResource(const std::filesystem::path &source, const std::filesystem::path &outputDirectory) const;

    void packResource(const std::filesystem::path &sourceDirectory, const std::filesystem::path &destination) const;

    [[nodiscard]] ArchiveAnalysis inspectArchive(const std::filesystem::path &source) const;
};

}  // namespace teampandory::powpack
