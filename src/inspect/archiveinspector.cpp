/**
 * @file archiveinspector.cpp
 * @brief Implements shallow archive analysis for `.fw` and `PATO` OTA
 * containers, including hashes and boot partition inspection.
 */

#include "inspect/archiveinspector.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "io/filesystemsupport.hpp"
#include "resources/resourcecodec.hpp"
#include "support/sha256.hpp"
#include "support/exceptionsupport.hpp"
#include "teampandory/powpack/powpack.hpp"

namespace fs = std::filesystem;

namespace teampandory::powpack {

ArchiveAnalysis ArchiveTool::inspectArchive(const fs::path &source) const {
    return detail::ArchiveInspector{}.inspectArchive(source);
}

}  // namespace teampandory::powpack

namespace teampandory::powpack::detail {
namespace {

constexpr std::uint8_t fatLongFileNameAttr = 0x0f;
constexpr std::uint8_t fatVolumeLabelAttr = 0x08;

struct FatFileEntry {
    std::string name;
    std::uint16_t cluster = 0;
    std::uint32_t size = 0;
};

std::string sha256HexForSlice(const std::vector<std::uint8_t> &data, std::size_t offset, std::size_t size) {
    if (offset + size > data.size()) {
        raiseRuntimeError("slice exceeds buffer during sha256");
    }
    return sha256Hex(std::vector<std::uint8_t>(data.begin() + static_cast<std::ptrdiff_t>(offset),
                                               data.begin() + static_cast<std::ptrdiff_t>(offset + size)));
}

std::string trimRight(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.pop_back();
    }
    return value;
}

std::vector<FatFileEntry> parseFat16Root(const std::vector<std::uint8_t> &bytes) {
    const auto bytesPerSector = FileSystemSupport::readU32Le(bytes, 11) & 0xffffU;
    const auto sectorsPerCluster = bytes[13];
    const auto reservedSectors = FileSystemSupport::readU32Le(bytes, 14) & 0xffffU;
    const auto fatsCount = bytes[16];
    const auto rootEntries = FileSystemSupport::readU32Le(bytes, 17) & 0xffffU;
    const auto sectorsPerFat = FileSystemSupport::readU32Le(bytes, 22) & 0xffffU;

    const std::size_t rootOffset = static_cast<std::size_t>(reservedSectors + fatsCount * sectorsPerFat) * bytesPerSector;
    const std::size_t rootBytes = static_cast<std::size_t>(rootEntries) * 32;
    if (rootOffset + rootBytes > bytes.size()) {
        raiseRuntimeError("FAT16 root directory exceeds image size");
    }

    std::vector<FatFileEntry> files;
    for (std::size_t offset = rootOffset; offset < rootOffset + rootBytes; offset += 32) {
        const auto firstByte = bytes[offset];
        if (firstByte == 0x00) {
            break;
        }
        if (firstByte == 0xe5) {
            continue;
        }

        const auto attr = bytes[offset + 11];
        if (attr == fatLongFileNameAttr || (attr & fatVolumeLabelAttr) != 0) {
            continue;
        }

        auto base = FileSystemSupport::readFixedString(bytes, offset, 8);
        auto ext = FileSystemSupport::readFixedString(bytes, offset + 8, 3);
        base = trimRight(base);
        ext = trimRight(ext);

        FatFileEntry file;
        file.name = ext.empty() ? base : base + "." + ext;
        file.cluster = static_cast<std::uint16_t>(FileSystemSupport::readU32Le(bytes, offset + 26) & 0xffffU);
        file.size = FileSystemSupport::readU32Le(bytes, offset + 28);
        files.push_back(std::move(file));
    }

    return files;
}

std::vector<std::uint8_t> readFat16File(const std::vector<std::uint8_t> &bytes, const FatFileEntry &entry) {
    const auto bytesPerSector = FileSystemSupport::readU32Le(bytes, 11) & 0xffffU;
    const auto sectorsPerCluster = bytes[13];
    const auto reservedSectors = FileSystemSupport::readU32Le(bytes, 14) & 0xffffU;
    const auto fatsCount = bytes[16];
    const auto rootEntries = FileSystemSupport::readU32Le(bytes, 17) & 0xffffU;
    const auto sectorsPerFat = FileSystemSupport::readU32Le(bytes, 22) & 0xffffU;

    const std::size_t fatOffset = static_cast<std::size_t>(reservedSectors) * bytesPerSector;
    const std::size_t rootSectors = (static_cast<std::size_t>(rootEntries) * 32 + (bytesPerSector - 1)) / bytesPerSector;
    const std::size_t dataOffset =
        static_cast<std::size_t>(reservedSectors + fatsCount * sectorsPerFat + rootSectors) * bytesPerSector;
    const std::size_t clusterSize = static_cast<std::size_t>(bytesPerSector) * sectorsPerCluster;

    std::vector<std::uint8_t> output;
    output.reserve(entry.size);

    std::uint16_t cluster = entry.cluster;
    while (cluster >= 2 && cluster < 0xfff8 && output.size() < entry.size) {
        const std::size_t clusterOffset = dataOffset + static_cast<std::size_t>(cluster - 2) * clusterSize;
        if (clusterOffset + clusterSize > bytes.size()) {
            raiseRuntimeError("FAT16 cluster exceeds image size");
        }

        const auto bytesToCopy = std::min(clusterSize, static_cast<std::size_t>(entry.size) - output.size());
        output.insert(output.end(), bytes.begin() + static_cast<std::ptrdiff_t>(clusterOffset),
                      bytes.begin() + static_cast<std::ptrdiff_t>(clusterOffset + bytesToCopy));

        const std::size_t fatEntryOffset = fatOffset + static_cast<std::size_t>(cluster) * 2;
        if (fatEntryOffset + 2 > bytes.size()) {
            raiseRuntimeError("FAT16 chain entry exceeds image size");
        }
        cluster = static_cast<std::uint16_t>(FileSystemSupport::readU32Le(bytes, fatEntryOffset) & 0xffffU);
    }

    if (output.size() != entry.size) {
        raiseRuntimeError("FAT16 file read size mismatch");
    }
    return output;
}

std::optional<std::string> findKernelString(const std::vector<std::uint8_t> &bytes) {
    const std::string_view marker = "Linux-";
    for (std::size_t offset = 0; offset + marker.size() <= bytes.size(); ++offset) {
        if (std::equal(marker.begin(), marker.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset))) {
            std::string result;
            for (std::size_t pos = offset; pos < bytes.size(); ++pos) {
                const unsigned char ch = bytes[pos];
                if (ch == 0 || ch == '\n' || ch == '\r') {
                    break;
                }
                if (std::isprint(ch) == 0) {
                    break;
                }
                result.push_back(static_cast<char>(ch));
            }
            if (!result.empty()) {
                return result;
            }
        }
    }
    return std::nullopt;
}

void inspectBootPartition(const std::vector<std::uint8_t> &partitionBytes, ArchiveAnalysis &analysis) {
    const auto files = parseFat16Root(partitionBytes);
    std::map<std::string, FatFileEntry> fileMap;
    analysis.boot_files.clear();
    for (const auto &file : files) {
        analysis.boot_files.push_back(file.name);
        fileMap.emplace(file.name, file);
    }

    if (const auto iterator = fileMap.find("UENV.TXT"); iterator != fileMap.end()) {
        const auto uenvBytes = readFat16File(partitionBytes, iterator->second);
        auto uenv = std::string(reinterpret_cast<const char *>(uenvBytes.data()), uenvBytes.size());
        analysis.uenv_text = trimRight(uenv);
    }

    if (const auto iterator = fileMap.find("UIMAGE"); iterator != fileMap.end()) {
        const auto uimage = readFat16File(partitionBytes, iterator->second);
        analysis.kernel_string = findKernelString(uimage);
    }
}

}  // namespace

ArchiveAnalysis ArchiveInspector::inspectArchive(const fs::path &source) const {
    ArchiveTool archiveTool;
    const auto bytes = FileSystemSupport::readFile(source);

    ArchiveAnalysis analysis;
    analysis.container_name = source.filename().string();
    analysis.file_size = bytes.size();
    analysis.sha256 = sha256Hex(bytes);
    analysis.format = archiveTool.detectFormat(source);

    if (analysis.format == ContainerFormat::firmware) {
        const auto entries = archiveTool.inspectFirmware(source);
        for (const auto &entry : entries) {
            analysis.entries.push_back(AnalysedEntry{
                .file_name = entry.outputFileName(),
                .offset = entry.offset,
                .size = entry.size,
                .sha256 = sha256HexForSlice(bytes, static_cast<std::size_t>(entry.offset), static_cast<std::size_t>(entry.size)),
                .type = "FW",
                .crc = 0,
                .partition = 0,
            });

            if (entry.name == "MISC" && entry.filesystem == "FAT16") {
                const auto miscBytes = std::vector<std::uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset),
                                                                 bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset + entry.size));
                inspectBootPartition(miscBytes, analysis);
            }
        }
        return analysis;
    }

    if (analysis.format == ContainerFormat::resourceRes || analysis.format == ContainerFormat::resourceStr) {
        const auto entries = ArchiveTool{}.inspectResource(source);
        for (const auto &entry : entries) {
            analysis.entries.push_back(AnalysedEntry{
                .file_name = entry.defaultExportName(),
                .offset = entry.offset,
                .size = entry.size,
                .sha256 = sha256HexForSlice(bytes, entry.offset, entry.size),
                .type = entry.type_name,
                .crc = 0,
                .partition = 0,
            });
        }
        return analysis;
    }

    const auto version = FileSystemSupport::readFixedString(bytes, 4, 56);
    analysis.version = version;

    const auto entries = archiveTool.inspectOta(source);
    for (const auto &entry : entries) {
        analysis.entries.push_back(AnalysedEntry{
            .file_name = entry.outputFileName(),
            .offset = entry.offset,
            .size = entry.size,
            .sha256 = sha256HexForSlice(bytes, entry.offset, entry.size),
            .type = entry.flag != 0 ? "RAW" : "IMG",
            .crc = entry.crc,
            .partition = entry.partition,
        });

        if (entry.name == "misc.img" && entry.partition == 0) {
            const auto miscBytes = std::vector<std::uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset),
                                                             bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset + entry.size));
            inspectBootPartition(miscBytes, analysis);
        }
    }

    return analysis;
}

}  // namespace teampandory::powpack::detail
