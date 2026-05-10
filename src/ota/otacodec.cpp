/**
 * @file otacodec.cpp
 * @brief Implements parsing and extraction for PowKiddy `PATO` OTA
 * `update.zip` containers.
 */

#include "ota/otacodec.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "io/filesystemsupport.hpp"
#include "support/exceptionsupport.hpp"

namespace fs = std::filesystem;

namespace teampandory::powpack {

std::string OtaEntry::outputFileName() const {
    if (flag != 0) {
        return "RAW." + std::to_string(partition) + "." + name;
    }
    return std::to_string(partition) + "." + name;
}

ContainerFormat ArchiveTool::detectFormat(const fs::path &source) const {
    const auto bytes = detail::FileSystemSupport::readFile(source);
    if (bytes.size() < 4) {
        detail::raiseRuntimeError("file too small to detect format: " + source.string());
    }

    if (bytes.size() >= 16) {
        const auto magic = detail::FileSystemSupport::readFixedString(bytes, 0, 16);
        if (magic.rfind("WFDNUOPMOCSTCA", 0) == 0) {
            return ContainerFormat::firmware;
        }
    }

    const auto magic4 = detail::FileSystemSupport::readFixedString(bytes, 0, 4);
    if (magic4 == "PATO") {
        return ContainerFormat::ota;
    }

    const auto magic3 = detail::FileSystemSupport::readFixedString(bytes, 0, 3);
    if (magic3 == "RES") {
        if (source.extension() == ".str") {
            return ContainerFormat::resourceStr;
        }
        return ContainerFormat::resourceRes;
    }

    detail::raiseRuntimeError("unsupported container format: " + source.string());
}

std::vector<OtaEntry> ArchiveTool::inspectOta(const fs::path &source) const {
    return detail::OtaCodec{}.inspectOta(source);
}

void ArchiveTool::extractOta(const fs::path &source, const fs::path &outputDirectory) const {
    detail::OtaCodec{}.extractOta(source, outputDirectory);
}

void ArchiveTool::packOta(const fs::path &sourceDirectory, const fs::path &destination) const {
    detail::OtaCodec{}.packOta(sourceDirectory, destination);
}

}  // namespace teampandory::powpack

namespace teampandory::powpack::detail {
namespace {

constexpr std::size_t blockSize = 512;
constexpr std::size_t headerSize = 2048;
constexpr std::size_t itemSize = 64;
constexpr std::size_t versionLength = 56;
constexpr std::string_view otaMagic = "PATO";
constexpr std::string_view metadataFileName = ".powpack-ota.meta";

std::uint32_t checksumWords(const std::vector<std::uint8_t> &data) {
    if (data.size() % 4 != 0) {
        raiseRuntimeError("checksum requires 4-byte aligned buffer");
    }

    std::uint64_t checksum = 0;
    for (std::size_t offset = 0; offset < data.size(); offset += 4) {
        checksum += FileSystemSupport::readU32Le(data, offset);
    }
    return static_cast<std::uint32_t>(checksum & 0xffffffffU);
}

std::string readVersion(const std::vector<std::uint8_t> &bytes) {
    return FileSystemSupport::readFixedString(bytes, 4, versionLength);
}

std::vector<OtaEntry> parseEntries(const std::vector<std::uint8_t> &bytes, const fs::path &source) {
    if (bytes.size() < headerSize) {
        raiseRuntimeError("file too small for OTA header: " + source.string());
    }

    const auto magic = FileSystemSupport::readFixedString(bytes, 0, 4);
    if (magic != otaMagic) {
        raiseRuntimeError("unsupported OTA magic in " + source.string());
    }

    std::vector<std::uint8_t> header(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(headerSize - 4));
    const auto expectedHeaderChecksum = FileSystemSupport::readU32Le(bytes, headerSize - 4);
    const auto actualHeaderChecksum = checksumWords(header);
    if (expectedHeaderChecksum != actualHeaderChecksum) {
        raiseRuntimeError("wrong OTA header checksum in " + source.string());
    }

    const auto itemsCount = FileSystemSupport::readU32Le(bytes, 60);
    const auto tableEnd = 64U + itemsCount * itemSize;
    if (tableEnd > headerSize - 4) {
        raiseRuntimeError("OTA entry table exceeds header bounds in " + source.string());
    }

    std::vector<OtaEntry> entries;
    entries.reserve(itemsCount);

    for (std::size_t index = 0; index < itemsCount; ++index) {
        const auto entryOffset = 64 + index * itemSize;
        OtaEntry entry;
        entry.name = FileSystemSupport::readFixedString(bytes, entryOffset, 32);
        entry.flag = bytes[entryOffset + 32];
        entry.partition = bytes[entryOffset + 33];
        entry.size = FileSystemSupport::readU32Le(bytes, entryOffset + 36) * blockSize;
        entry.offset = FileSystemSupport::readU32Le(bytes, entryOffset + 40) * blockSize;
        entry.crc = FileSystemSupport::readU32Le(bytes, entryOffset + 44);

        if (entry.name.empty()) {
            raiseRuntimeError("invalid empty OTA entry name in " + source.string());
        }
        if (entry.offset + entry.size > bytes.size()) {
            raiseRuntimeError("OTA entry extends past end of file in " + source.string() + ": " + entry.outputFileName());
        }

        const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset);
        const auto end = begin + static_cast<std::ptrdiff_t>(entry.size);
        const auto payload = std::vector<std::uint8_t>(begin, end);
        const auto crc = checksumWords(payload);
        if (crc != entry.crc) {
            raiseRuntimeError("wrong OTA payload checksum in " + source.string() + ": " + entry.outputFileName());
        }

        entries.push_back(std::move(entry));
    }

    return entries;
}

std::size_t preferredOrder(const OtaEntry &entry) {
    if (entry.name == "uboot.bin" && entry.flag == 1 && entry.partition == 1) {
        return 0;
    }
    if (entry.name == "misc.img" && entry.flag == 0 && entry.partition == 0) {
        return 1;
    }
    if (entry.name == "recovery.img" && entry.flag == 0 && entry.partition == 1) {
        return 2;
    }
    if (entry.name == "system.img" && entry.flag == 0 && entry.partition == 3) {
        return 3;
    }
    if (entry.name == "res.img" && entry.flag == 0 && entry.partition == 5) {
        return 4;
    }
    return 100;
}

OtaEntry parseExtractedFileName(const fs::path &path) {
    const auto fileName = path.filename().string();
    OtaEntry entry;

    if (fileName.rfind("RAW.", 0) == 0) {
        const auto firstDot = fileName.find('.', 4);
        if (firstDot == std::string::npos || firstDot == 4 || firstDot + 1 >= fileName.size()) {
            raiseRuntimeError("could not parse RAW OTA payload file name: " + path.string());
        }
        entry.flag = 1;
        entry.partition = static_cast<std::uint8_t>(std::stoul(fileName.substr(4, firstDot - 4)));
        entry.name = fileName.substr(firstDot + 1);
    } else {
        const auto firstDot = fileName.find('.');
        if (firstDot == std::string::npos || firstDot == 0 || firstDot + 1 >= fileName.size()) {
            raiseRuntimeError("could not parse OTA payload file name: " + path.string());
        }
        entry.flag = 0;
        entry.partition = static_cast<std::uint8_t>(std::stoul(fileName.substr(0, firstDot)));
        entry.name = fileName.substr(firstDot + 1);
    }

    entry.size = static_cast<std::uint32_t>(fs::file_size(path));
    if (entry.size < blockSize || (entry.size % blockSize) != 0) {
        raiseRuntimeError("OTA payload must be a multiple of 512 bytes: " + path.string());
    }
    return entry;
}

std::optional<OtaEntry> tryParseExtractedFileName(const fs::path &path) {
    const auto fileName = path.filename().string();
    if (fileName == metadataFileName) {
        return std::nullopt;
    }

    if (fileName.rfind("RAW.", 0) == 0) {
        const auto firstDot = fileName.find('.', 4);
        if (firstDot == std::string::npos || firstDot == 4 || firstDot + 1 >= fileName.size()) {
            return std::nullopt;
        }
        const auto partitionText = fileName.substr(4, firstDot - 4);
        if (partitionText.find_first_not_of("0123456789") != std::string::npos) {
            return std::nullopt;
        }
    } else {
        const auto firstDot = fileName.find('.');
        if (firstDot == std::string::npos || firstDot == 0 || firstDot + 1 >= fileName.size()) {
            return std::nullopt;
        }
        const auto partitionText = fileName.substr(0, firstDot);
        if (partitionText.find_first_not_of("0123456789") != std::string::npos) {
            return std::nullopt;
        }
    }

    return parseExtractedFileName(path);
}

std::string readMetadataVersion(const fs::path &sourceDirectory) {
    const fs::path metadataPath = sourceDirectory / metadataFileName;
    std::ifstream input(metadataPath);
    if (!input) {
        raiseRuntimeError("missing OTA metadata file: " + metadataPath.string());
    }

    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind("version=", 0) == 0) {
            return line.substr(8);
        }
    }

    raiseRuntimeError("missing version= line in OTA metadata: " + metadataPath.string());
}

void writeMetadata(const fs::path &outputDirectory, std::string_view version) {
    std::ofstream output(outputDirectory / metadataFileName, std::ios::binary);
    if (!output) {
        raiseRuntimeError("failed to write OTA metadata");
    }
    output << "format=ota\n";
    output << "version=" << version << '\n';
}

}  // namespace

std::vector<OtaEntry> OtaCodec::inspectOta(const fs::path &source) const {
    const auto bytes = FileSystemSupport::readFile(source);
    return parseEntries(bytes, source);
}

void OtaCodec::extractOta(const fs::path &source, const fs::path &outputDirectory) const {
    const auto bytes = FileSystemSupport::readFile(source);
    const auto entries = parseEntries(bytes, source);
    const auto version = readVersion(bytes);

    fs::create_directories(outputDirectory);
    writeMetadata(outputDirectory, version);

    for (const auto &entry : entries) {
        const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset);
        const auto end = begin + static_cast<std::ptrdiff_t>(entry.size);
        FileSystemSupport::writeFile(outputDirectory / entry.outputFileName(), std::vector<std::uint8_t>(begin, end));
    }
}

void OtaCodec::packOta(const fs::path &sourceDirectory, const fs::path &destination) const {
    if (!fs::is_directory(sourceDirectory)) {
        raiseRuntimeError("source is not a directory: " + sourceDirectory.string());
    }

    std::vector<OtaEntry> entries;
    for (const auto &directoryEntry : fs::directory_iterator(sourceDirectory)) {
        if (!directoryEntry.is_regular_file()) {
            continue;
        }
        const auto entry = tryParseExtractedFileName(directoryEntry.path());
        if (!entry.has_value()) {
            continue;
        }
        entries.push_back(std::move(*entry));
    }

    if (entries.empty()) {
        raiseRuntimeError("no OTA payload files found in " + sourceDirectory.string());
    }

    std::sort(entries.begin(), entries.end(), [](const OtaEntry &left, const OtaEntry &right) {
        const auto leftRank = preferredOrder(left);
        const auto rightRank = preferredOrder(right);
        if (leftRank != rightRank) {
            return leftRank < rightRank;
        }
        if (left.partition != right.partition) {
            return left.partition < right.partition;
        }
        if (left.flag != right.flag) {
            return left.flag < right.flag;
        }
        return left.name < right.name;
    });

    const auto version = readMetadataVersion(sourceDirectory);
    std::uint32_t nextOffset = headerSize;
    for (auto &entry : entries) {
        entry.offset = nextOffset;
        const auto payload = FileSystemSupport::readFile(sourceDirectory / entry.outputFileName());
        entry.crc = checksumWords(payload);
        nextOffset += entry.size;
    }

    std::vector<std::uint8_t> output;
    output.reserve(nextOffset);
    FileSystemSupport::appendFixedString(output, std::string(otaMagic), 4);
    FileSystemSupport::appendFixedString(output, version, versionLength);
    FileSystemSupport::appendU32Le(output, static_cast<std::uint32_t>(entries.size()));

    for (const auto &entry : entries) {
        FileSystemSupport::appendFixedString(output, entry.name, 32);
        output.push_back(entry.flag);
        output.push_back(entry.partition);
        output.push_back(0);
        output.push_back(0);
        FileSystemSupport::appendU32Le(output, entry.size / blockSize);
        FileSystemSupport::appendU32Le(output, entry.offset / blockSize);
        FileSystemSupport::appendU32Le(output, entry.crc);
        output.insert(output.end(), 16, static_cast<std::uint8_t>(0));
    }

    if (output.size() > headerSize - 4) {
        raiseRuntimeError("OTA header table too large");
    }
    output.insert(output.end(), (headerSize - 4) - output.size(), static_cast<std::uint8_t>(0));
    const auto headerChecksum = checksumWords(output);
    FileSystemSupport::appendU32Le(output, headerChecksum);

    for (const auto &entry : entries) {
        const auto payload = FileSystemSupport::readFile(sourceDirectory / entry.outputFileName());
        output.insert(output.end(), payload.begin(), payload.end());
    }

    FileSystemSupport::writeFile(destination, output);
}

}  // namespace teampandory::powpack::detail
