/**
 * @file firmwarecodec.cpp
 * @brief Implements parsing and extraction for Actions `.fw` containers.
 */

#include "fw/firmwarecodec.hpp"

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "io/filesystemsupport.hpp"
#include "support/exceptionsupport.hpp"

namespace fs = std::filesystem;

namespace teampandory::powpack {

std::string FirmwareEntry::outputFileName() const {
    return name + "." + filesystem + ".bin";
}

std::vector<FirmwareEntry> ArchiveTool::inspectFirmware(const fs::path &source) const {
    return detail::FirmwareCodec{}.inspectFirmware(source);
}

void ArchiveTool::extractFirmware(const fs::path &source, const fs::path &outputDirectory) const {
    detail::FirmwareCodec{}.extractFirmware(source, outputDirectory);
}

void ArchiveTool::packFirmware(const fs::path &sourceDirectory, const fs::path &destination) const {
    detail::FirmwareCodec{}.packFirmware(sourceDirectory, destination);
}

}  // namespace teampandory::powpack

namespace teampandory::powpack::detail {
namespace {

constexpr std::size_t magicLength = 16;
constexpr std::size_t headerLength = 64;
constexpr std::size_t itemLength = 64;
constexpr std::uint64_t blockAlignment = 512;
constexpr std::size_t reserved1Length = 16;
constexpr std::size_t reserved2Length = 24;
constexpr std::string_view firmwareMagic = "WFDNUOPMOCSTCA";

std::size_t preferredOrder(const FirmwareEntry &entry) {
    if (entry.name == "FW" && entry.filesystem == "FW") {
        return 0;
    }
    if (entry.name == "MISC" && entry.filesystem == "FAT16") {
        return 1;
    }
    if (entry.name == "RECOVERY" && entry.filesystem == "FAT16") {
        return 2;
    }
    if (entry.name == "SYSTEM" && entry.filesystem == "squashfs") {
        return 3;
    }
    if (entry.name == "RES" && entry.filesystem == "squashfs") {
        return 4;
    }
    return 100;
}

std::uint64_t alignUp(std::uint64_t value, std::uint64_t alignment) {
    const auto remainder = value % alignment;
    if (remainder == 0) {
        return value;
    }
    return value + (alignment - remainder);
}

std::vector<FirmwareEntry> parseEntries(const std::vector<std::uint8_t> &bytes, const fs::path &source) {
    if (bytes.size() < 64) {
        raiseRuntimeError("file too small for .fw header: " + source.string());
    }

    const auto magic = FileSystemSupport::readFixedString(bytes, 0, magicLength);
    if (magic.rfind(firmwareMagic, 0) != 0) {
        raiseRuntimeError("unsupported firmware magic in " + source.string());
    }

    const auto headerSize = FileSystemSupport::readU32Le(bytes, 16);
    const auto itemsCount = FileSystemSupport::readU32Le(bytes, 36);

    if (headerSize > bytes.size()) {
        raiseRuntimeError("header size exceeds file length in " + source.string());
    }

    const std::size_t tableStart = 64;
    const std::size_t tableSize = static_cast<std::size_t>(itemsCount) * itemLength;
    if (tableStart + tableSize > headerSize) {
        raiseRuntimeError("entry table exceeds header size in " + source.string());
    }

    std::vector<FirmwareEntry> entries;
    entries.reserve(itemsCount);

    for (std::size_t index = 0; index < itemsCount; ++index) {
        const auto entryOffset = tableStart + index * itemLength;
        FirmwareEntry entry;
        entry.name = FileSystemSupport::readFixedString(bytes, entryOffset, 16);
        entry.filesystem = FileSystemSupport::readFixedString(bytes, entryOffset + 16, 8);
        entry.offset = FileSystemSupport::readU64Le(bytes, entryOffset + 24);
        entry.size = FileSystemSupport::readU64Le(bytes, entryOffset + 32);

        if (entry.name.empty() || entry.filesystem.empty()) {
            raiseRuntimeError("invalid empty entry name or filesystem in " + source.string());
        }
        if (entry.offset + entry.size > bytes.size()) {
            raiseRuntimeError("entry extends past end of file in " + source.string() + ": " + entry.outputFileName());
        }

        entries.push_back(std::move(entry));
    }

    return entries;
}

FirmwareEntry parseExtractedFileName(const fs::path &path) {
    if (path.extension() != ".bin") {
        raiseRuntimeError("expected .bin payload file in extracted firmware directory: " + path.string());
    }

    const auto stem = path.stem().string();
    const auto separator = stem.rfind('.');
    if (separator == std::string::npos || separator == 0 || separator == stem.size() - 1) {
        raiseRuntimeError("could not parse extracted firmware file name: " + path.string());
    }

    FirmwareEntry entry;
    entry.name = stem.substr(0, separator);
    entry.filesystem = stem.substr(separator + 1);
    entry.size = fs::file_size(path);
    return entry;
}

}  // namespace

std::vector<FirmwareEntry> FirmwareCodec::inspectFirmware(const fs::path &source) const {
    const auto bytes = FileSystemSupport::readFile(source);
    return parseEntries(bytes, source);
}

void FirmwareCodec::extractFirmware(const fs::path &source, const fs::path &outputDirectory) const {
    const auto bytes = FileSystemSupport::readFile(source);
    const auto entries = parseEntries(bytes, source);

    fs::create_directories(outputDirectory);
    for (const auto &entry : entries) {
        const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset);
        const auto end = begin + static_cast<std::ptrdiff_t>(entry.size);
        FileSystemSupport::writeFile(outputDirectory / entry.outputFileName(), std::vector<std::uint8_t>(begin, end));
    }
}

void FirmwareCodec::packFirmware(const fs::path &sourceDirectory, const fs::path &destination) const {
    if (!fs::is_directory(sourceDirectory)) {
        raiseRuntimeError("source is not a directory: " + sourceDirectory.string());
    }

    std::vector<FirmwareEntry> entries;
    for (const auto &directoryEntry : fs::directory_iterator(sourceDirectory)) {
        if (!directoryEntry.is_regular_file() || directoryEntry.path().extension() != ".bin") {
            continue;
        }
        entries.push_back(parseExtractedFileName(directoryEntry.path()));
    }

    if (entries.empty()) {
        raiseRuntimeError("no .bin payload files found in " + sourceDirectory.string());
    }

    std::sort(entries.begin(), entries.end(), [](const FirmwareEntry &left, const FirmwareEntry &right) {
        const auto leftRank = preferredOrder(left);
        const auto rightRank = preferredOrder(right);
        if (leftRank != rightRank) {
            return leftRank < rightRank;
        }
        if (left.name != right.name) {
            return left.name < right.name;
        }
        return left.filesystem < right.filesystem;
    });

    const std::uint32_t fullHeaderSize = static_cast<std::uint32_t>(headerLength + entries.size() * itemLength);
    std::uint64_t nextOffset = fullHeaderSize;
    for (auto &entry : entries) {
        entry.offset = nextOffset;
        nextOffset += alignUp(entry.size, blockAlignment);
    }

    std::vector<std::uint8_t> output;
    output.reserve(static_cast<std::size_t>(nextOffset));
    FileSystemSupport::appendFixedString(output, std::string(firmwareMagic), magicLength);
    FileSystemSupport::appendU32Le(output, fullHeaderSize);
    output.insert(output.end(), reserved1Length, static_cast<std::uint8_t>(0));
    FileSystemSupport::appendU32Le(output, static_cast<std::uint32_t>(entries.size()));
    output.insert(output.end(), reserved2Length, static_cast<std::uint8_t>(0));

    for (const auto &entry : entries) {
        FileSystemSupport::appendFixedString(output, entry.name, 16);
        FileSystemSupport::appendFixedString(output, entry.filesystem, 8);
        FileSystemSupport::appendU64Le(output, entry.offset);
        FileSystemSupport::appendU64Le(output, entry.size);
        output.insert(output.end(), 24, static_cast<std::uint8_t>(0));
    }

    for (const auto &entry : entries) {
        const auto payloadPath = sourceDirectory / entry.outputFileName();
        const auto payload = FileSystemSupport::readFile(payloadPath);
        if (payload.size() != entry.size) {
            raiseRuntimeError("payload size changed during pack for " + payloadPath.string());
        }
        if (output.size() < entry.offset) {
            output.insert(output.end(), static_cast<std::size_t>(entry.offset - output.size()), static_cast<std::uint8_t>(0));
        }
        output.insert(output.end(), payload.begin(), payload.end());
    }

    FileSystemSupport::writeFile(destination, output);
}

}  // namespace teampandory::powpack::detail
