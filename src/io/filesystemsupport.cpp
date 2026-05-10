/**
 * @file filesystemsupport.cpp
 * @brief Implements simple whole-file and little-endian buffer helpers.
 */

#include "io/filesystemsupport.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

#include "support/exceptionsupport.hpp"

namespace fs = std::filesystem;

namespace teampandory::powpack::detail {

std::vector<std::uint8_t> FileSystemSupport::readFile(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        raiseRuntimeError("failed to open " + path.string());
    }

    input.seekg(0, std::ios::end);
    const auto fileSize = input.tellg();
    input.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> data(static_cast<std::size_t>(fileSize));
    if (!data.empty()) {
        input.read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(data.size()));
    }

    if (!input && !data.empty()) {
        raiseRuntimeError("failed to read " + path.string());
    }

    return data;
}

void FileSystemSupport::writeFile(const fs::path &path, const std::vector<std::uint8_t> &data) {
    if (!path.parent_path().empty()) {
        fs::create_directories(path.parent_path());
    }

    std::ofstream output(path, std::ios::binary);
    if (!output) {
        raiseRuntimeError("failed to open " + path.string() + " for writing");
    }

    if (!data.empty()) {
        output.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    }

    if (!output) {
        raiseRuntimeError("failed to write " + path.string());
    }
}

std::uint32_t FileSystemSupport::readU32Le(const std::vector<std::uint8_t> &data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        raiseRuntimeError("unexpected end of buffer");
    }

    return static_cast<std::uint32_t>(data[offset]) | (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 16) | (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint16_t FileSystemSupport::readU16Le(const std::vector<std::uint8_t> &data, std::size_t offset) {
    if (offset + 2 > data.size()) {
        raiseRuntimeError("unexpected end of buffer");
    }

    return static_cast<std::uint16_t>(data[offset]) | static_cast<std::uint16_t>(data[offset + 1] << 8);
}

std::uint64_t FileSystemSupport::readU64Le(const std::vector<std::uint8_t> &data, std::size_t offset) {
    if (offset + 8 > data.size()) {
        raiseRuntimeError("unexpected end of buffer");
    }

    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(data[offset + index]) << (index * 8);
    }
    return value;
}

std::string FileSystemSupport::readFixedString(const std::vector<std::uint8_t> &data, std::size_t offset, std::size_t length) {
    if (offset + length > data.size()) {
        raiseRuntimeError("unexpected end of buffer");
    }

    const auto begin = reinterpret_cast<const char *>(data.data() + offset);
    std::string value(begin, begin + length);
    const auto nulPos = value.find('\0');
    if (nulPos != std::string::npos) {
        value.resize(nulPos);
    }
    return value;
}

void FileSystemSupport::appendFixedString(std::vector<std::uint8_t> &data, const std::string &value, std::size_t length) {
    if (value.size() > length) {
        raiseRuntimeError("value too long for fixed string field: " + value);
    }

    data.insert(data.end(), value.begin(), value.end());
    data.insert(data.end(), length - value.size(), static_cast<std::uint8_t>(0));
}

void FileSystemSupport::appendU32Le(std::vector<std::uint8_t> &data, std::uint32_t value) {
    data.push_back(static_cast<std::uint8_t>(value & 0xff));
    data.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    data.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    data.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
}

void FileSystemSupport::appendU64Le(std::vector<std::uint8_t> &data, std::uint64_t value) {
    for (std::size_t index = 0; index < 8; ++index) {
        data.push_back(static_cast<std::uint8_t>((value >> (index * 8)) & 0xff));
    }
}

void FileSystemSupport::appendU16Le(std::vector<std::uint8_t> &data, std::uint16_t value) {
    data.push_back(static_cast<std::uint8_t>(value & 0xff));
    data.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
}

}  // namespace teampandory::powpack::detail
