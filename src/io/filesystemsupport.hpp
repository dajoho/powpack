/**
 * @file filesystemsupport.hpp
 * @brief Declares file and binary-buffer helpers shared by the firmware codec.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace teampandory::powpack::detail {

class FileSystemSupport {
   public:
    static std::vector<std::uint8_t> readFile(const std::filesystem::path &path);

    static void writeFile(const std::filesystem::path &path, const std::vector<std::uint8_t> &data);

    static std::uint32_t readU32Le(const std::vector<std::uint8_t> &data, std::size_t offset);

    static std::uint64_t readU64Le(const std::vector<std::uint8_t> &data, std::size_t offset);

    static std::uint16_t readU16Le(const std::vector<std::uint8_t> &data, std::size_t offset);

    static std::string readFixedString(const std::vector<std::uint8_t> &data, std::size_t offset, std::size_t length);

    static void appendFixedString(std::vector<std::uint8_t> &data, const std::string &value, std::size_t length);

    static void appendU32Le(std::vector<std::uint8_t> &data, std::uint32_t value);

    static void appendU64Le(std::vector<std::uint8_t> &data, std::uint64_t value);

    static void appendU16Le(std::vector<std::uint8_t> &data, std::uint16_t value);
};

}  // namespace teampandory::powpack::detail
