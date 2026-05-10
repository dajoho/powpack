/**
 * @file resourcecodec.cpp
 * @brief Implements inspection, extraction, and repacking for Actions `.res`
 * and `.str` resource files.
 */

#include "resources/resourcecodec.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/sha.h>
#include <zlib.h>

#include "io/filesystemsupport.hpp"
#include "support/exceptionsupport.hpp"

namespace fs = std::filesystem;

namespace teampandory::powpack {
namespace {

constexpr std::string_view metadataFileName = ".powpack-resource.meta";
constexpr std::string_view blobDirectoryName = ".powpack-blobs";

std::string resourceTypeName(std::uint8_t type) {
    switch (type) {
        case 0x03:
            return "String.UTF-8";
        case 0x04:
            return "String.UNKNOWN";
        case 0x05:
            return "Image.RGB-565";
        case 0x07:
            return "Image.RGB-565.gzip";
        case 0x08:
            return "Image.RGBA-565.gzip";
        case 0x0b:
            return "Image.RGBA-8888";
        default: {
            std::ostringstream stream;
            stream << "UNKNOWN_" << static_cast<unsigned>(type);
            return stream.str();
        }
    }
}

}  // namespace

std::string ResourceEntry::defaultExportName() const {
    if (type == 0x03 || type == 0x04) {
        return name + ".txt";
    }
    if (type == 0x07) {
        return name + ".ppm";
    }
    if (type == 0x05 || type == 0x08 || type == 0x0b) {
        return name + ".pam";
    }
    return name + ".bin";
}

std::vector<ResourceEntry> ArchiveTool::inspectResource(const fs::path &source) const {
    return detail::ResourceCodec{}.inspectResource(source);
}

void ArchiveTool::extractResource(const fs::path &source, const fs::path &outputDirectory) const {
    detail::ResourceCodec{}.extractResource(source, outputDirectory);
}

void ArchiveTool::packResource(const fs::path &sourceDirectory, const fs::path &destination) const {
    detail::ResourceCodec{}.packResource(sourceDirectory, destination);
}

}  // namespace teampandory::powpack

namespace teampandory::powpack::detail {
namespace {

constexpr std::string_view resourceMagic = "RES";
constexpr std::size_t resourceHeaderSize = 16;
constexpr std::size_t entryHeaderSize = 16;

struct ResourceFileHeader {
    std::uint8_t versionByte = 0;
    std::uint16_t itemsCount = 0;
    std::uint16_t unknownWord = 0;
    std::array<std::uint8_t, 8> versionBytes {};
};

struct MetadataEntry {
    ResourceEntry entry;
    std::string exportedName;
    std::string exportedSha256;
    std::string rawBlobName;
};

struct Metadata {
    std::string format;
    ResourceFileHeader header;
    std::vector<MetadataEntry> entries;
};

std::string sha256Hex(const std::vector<std::uint8_t> &data) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
    SHA256(data.data(), data.size(), digest.data());
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char byte : digest) {
        result.push_back(hex[(byte >> 4) & 0x0f]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
}

std::vector<std::uint8_t> zlibInflate(const std::vector<std::uint8_t> &compressed, std::size_t expectedSize) {
    std::vector<std::uint8_t> output(expectedSize);
    uLongf destLength = static_cast<uLongf>(expectedSize);
    const auto result = uncompress(output.data(), &destLength, compressed.data(), static_cast<uLong>(compressed.size()));
    if (result != Z_OK || destLength != expectedSize) {
        raiseRuntimeError("failed to inflate resource image");
    }
    return output;
}

std::vector<std::uint8_t> zlibDeflate(const std::vector<std::uint8_t> &raw) {
    uLongf destLength = compressBound(static_cast<uLong>(raw.size()));
    std::vector<std::uint8_t> output(destLength);
    const auto result = compress2(output.data(), &destLength, raw.data(), static_cast<uLong>(raw.size()), Z_BEST_COMPRESSION);
    if (result != Z_OK) {
        raiseRuntimeError("failed to deflate resource image");
    }
    output.resize(destLength);
    return output;
}

std::vector<ResourceEntry> parseEntries(const std::vector<std::uint8_t> &bytes, const fs::path &source, ResourceFileHeader *outHeader,
                                        std::string *outFormat) {
    if (bytes.size() < resourceHeaderSize) {
        raiseRuntimeError("file too small for resource header: " + source.string());
    }
    if (FileSystemSupport::readFixedString(bytes, 0, 3) != resourceMagic) {
        raiseRuntimeError("unsupported resource magic in " + source.string());
    }

    ResourceFileHeader header;
    header.versionByte = bytes[3];
    header.itemsCount = FileSystemSupport::readU16Le(bytes, 4);
    header.unknownWord = FileSystemSupport::readU16Le(bytes, 6);
    for (std::size_t index = 0; index < header.versionBytes.size(); ++index) {
        header.versionBytes[index] = bytes[8 + index];
    }

    const auto format = source.extension() == ".str" ? std::string("str") : std::string("res");
    std::vector<ResourceEntry> entries;
    entries.reserve(header.itemsCount);

    std::size_t cursor = resourceHeaderSize;
    for (std::size_t index = 0; index < header.itemsCount; ++index) {
        if (cursor + entryHeaderSize > bytes.size()) {
            raiseRuntimeError("resource entry table exceeds file size in " + source.string());
        }

        ResourceEntry entry;
        entry.offset = FileSystemSupport::readU32Le(bytes, cursor);
        entry.size = FileSystemSupport::readU16Le(bytes, cursor + 4);
        entry.type = bytes[cursor + 6];
        entry.name = FileSystemSupport::readFixedString(bytes, cursor + 7, 9);
        entry.type_name = teampandory::powpack::resourceTypeName(entry.type);

        if (entry.name.empty()) {
            raiseRuntimeError("invalid empty resource entry name in " + source.string());
        }
        if (entry.offset + entry.size > bytes.size()) {
            raiseRuntimeError("resource entry exceeds file size in " + source.string() + ": " + entry.name);
        }

        entries.push_back(std::move(entry));
        cursor += entryHeaderSize;
    }

    if (outHeader != nullptr) {
        *outHeader = header;
    }
    if (outFormat != nullptr) {
        *outFormat = format;
    }
    return entries;
}

std::vector<std::uint8_t> decodeRgb555ToRgb(const std::vector<std::uint8_t> &raw, bool withAlpha) {
    const std::size_t pixelStride = withAlpha ? 3 : 2;
    if (raw.size() % pixelStride != 0) {
        raiseRuntimeError("invalid raw pixel buffer size");
    }

    std::vector<std::uint8_t> output;
    output.reserve((raw.size() / pixelStride) * (withAlpha ? 4 : 3));

    for (std::size_t offset = 0; offset < raw.size(); offset += pixelStride) {
        const auto pixel = static_cast<std::uint16_t>(raw[offset]) | static_cast<std::uint16_t>(raw[offset + 1] << 8);
        const auto r5 = static_cast<std::uint8_t>((pixel >> 11) & 0x1f);
        const auto g5 = static_cast<std::uint8_t>((pixel >> 6) & 0x1f);
        const auto b5 = static_cast<std::uint8_t>(pixel & 0x1f);
        output.push_back(static_cast<std::uint8_t>((r5 * 255 + 15) / 31));
        output.push_back(static_cast<std::uint8_t>((g5 * 255 + 15) / 31));
        output.push_back(static_cast<std::uint8_t>((b5 * 255 + 15) / 31));
        if (withAlpha) {
            output.push_back(raw[offset + 2]);
        }
    }

    return output;
}

std::vector<std::uint8_t> encodeRgb555FromRgb(const std::vector<std::uint8_t> &pixels, bool withAlpha) {
    const std::size_t pixelStride = withAlpha ? 4 : 3;
    if (pixels.size() % pixelStride != 0) {
        raiseRuntimeError("invalid exported pixel buffer size");
    }

    std::vector<std::uint8_t> output;
    output.reserve((pixels.size() / pixelStride) * (withAlpha ? 3 : 2));

    for (std::size_t offset = 0; offset < pixels.size(); offset += pixelStride) {
        const auto r5 = static_cast<std::uint16_t>((pixels[offset] * 31 + 127) / 255);
        const auto g5 = static_cast<std::uint16_t>((pixels[offset + 1] * 31 + 127) / 255);
        const auto b5 = static_cast<std::uint16_t>((pixels[offset + 2] * 31 + 127) / 255);
        const auto pixel = static_cast<std::uint16_t>((r5 << 11) | (g5 << 6) | b5);
        output.push_back(static_cast<std::uint8_t>(pixel & 0xff));
        output.push_back(static_cast<std::uint8_t>((pixel >> 8) & 0xff));
        if (withAlpha) {
            output.push_back(pixels[offset + 3]);
        }
    }

    return output;
}

void writePpm(const fs::path &path, std::uint16_t width, std::uint16_t height, const std::vector<std::uint8_t> &rgb) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        raiseRuntimeError("failed to write " + path.string());
    }
    output << "P6\n" << width << ' ' << height << "\n255\n";
    output.write(reinterpret_cast<const char *>(rgb.data()), static_cast<std::streamsize>(rgb.size()));
}

void writePam(const fs::path &path, std::uint16_t width, std::uint16_t height, const std::vector<std::uint8_t> &rgba) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        raiseRuntimeError("failed to write " + path.string());
    }
    output << "P7\nWIDTH " << width << "\nHEIGHT " << height << "\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n";
    output.write(reinterpret_cast<const char *>(rgba.data()), static_cast<std::streamsize>(rgba.size()));
}

std::vector<std::uint8_t> readPpm(const fs::path &path, std::uint16_t *outWidth, std::uint16_t *outHeight) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        raiseRuntimeError("failed to read " + path.string());
    }

    std::string magic;
    input >> magic;
    if (magic != "P6") {
        raiseRuntimeError("expected P6 PPM file: " + path.string());
    }
    unsigned width = 0;
    unsigned height = 0;
    unsigned maxval = 0;
    input >> width >> height >> maxval;
    input.get();
    if (maxval != 255) {
        raiseRuntimeError("unsupported PPM maxval in " + path.string());
    }

    std::vector<std::uint8_t> data(width * height * 3);
    input.read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!input) {
        raiseRuntimeError("failed to read PPM pixel data from " + path.string());
    }

    *outWidth = static_cast<std::uint16_t>(width);
    *outHeight = static_cast<std::uint16_t>(height);
    return data;
}

std::vector<std::uint8_t> readPam(const fs::path &path, std::uint16_t *outWidth, std::uint16_t *outHeight) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        raiseRuntimeError("failed to read " + path.string());
    }

    std::string line;
    std::getline(input, line);
    if (line != "P7") {
        raiseRuntimeError("expected P7 PAM file: " + path.string());
    }

    unsigned width = 0;
    unsigned height = 0;
    unsigned depth = 0;
    unsigned maxval = 0;
    while (std::getline(input, line)) {
        if (line == "ENDHDR") {
            break;
        }
        std::istringstream lineStream(line);
        std::string key;
        lineStream >> key;
        if (key == "WIDTH") {
            lineStream >> width;
        } else if (key == "HEIGHT") {
            lineStream >> height;
        } else if (key == "DEPTH") {
            lineStream >> depth;
        } else if (key == "MAXVAL") {
            lineStream >> maxval;
        }
    }

    if (depth != 4 || maxval != 255) {
        raiseRuntimeError("unsupported PAM layout in " + path.string());
    }

    std::vector<std::uint8_t> data(width * height * 4);
    input.read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!input) {
        raiseRuntimeError("failed to read PAM pixel data from " + path.string());
    }

    *outWidth = static_cast<std::uint16_t>(width);
    *outHeight = static_cast<std::uint16_t>(height);
    return data;
}

std::string hexEncode(const std::array<std::uint8_t, 8> &bytes) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2);
    for (auto byte : bytes) {
        output.push_back(hex[(byte >> 4) & 0x0f]);
        output.push_back(hex[byte & 0x0f]);
    }
    return output;
}

std::array<std::uint8_t, 8> hexDecode8(std::string_view hexString) {
    std::array<std::uint8_t, 8> output {};
    if (hexString.size() != output.size() * 2) {
        raiseRuntimeError("invalid 8-byte hex string");
    }
    auto decodeNibble = [](char ch) -> std::uint8_t {
        if (ch >= '0' && ch <= '9') {
            return static_cast<std::uint8_t>(ch - '0');
        }
        if (ch >= 'a' && ch <= 'f') {
            return static_cast<std::uint8_t>(10 + ch - 'a');
        }
        if (ch >= 'A' && ch <= 'F') {
            return static_cast<std::uint8_t>(10 + ch - 'A');
        }
        raiseRuntimeError("invalid hex character");
    };
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<std::uint8_t>((decodeNibble(hexString[index * 2]) << 4) | decodeNibble(hexString[index * 2 + 1]));
    }
    return output;
}

Metadata loadMetadata(const fs::path &sourceDirectory) {
    std::ifstream input(sourceDirectory / metadataFileName.data());
    if (!input) {
        raiseRuntimeError("missing resource metadata file");
    }

    Metadata metadata;
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind("format=", 0) == 0) {
            metadata.format = line.substr(7);
        } else if (line.rfind("version_byte=", 0) == 0) {
            metadata.header.versionByte = static_cast<std::uint8_t>(std::stoul(line.substr(13)));
        } else if (line.rfind("unknown_word=", 0) == 0) {
            metadata.header.unknownWord = static_cast<std::uint16_t>(std::stoul(line.substr(13)));
        } else if (line.rfind("version_raw=", 0) == 0) {
            metadata.header.versionBytes = hexDecode8(line.substr(12));
        } else if (line.rfind("entry\t", 0) == 0) {
            std::vector<std::string> parts;
            std::size_t start = 0;
            while (start <= line.size()) {
                const auto tab = line.find('\t', start);
                parts.push_back(line.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
                if (tab == std::string::npos) {
                    break;
                }
                start = tab + 1;
            }
            if (parts.size() != 6) {
                raiseRuntimeError("invalid resource metadata entry line");
            }
            MetadataEntry entry;
            entry.entry.name = parts[1];
            entry.entry.type = static_cast<std::uint8_t>(std::stoul(parts[2]));
            entry.entry.type_name = teampandory::powpack::resourceTypeName(entry.entry.type);
            entry.exportedName = parts[3];
            entry.exportedSha256 = parts[4];
            entry.rawBlobName = parts[5];
            metadata.entries.push_back(std::move(entry));
        }
    }

    metadata.header.itemsCount = static_cast<std::uint16_t>(metadata.entries.size());
    if (metadata.format.empty()) {
        raiseRuntimeError("resource metadata missing format");
    }
    return metadata;
}

void saveMetadata(const fs::path &outputDirectory, const Metadata &metadata) {
    std::ofstream output(outputDirectory / metadataFileName.data(), std::ios::binary);
    if (!output) {
        raiseRuntimeError("failed to write resource metadata");
    }

    output << "format=" << metadata.format << '\n';
    output << "version_byte=" << static_cast<unsigned>(metadata.header.versionByte) << '\n';
    output << "unknown_word=" << metadata.header.unknownWord << '\n';
    output << "version_raw=" << hexEncode(metadata.header.versionBytes) << '\n';
    for (const auto &entry : metadata.entries) {
        output << "entry\t" << entry.entry.name << '\t' << static_cast<unsigned>(entry.entry.type) << '\t' << entry.exportedName << '\t'
               << entry.exportedSha256 << '\t' << entry.rawBlobName << '\n';
    }
}

std::vector<std::uint8_t> exportEntryPayload(const std::vector<std::uint8_t> &payload, const ResourceEntry &entry, const fs::path &path) {
    if (entry.type == 0x03 || entry.type == 0x04) {
        const auto textLength = payload.empty() ? 0 : payload.size() - 1;
        const auto text = std::vector<std::uint8_t>(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(textLength));
        FileSystemSupport::writeFile(path, text);
        return text;
    }

    if (entry.type == 0x05) {
        const auto width = FileSystemSupport::readU16Le(payload, 0);
        const auto height = FileSystemSupport::readU16Le(payload, 2);
        const auto imageData = std::vector<std::uint8_t>(payload.begin() + 4, payload.end());
        const auto rgba = decodeRgb555ToRgb(imageData, true);
        writePam(path, width, height, rgba);
        return FileSystemSupport::readFile(path);
    }

    if (entry.type == 0x07 || entry.type == 0x08) {
        const auto width = FileSystemSupport::readU16Le(payload, 0);
        const auto height = FileSystemSupport::readU16Le(payload, 2);
        const auto compressedSize = FileSystemSupport::readU32Le(payload, 4);
        const auto compressed = std::vector<std::uint8_t>(payload.begin() + 8,
                                                          payload.begin() + 8 + static_cast<std::ptrdiff_t>(compressedSize));
        const auto raw = zlibInflate(compressed, static_cast<std::size_t>(width) * height * (entry.type == 0x07 ? 2 : 3));
        if (entry.type == 0x07) {
            const auto rgb = decodeRgb555ToRgb(raw, false);
            writePpm(path, width, height, rgb);
        } else {
            const auto rgba = decodeRgb555ToRgb(raw, true);
            writePam(path, width, height, rgba);
        }
        return FileSystemSupport::readFile(path);
    }

    if (entry.type == 0x0b) {
        const auto width = FileSystemSupport::readU16Le(payload, 0);
        const auto height = FileSystemSupport::readU16Le(payload, 2);
        const auto rgba = std::vector<std::uint8_t>(payload.begin() + 4, payload.end());
        writePam(path, width, height, rgba);
        return FileSystemSupport::readFile(path);
    }

    FileSystemSupport::writeFile(path, payload);
    return payload;
}

std::vector<std::uint8_t> buildEntryPayload(const fs::path &sourceDirectory, const MetadataEntry &metadataEntry) {
    const auto exportedPath = sourceDirectory / metadataEntry.exportedName;
    const auto exportedBytes = FileSystemSupport::readFile(exportedPath);
    if (sha256Hex(exportedBytes) == metadataEntry.exportedSha256) {
        const auto rawPath = sourceDirectory / blobDirectoryName.data() / metadataEntry.rawBlobName;
        if (fs::exists(rawPath)) {
            return FileSystemSupport::readFile(rawPath);
        }
    }

    const auto &entry = metadataEntry.entry;
    if (entry.type == 0x03 || entry.type == 0x04) {
        auto payload = exportedBytes;
        payload.push_back(0);
        return payload;
    }

    if (entry.type == 0x05) {
        std::uint16_t width = 0;
        std::uint16_t height = 0;
        const auto rgba = readPam(exportedPath, &width, &height);
        auto payload = std::vector<std::uint8_t> {};
        FileSystemSupport::appendU16Le(payload, width);
        FileSystemSupport::appendU16Le(payload, height);
        const auto raw = encodeRgb555FromRgb(rgba, true);
        payload.insert(payload.end(), raw.begin(), raw.end());
        return payload;
    }

    if (entry.type == 0x07) {
        std::uint16_t width = 0;
        std::uint16_t height = 0;
        const auto rgb = readPpm(exportedPath, &width, &height);
        auto payload = std::vector<std::uint8_t> {};
        const auto raw = encodeRgb555FromRgb(rgb, false);
        const auto compressed = zlibDeflate(raw);
        FileSystemSupport::appendU16Le(payload, width);
        FileSystemSupport::appendU16Le(payload, height);
        FileSystemSupport::appendU32Le(payload, static_cast<std::uint32_t>(compressed.size()));
        payload.insert(payload.end(), compressed.begin(), compressed.end());
        return payload;
    }

    if (entry.type == 0x08) {
        std::uint16_t width = 0;
        std::uint16_t height = 0;
        const auto rgba = readPam(exportedPath, &width, &height);
        auto payload = std::vector<std::uint8_t> {};
        const auto raw = encodeRgb555FromRgb(rgba, true);
        const auto compressed = zlibDeflate(raw);
        FileSystemSupport::appendU16Le(payload, width);
        FileSystemSupport::appendU16Le(payload, height);
        FileSystemSupport::appendU32Le(payload, static_cast<std::uint32_t>(compressed.size()));
        payload.insert(payload.end(), compressed.begin(), compressed.end());
        return payload;
    }

    if (entry.type == 0x0b) {
        std::uint16_t width = 0;
        std::uint16_t height = 0;
        const auto rgba = readPam(exportedPath, &width, &height);
        auto payload = std::vector<std::uint8_t> {};
        FileSystemSupport::appendU16Le(payload, width);
        FileSystemSupport::appendU16Le(payload, height);
        payload.insert(payload.end(), rgba.begin(), rgba.end());
        return payload;
    }

    return exportedBytes;
}

}  // namespace

std::vector<ResourceEntry> ResourceCodec::inspectResource(const fs::path &source) const {
    const auto bytes = FileSystemSupport::readFile(source);
    return parseEntries(bytes, source, nullptr, nullptr);
}

void ResourceCodec::extractResource(const fs::path &source, const fs::path &outputDirectory) const {
    const auto bytes = FileSystemSupport::readFile(source);
    ResourceFileHeader header;
    std::string format;
    const auto entries = parseEntries(bytes, source, &header, &format);

    fs::create_directories(outputDirectory);
    fs::create_directories(outputDirectory / blobDirectoryName.data());

    Metadata metadata;
    metadata.format = format;
    metadata.header = header;

    for (const auto &entry : entries) {
        const auto payload = std::vector<std::uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset),
                                                       bytes.begin() + static_cast<std::ptrdiff_t>(entry.offset + entry.size));
        const auto exportedName = entry.defaultExportName();
        const auto exportedBytes = exportEntryPayload(payload, entry, outputDirectory / exportedName);
        const auto rawBlobName = entry.name + ".bin";
        FileSystemSupport::writeFile(outputDirectory / blobDirectoryName.data() / rawBlobName, payload);

        metadata.entries.push_back(MetadataEntry{
            .entry = entry,
            .exportedName = exportedName,
            .exportedSha256 = sha256Hex(exportedBytes),
            .rawBlobName = rawBlobName,
        });
    }

    saveMetadata(outputDirectory, metadata);
}

void ResourceCodec::packResource(const fs::path &sourceDirectory, const fs::path &destination) const {
    if (!fs::is_directory(sourceDirectory)) {
        raiseRuntimeError("source is not a directory: " + sourceDirectory.string());
    }

    const auto metadata = loadMetadata(sourceDirectory);
    std::vector<MetadataEntry> entries = metadata.entries;
    std::vector<std::vector<std::uint8_t>> payloads;
    payloads.reserve(entries.size());

    std::uint32_t nextOffset = resourceHeaderSize + static_cast<std::uint32_t>(entries.size() * entryHeaderSize);
    for (auto &entry : entries) {
        auto payload = buildEntryPayload(sourceDirectory, entry);
        entry.entry.offset = nextOffset;
        entry.entry.size = static_cast<std::uint16_t>(payload.size());
        nextOffset += entry.entry.size;
        payloads.push_back(std::move(payload));
    }

    std::vector<std::uint8_t> output;
    output.reserve(nextOffset);
    FileSystemSupport::appendFixedString(output, std::string(resourceMagic), 3);
    output.push_back(metadata.header.versionByte);
    FileSystemSupport::appendU16Le(output, static_cast<std::uint16_t>(entries.size()));
    FileSystemSupport::appendU16Le(output, metadata.header.unknownWord);
    output.insert(output.end(), metadata.header.versionBytes.begin(), metadata.header.versionBytes.end());

    for (const auto &entry : entries) {
        FileSystemSupport::appendU32Le(output, entry.entry.offset);
        FileSystemSupport::appendU16Le(output, entry.entry.size);
        output.push_back(entry.entry.type);
        FileSystemSupport::appendFixedString(output, entry.entry.name, 9);
    }

    for (const auto &payload : payloads) {
        output.insert(output.end(), payload.begin(), payload.end());
    }

    FileSystemSupport::writeFile(destination, output);
}

}  // namespace teampandory::powpack::detail
