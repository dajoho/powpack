/**
 * @file cli.cpp
 * @brief Implements the 7z-style command-line front-end for `.fw`, OTA
 * `update.zip`, `.res`, and `.str` listing, extraction, and repacking.
 */

#include "cli/cli.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "cli/localization.hpp"
#include "support/exceptionsupport.hpp"
#include "teampandory/powpack/powpack.hpp"
#include "powpackconfig.generated.hpp"

namespace fs = std::filesystem;

namespace teampandory::powpack::detail {
namespace {

std::string formatLabel(ContainerFormat format) {
    switch (format) {
        case ContainerFormat::firmware:
            return ".fw";
        case ContainerFormat::ota:
            return "PATO OTA";
        case ContainerFormat::resourceRes:
            return ".res";
        case ContainerFormat::resourceStr:
            return ".str";
    }
    return "unknown";
}

void printUsage(std::ostream &stream) {
    stream << "powpack " << POWPACK_VERSION << '\n';
    stream << tr("Usage:") << '\n';
    stream << "  powpack l <archive>\n";
    stream << "  powpack i <archive>\n";
    stream << "  powpack x <archive> [-o output_dir]\n";
    stream << "  powpack a <input_dir> <output.fw|update.zip|file.res|file.str>\n";
    stream << "  powpack --help\n";
}

std::optional<std::string> parseLanguageOption(int argc, char **argv) {
    for (int index = 1; index < argc; ++index) {
        if (std::string_view(argv[index]) == "--lang" && index + 1 < argc) {
            return std::string(argv[index + 1]);
        }
    }
    return std::nullopt;
}

std::vector<std::string_view> filteredArguments(int argc, char **argv) {
    std::vector<std::string_view> arguments;
    arguments.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));

    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--lang") {
            ++index;
            continue;
        }
        arguments.push_back(argument);
    }

    return arguments;
}

fs::path defaultExtractDirectory(const fs::path &source) {
    return source.parent_path() / (source.filename().string() + "_UNPACKED");
}

void listFirmware(const fs::path &source) {
    ArchiveTool archiveTool;
    const auto entries = archiveTool.inspectFirmware(source);

    std::cout << source.filename().string() << '\n';
    std::cout << std::left << std::setw(28) << "FILE"
              << std::right << std::setw(14) << "OFFSET"
              << std::setw(14) << "SIZE" << '\n';
    std::cout << std::string(56, '-') << '\n';
    for (const auto &entry : entries) {
        std::cout << std::left << std::setw(28) << entry.outputFileName()
                  << std::right << std::setw(14) << entry.offset
                  << std::setw(14) << entry.size << '\n';
    }
}

void listOta(const fs::path &source) {
    ArchiveTool archiveTool;
    const auto entries = archiveTool.inspectOta(source);

    std::cout << source.filename().string() << '\n';
    std::cout << std::left << std::setw(28) << "FILE"
              << std::right << std::setw(8) << "TYPE"
              << std::setw(8) << "PART"
              << std::setw(14) << "OFFSET"
              << std::setw(14) << "SIZE" << '\n';
    std::cout << std::string(72, '-') << '\n';
    for (const auto &entry : entries) {
        std::cout << std::left << std::setw(28) << entry.outputFileName()
                  << std::right << std::setw(8) << (entry.flag != 0 ? "RAW" : "IMG")
                  << std::setw(8) << static_cast<unsigned>(entry.partition)
                  << std::setw(14) << entry.offset
                  << std::setw(14) << entry.size << '\n';
    }
}

void listResource(const fs::path &source) {
    ArchiveTool archiveTool;
    const auto entries = archiveTool.inspectResource(source);

    std::cout << source.filename().string() << '\n';
    std::cout << std::left << std::setw(20) << "NAME"
              << std::setw(24) << "TYPE"
              << std::right << std::setw(12) << "OFFSET"
              << std::setw(10) << "SIZE" << '\n';
    std::cout << std::string(66, '-') << '\n';
    for (const auto &entry : entries) {
        std::cout << std::left << std::setw(20) << entry.name
                  << std::setw(24) << entry.type_name
                  << std::right << std::setw(12) << entry.offset
                  << std::setw(10) << entry.size << '\n';
    }
}

void inspectArchive(const fs::path &source) {
    ArchiveTool archiveTool;
    const auto analysis = archiveTool.inspectArchive(source);

    std::cout << "File: " << analysis.container_name << '\n';
    std::cout << "Format: " << formatLabel(analysis.format) << '\n';
    std::cout << "Size: " << analysis.file_size << '\n';
    std::cout << "SHA256: " << analysis.sha256 << '\n';
    if (analysis.version.has_value()) {
        std::cout << "Version: " << *analysis.version << '\n';
    }
    if (analysis.kernel_string.has_value()) {
        std::cout << "Kernel: " << *analysis.kernel_string << '\n';
    }
    if (analysis.uenv_text.has_value()) {
        std::cout << "Uenv: " << *analysis.uenv_text << '\n';
    }
    if (!analysis.boot_files.empty()) {
        std::cout << "Boot files:" << '\n';
        for (const auto &file : analysis.boot_files) {
            std::cout << "  - " << file << '\n';
        }
    }

    std::cout << "Entries:" << '\n';
    for (const auto &entry : analysis.entries) {
        std::cout << "  - " << entry.file_name << '\n';
        std::cout << "    Type: " << entry.type << '\n';
        if (analysis.format == ContainerFormat::ota) {
            std::cout << "    Part: " << static_cast<unsigned>(entry.partition) << '\n';
            std::cout << "    CRC: " << std::hex << std::setw(8) << std::setfill('0') << entry.crc << std::dec
                      << std::setfill(' ') << '\n';
        }
        std::cout << "    Offset: " << entry.offset << '\n';
        std::cout << "    Size: " << entry.size << '\n';
        std::cout << "    SHA256: " << entry.sha256 << '\n';
    }
}

void extractFirmware(const fs::path &source, const fs::path &outputDirectory) {
    ArchiveTool archiveTool;
    archiveTool.extractFirmware(source, outputDirectory);
    std::cout << tr("Extracted to") << ": " << outputDirectory.string() << '\n';
}

void extractOta(const fs::path &source, const fs::path &outputDirectory) {
    ArchiveTool archiveTool;
    archiveTool.extractOta(source, outputDirectory);
    std::cout << tr("Extracted to") << ": " << outputDirectory.string() << '\n';
}

void packFirmware(const fs::path &sourceDirectory, const fs::path &destination) {
    ArchiveTool archiveTool;
    archiveTool.packFirmware(sourceDirectory, destination);
    std::cout << tr("Packed to") << ": " << destination.string() << '\n';
}

void packOta(const fs::path &sourceDirectory, const fs::path &destination) {
    ArchiveTool archiveTool;
    archiveTool.packOta(sourceDirectory, destination);
    std::cout << tr("Packed to") << ": " << destination.string() << '\n';
}

void extractResource(const fs::path &source, const fs::path &outputDirectory) {
    ArchiveTool archiveTool;
    archiveTool.extractResource(source, outputDirectory);
    std::cout << tr("Extracted to") << ": " << outputDirectory.string() << '\n';
}

void packResource(const fs::path &sourceDirectory, const fs::path &destination) {
    ArchiveTool archiveTool;
    archiveTool.packResource(sourceDirectory, destination);
    std::cout << tr("Packed to") << ": " << destination.string() << '\n';
}

}  // namespace

int Cli::run(int argc, char **argv) {
    const auto language = parseLanguageOption(argc, argv);
    initializeLocalization(language);

    const auto arguments = filteredArguments(argc, argv);
    if (arguments.empty() || arguments[0] == "--help" || arguments[0] == "-h") {
        printUsage(std::cout);
        return 0;
    }

    try {
        const std::string_view command = arguments[0];
        if (command == "l") {
            if (arguments.size() != 2) {
                raiseRuntimeError("expected one archive path for 'l'");
            }
            const fs::path source(arguments[1]);
            ArchiveTool archiveTool;
            switch (archiveTool.detectFormat(source)) {
                case ContainerFormat::firmware:
                    listFirmware(source);
                    break;
                case ContainerFormat::ota:
                    listOta(source);
                    break;
                case ContainerFormat::resourceRes:
                case ContainerFormat::resourceStr:
                    listResource(source);
                    break;
            }
            return 0;
        }

        if (command == "i") {
            if (arguments.size() != 2) {
                raiseRuntimeError("expected one archive path for 'i'");
            }
            inspectArchive(fs::path(arguments[1]));
            return 0;
        }

        if (command == "x") {
            if (arguments.size() != 2 && arguments.size() != 4) {
                raiseRuntimeError("expected 'x <archive> [-o output_dir]'");
            }

            fs::path outputDirectory;
            if (arguments.size() == 4) {
                if (arguments[2] != "-o") {
                    raiseRuntimeError("expected '-o' before output directory");
                }
                outputDirectory = fs::path(arguments[3]);
            } else {
                outputDirectory = defaultExtractDirectory(fs::path(arguments[1]));
            }

            const fs::path source(arguments[1]);
            ArchiveTool archiveTool;
            switch (archiveTool.detectFormat(source)) {
                case ContainerFormat::firmware:
                    extractFirmware(source, outputDirectory);
                    break;
                case ContainerFormat::ota:
                    extractOta(source, outputDirectory);
                    break;
                case ContainerFormat::resourceRes:
                case ContainerFormat::resourceStr:
                    extractResource(source, outputDirectory);
                    break;
            }
            return 0;
        }

        if (command == "a") {
            if (arguments.size() != 3) {
                raiseRuntimeError("expected 'a <input_dir> <output.fw|update.zip>'");
            }
            const fs::path sourceDirectory(arguments[1]);
            const fs::path destination(arguments[2]);
            if (destination.extension() == ".fw") {
                packFirmware(sourceDirectory, destination);
            } else if (destination.filename() == "update.zip" || destination.extension() == ".zip") {
                packOta(sourceDirectory, destination);
            } else if (destination.extension() == ".res" || destination.extension() == ".str") {
                packResource(sourceDirectory, destination);
            } else {
                raiseRuntimeError("could not infer output format; use .fw, update.zip, .res, or .str");
            }
            return 0;
        }

        raiseRuntimeError("unsupported command: " + std::string(command));
    } catch (const std::exception &exception) {
        std::cerr << "powpack: " << exception.what() << '\n';
        return 1;
    }
}

}  // namespace teampandory::powpack::detail
