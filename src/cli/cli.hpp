/**
 * @file cli.hpp
 * @brief Declares the command-line entry point for the standalone powpack CLI.
 */

#pragma once

namespace teampandory::powpack::detail {

class Cli {
   public:
    static int run(int argc, char **argv);
};

}  // namespace teampandory::powpack::detail
