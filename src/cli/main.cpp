/**
 * @file main.cpp
 * @brief Forwards the executable entry point into the CLI layer.
 */

#include "cli/cli.hpp"

int main(int argc, char **argv) {
    return teampandory::powpack::detail::Cli::run(argc, argv);
}
