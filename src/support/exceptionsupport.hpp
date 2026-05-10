/**
 * @file exceptionsupport.hpp
 * @brief Small helpers for explicit fatal and runtime error reporting.
 */

#pragma once

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>

#include "powpackconfig.generated.hpp"

namespace teampandory::powpack::detail {

[[noreturn]] inline void failWithoutExceptions(std::string_view message) {
    std::fputs("powpack: ", stderr);
    std::fwrite(message.data(), sizeof(char), message.size(), stderr);
    std::fputc('\n', stderr);
    std::abort();
}

[[noreturn]] inline void raiseRuntimeError(const std::string &message) {
#if POWPACK_HAVE_EXCEPTIONS
    throw std::runtime_error(message);
#else
    failWithoutExceptions(message);
#endif
}

}  // namespace teampandory::powpack::detail
