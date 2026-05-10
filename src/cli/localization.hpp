/**
 * @file localization.hpp
 * @brief Declares minimal gettext helpers for the powpack CLI.
 */

#pragma once

#include <optional>
#include <string>

namespace teampandory::powpack::detail {

void initializeLocalization(const std::optional<std::string> &languageName);

const char *tr(const char *messageId);

}  // namespace teampandory::powpack::detail
