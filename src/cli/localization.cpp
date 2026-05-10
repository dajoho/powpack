/**
 * @file localization.cpp
 * @brief Implements gettext initialization for the powpack CLI.
 */

#include "cli/localization.hpp"

#include <clocale>
#include <cstdlib>
#include <optional>
#include <string>

#include "powpackconfig.generated.hpp"

#if POWPACK_HAVE_GETTEXT
#include <libintl.h>
#endif

namespace teampandory::powpack::detail {

void initializeLocalization(const std::optional<std::string> &languageName) {
    if (languageName.has_value()) {
#if defined(_WIN32)
        _putenv_s("LANGUAGE", languageName->c_str());
#else
        setenv("LANGUAGE", languageName->c_str(), 1);
#endif
    }

    setlocale(LC_ALL, "");

#if POWPACK_HAVE_GETTEXT
    bindtextdomain(POWPACK_TEXT_DOMAIN, POWPACK_LOCALE_DIR);
    bind_textdomain_codeset(POWPACK_TEXT_DOMAIN, "UTF-8");
    textdomain(POWPACK_TEXT_DOMAIN);
#endif
}

const char *tr(const char *messageId) {
#if POWPACK_HAVE_GETTEXT
    return gettext(messageId);
#else
    return messageId;
#endif
}

}  // namespace teampandory::powpack::detail
