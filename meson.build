project(
  'powpack',
  'cpp',
  version: '0.1.0',
  license: 'GPL-2.0',
  default_options: [
    'cpp_std=c++20',
    'warning_level=3',
    'buildtype=debugoptimized',
  ],
)

i18n = import('i18n')
pkg = import('pkgconfig')

cpp = meson.get_compiler('cpp')
zlib_dep = dependency('zlib', required: true)
libintl_dep = cpp.find_library('intl', required: false)
have_gettext_header = cpp.has_header('libintl.h')
have_gettext_symbol = false
if have_gettext_header
  have_gettext_symbol = cpp.has_function(
    'gettext',
    prefix: '#include <libintl.h>',
    dependencies: libintl_dep.found() ? [libintl_dep] : [],
  )
endif
have_gettext = have_gettext_header and have_gettext_symbol

public_inc = include_directories('include')
private_inc = include_directories('src')

config = configuration_data()
config.set10('POWPACK_HAVE_GETTEXT', have_gettext)
config.set10('POWPACK_HAVE_EXCEPTIONS', true)
config.set_quoted('POWPACK_VERSION', meson.project_version())
config.set_quoted('POWPACK_LOCALE_DIR', meson.current_build_dir() / 'po')
config.set_quoted('POWPACK_TEXT_DOMAIN', 'powpack')
configure_file(
  input: 'src/powpackconfig.hpp.in',
  output: 'powpackconfig.generated.hpp',
  configuration: config,
)

library_sources = files(
  'src/fw/firmwarecodec.cpp',
  'src/inspect/archiveinspector.cpp',
  'src/ota/otacodec.cpp',
  'src/resources/resourcecodec.cpp',
  'src/io/filesystemsupport.cpp',
  'src/support/sha256.cpp',
)

libpowpack = library(
  'powpack',
  library_sources,
  include_directories: [public_inc, private_inc],
  dependencies: [zlib_dep],
  install: true,
)

powpack_dep = declare_dependency(
  link_with: libpowpack,
  include_directories: public_inc,
  dependencies: (libintl_dep.found() ? [libintl_dep] : []) + [zlib_dep],
)

cli_dependencies = [powpack_dep]
if libintl_dep.found()
  cli_dependencies += libintl_dep
endif

cli_sources = files(
  'src/cli/cli.cpp',
  'src/cli/localization.cpp',
)

executable(
  'powpack',
  ['src/cli/main.cpp', cli_sources],
  include_directories: [public_inc, private_inc],
  dependencies: cli_dependencies,
  install: true,
)

install_subdir(
  'include/teampandory',
  install_dir: get_option('includedir'),
)

pkg.generate(
  libpowpack,
  name: 'powpack',
  filebase: 'powpack',
  description: 'Actions/PowKiddy firmware container inspection and extraction library',
  subdirs: '.',
)

subdir('po')

summary(
  {
    'gettext support': have_gettext,
  },
  section: 'powpack',
)
