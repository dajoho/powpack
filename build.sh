#!/bin/bash
set -euo pipefail

build_dir="${1:-build}"
meson setup "$build_dir" . --reconfigure
meson compile -C "$build_dir"
