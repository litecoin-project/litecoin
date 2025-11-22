#!/bin/sh
# Copyright (c) 2013-2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# ------------------------------------------------------------------------------
# Configuration & Setup
# ------------------------------------------------------------------------------

# Force a standardized locale to ensure deterministic build output.
export LC_ALL=C

# Exit immediately if any command exits with a non-zero status.
set -e

# Navigate to the directory containing this script to handle relative paths correctly.
srcdir="$(dirname "$0")"
cd "$srcdir" || exit 1

# ------------------------------------------------------------------------------
# Dependency Checks
# ------------------------------------------------------------------------------

# Helper function to check if a command exists.
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Verify that 'autoreconf' is installed.
if ! check_command autoreconf; then
    echo "Error: 'autoreconf' is not found." >&2
    echo "Please install 'autoconf', 'automake', and 'libtool' packages." >&2
    exit 1
fi

# Verify that 'pkg-config' is installed (often required by configure scripts).
if ! check_command pkg-config; then
    echo "Error: 'pkg-config' is not found." >&2
    echo "Please install the 'pkg-config' package." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# macOS / BSD Compatibility
# ------------------------------------------------------------------------------

# On macOS (Homebrew/MacPorts), 'libtoolize' is often named 'glibtoolize'.
# Autoreconf requires LIBTOOLIZE env var to be set if the default name isn't found.
if [ -z "${LIBTOOLIZE}" ] && check_command glibtoolize; then
    echo "Info: Detected 'glibtoolize', setting LIBTOOLIZE environment variable."
    export LIBTOOLIZE="$(command -v glibtoolize)"
fi

# ------------------------------------------------------------------------------
# Execution
# ------------------------------------------------------------------------------

echo "Bootstrapping build system with autoreconf..."

# Run autoreconf to generate the configure script.
# --install: Copy missing auxiliary files (config.guess, install-sh, etc.)
# --force: Overwrite existing files to ensure they are up-to-date
# --warnings=all: Report all warnings to help catch potential issues early
autoreconf --install --force --warnings=all

echo "Bootstrap complete. You can now run: ./configure"
