#!/bin/sh
# --- Metadata & Security Controls ---
# Ensure consistent string sorting and behavior across different locales
export LC_ALL=C

# --- Argument Handling & Validation ---
# Usage: ./genbuild.sh <output_file> <source_root>
if [ $# -lt 1 ]; then
    echo "Usage: $0 <output_file> [source_root]"
    exit 1
fi

OUTPUT_FILE="$1"
SRC_ROOT="${2:-.}" # Default to current directory if not provided

# Navigate to source root to ensure git commands run in the correct context
cd "$SRC_ROOT" || { echo "Error: Cannot access source root $SRC_ROOT"; exit 1; }

# Load existing build info to prevent unnecessary file writes (preserves timestamps)
INFO=""
if [ -f "$OUTPUT_FILE" ]; then
    INFO=$(head -n 1 "$OUTPUT_FILE")
fi



# --- Git Metadata Extraction ---
GIT_TAG=""
GIT_COMMIT=""

# Safety Check: Verify Git availability and repository status
if [ "${BITCOIN_GENBUILD_NO_GIT}" != "1" ] && command -v git >/dev/null 2>&1; then
    if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ]; then
        
        # Security & Integrity: Refresh index to ignore minor file touch events
        git diff >/dev/null 2>&1

        # Check for an exact tag match at the current HEAD (Release mode)
        RAW_DESC=$(git describe --abbrev=0 2>/dev/null || true)
        if [ -n "$RAW_DESC" ] && [ "$(git rev-parse HEAD)" = "$(git rev-list -1 "$RAW_DESC" 2>/dev/null)" ]; then
            # Ensure no uncommitted changes exist for a 'clean' tag
            git diff-index --quiet HEAD -- && GIT_TAG="$RAW_DESC"
        fi

        # Fallback to Short Commit Hash (Development mode)
        GIT_COMMIT=$(git rev-parse --short HEAD)
        # Append '-dirty' suffix if there are uncommitted local changes
        git diff-index --quiet HEAD -- || GIT_COMMIT="${GIT_COMMIT}-dirty"
    fi
fi

# --- Header Content Generation ---
if [ -n "$GIT_TAG" ]; then
    NEW_INFO="#define BUILD_GIT_TAG \"$GIT_TAG\""
elif [ -n "$GIT_COMMIT" ]; then
    NEW_INFO="#define BUILD_GIT_COMMIT \"$GIT_COMMIT\""
else
    NEW_INFO="// No build information available"
fi



# --- Atomic Update Logic ---
# Only write to the file if the content has changed.
# This avoids triggering unnecessary recompilations of dependent objects.
if [ "$INFO" != "$NEW_INFO" ]; then
    echo "Updating build information in $OUTPUT_FILE"
    echo "$NEW_INFO" > "$OUTPUT_FILE"
fi
