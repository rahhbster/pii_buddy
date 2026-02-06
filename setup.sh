#!/bin/bash
# PII Buddy — one-time setup
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== PII Buddy Setup ==="

# Find a suitable Python 3.9+ — prefer homebrew, fall back to system
PYTHON=""
for candidate in /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3 /usr/local/bin/python3.12 /usr/local/bin/python3.13 /usr/bin/python3; do
    if [ -x "$candidate" ]; then
        version=$("$candidate" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
        major=$(echo "$version" | grep -oE '[0-9]+' | head -1)
        minor=$(echo "$version" | grep -oE '[0-9]+' | tail -1)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ] 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.9+ required. Found versions:"
    python3 --version 2>/dev/null
    echo "Install Python 3.12 via: brew install python@3.12"
    exit 1
fi

echo "Using: $PYTHON ($($PYTHON --version))"

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    "$PYTHON" -m venv .venv
fi

echo "Installing dependencies..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

echo "Downloading spaCy language models..."
.venv/bin/python -m spacy download en_core_web_md --quiet
.venv/bin/python -m spacy download en_core_web_sm --quiet

# Create working directories
BUDDY_DIR="${PII_BUDDY_DIR:-$HOME/PII_Buddy}"
mkdir -p "$BUDDY_DIR/input" "$BUDDY_DIR/output" "$BUDDY_DIR/mappings" "$BUDDY_DIR/originals" "$BUDDY_DIR/logs" "$BUDDY_DIR/blocklists"

# Seed user blocklist if it doesn't exist
if [ ! -f "$BUDDY_DIR/blocklists/user_blocklist.txt" ]; then
    cat > "$BUDDY_DIR/blocklists/user_blocklist.txt" << 'BLOCKLIST'
# Your personal blocklist — terms here will NEVER be treated as a person's name.
# One per line, case-insensitive. Lines starting with # are comments.
#
# This file is yours and will never be overwritten by updates.
# Add company names, product names, or any terms that get incorrectly redacted.
#
# Examples:
# My Company Name
# Specific Product Name
# Internal Project Codename
BLOCKLIST
fi

# Seed settings.conf if it doesn't exist
if [ ! -f "$BUDDY_DIR/settings.conf" ]; then
    cat > "$BUDDY_DIR/settings.conf" << 'SETTINGS'
# PII Buddy Settings
# Uncomment and change values as needed. CLI flags override these settings.

[paths]
# input_dir = input
# output_dir = output

[output]
# format = txt          # "txt" or "same"
# tag = PII_FREE        # empty = no prefix, appends _redacted
# overwrite = false
# text_output = false
SETTINGS
    echo "  Created: $BUDDY_DIR/settings.conf"
fi

echo ""
echo "Setup complete."
echo "  Folder: $BUDDY_DIR"
echo ""
echo "To run:  ./run.sh"
echo "Then drop files into: $BUDDY_DIR/input/"
