#!/usr/bin/env bash
#
# PII Buddy — First-Time Setup (runs in Terminal on first launch from .app)
#
# This script is invoked by the app launcher when no .venv exists yet.
# It installs everything the user needs, then starts the menu bar app.
#
set -e

PROJECT_DIR="$1"
PYTHON_BIN="$2"

if [ -z "$PROJECT_DIR" ] || [ -z "$PYTHON_BIN" ]; then
    echo "Usage: first_run_setup.sh <project_dir> <python_path>"
    exit 1
fi

cd "$PROJECT_DIR"

echo ""
echo "=== PII Buddy — First-Time Setup ==="
echo ""
echo "This will take about 2-3 minutes."
echo ""

# Step 1: Create venv
printf "[1/5] Creating Python environment...          "
"$PYTHON_BIN" -m venv .venv
echo "✓"

# Step 2: Install dependencies
printf "[2/5] Installing dependencies...               "
.venv/bin/pip install --quiet --upgrade pip 2>/dev/null
.venv/bin/pip install --quiet -r requirements.txt 2>/dev/null
echo "✓"

# Step 3: Download spaCy models
printf "[3/5] Downloading language models (~50 MB)...  "
.venv/bin/python -m spacy download en_core_web_md --quiet 2>/dev/null
.venv/bin/python -m spacy download en_core_web_sm --quiet 2>/dev/null
echo "✓"

# Step 4: Install rumps for menu bar support
printf "[4/5] Installing menu bar support...           "
.venv/bin/pip install --quiet rumps 2>/dev/null
echo "✓"

# Step 5: Create working directories and seed files
printf "[5/5] Creating working folders...              "

BUDDY_DIR="${PII_BUDDY_DIR:-$HOME/PII_Buddy}"
mkdir -p "$BUDDY_DIR/input" "$BUDDY_DIR/output" "$BUDDY_DIR/mappings" \
         "$BUDDY_DIR/originals" "$BUDDY_DIR/logs" "$BUDDY_DIR/blocklists"

# Seed user blocklist
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

# Seed settings.conf
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
fi

echo "✓"

echo ""
echo "=== Setup complete! ==="
echo ""
echo "  Working folder: $BUDDY_DIR"
echo "  Drop files into: $BUDDY_DIR/input/"
echo ""
echo "Starting PII Buddy..."
echo "(You can close this terminal window.)"
echo ""

# Launch the menu bar app in the background
cd "$PROJECT_DIR"
nohup .venv/bin/python -m pii_buddy.menubar &>/dev/null &
