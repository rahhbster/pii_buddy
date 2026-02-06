#!/usr/bin/env bash
#
# Build a distributable PII_Buddy.dmg for macOS.
#
# Creates a .app bundle with:
#   - Smart launcher that handles first-run setup vs. normal launch
#   - Arbie app icon (.icns) converted from the 2048x2048 PNG
#   - Full project source (excluding .git, .venv, large PNGs)
#   - /Applications symlink for drag-to-install
#
# Usage:
#   ./extras/build_dmg.sh
#
# Output:
#   dist/PII_Buddy.dmg
#
# Requirements:
#   macOS with hdiutil, iconutil, sips (all standard)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

APP_NAME="PII Buddy"
BUNDLE_ID="dev.piibuddy.menubar"
VERSION="1.0.0"
DMG_NAME="PII_Buddy"

DIST_DIR="${PROJECT_DIR}/dist"
STAGE_DIR="${DIST_DIR}/staging"
APP_PATH="${STAGE_DIR}/${APP_NAME}.app"
CONTENTS="${APP_PATH}/Contents"

# Clean previous build
rm -rf "$STAGE_DIR"
mkdir -p "$DIST_DIR" "$STAGE_DIR"

echo "=== Building ${APP_NAME} DMG ==="
echo ""

# ------------------------------------------------------------------
# Step 1: Convert icon PNG → .icns
# ------------------------------------------------------------------
printf "[1/5] Converting app icon...  "

ICON_SRC="${PROJECT_DIR}/arbie_pii_buddy_ready.png"
ICONSET_DIR="${DIST_DIR}/PII_Buddy.iconset"

if [ ! -f "$ICON_SRC" ]; then
    echo "SKIP (no arbie_pii_buddy_ready.png found, using default)"
    ICNS_FILE=""
else
    rm -rf "$ICONSET_DIR"
    mkdir -p "$ICONSET_DIR"

    # Generate all required icon sizes
    for size in 16 32 64 128 256 512; do
        sips -z $size $size "$ICON_SRC" --out "${ICONSET_DIR}/icon_${size}x${size}.png" &>/dev/null
        double=$((size * 2))
        sips -z $double $double "$ICON_SRC" --out "${ICONSET_DIR}/icon_${size}x${size}@2x.png" &>/dev/null
    done
    # 512@2x is 1024
    sips -z 1024 1024 "$ICON_SRC" --out "${ICONSET_DIR}/icon_512x512@2x.png" &>/dev/null

    ICNS_FILE="${DIST_DIR}/AppIcon.icns"
    iconutil -c icns "$ICONSET_DIR" -o "$ICNS_FILE"
    rm -rf "$ICONSET_DIR"
    echo "✓"
fi

# ------------------------------------------------------------------
# Step 2: Create .app bundle structure
# ------------------------------------------------------------------
printf "[2/5] Creating app bundle...  "

mkdir -p "${CONTENTS}/MacOS"
mkdir -p "${CONTENTS}/Resources"

if [ -n "${ICNS_FILE:-}" ] && [ -f "$ICNS_FILE" ]; then
    cp "$ICNS_FILE" "${CONTENTS}/Resources/AppIcon.icns"
fi

echo "✓"

# ------------------------------------------------------------------
# Step 3: Copy project source into Resources/pii_buddy/
# ------------------------------------------------------------------
printf "[3/5] Copying project files...  "

BUNDLE_PROJECT="${CONTENTS}/Resources/pii_buddy"

rsync -a --quiet \
    --exclude='.git' \
    --exclude='.venv' \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    --exclude='dist' \
    --exclude='build' \
    --exclude='*.egg-info' \
    --exclude='arbie_pii_buddy_ready.png' \
    --exclude='arbie_pii_buddy_processing.png' \
    --exclude='arbie_pii_buddy_done.png' \
    "${PROJECT_DIR}/" "${BUNDLE_PROJECT}/"

echo "✓"

# ------------------------------------------------------------------
# Step 4: Write launcher script
# ------------------------------------------------------------------
printf "[4/5] Writing launcher...  "

cat > "${CONTENTS}/MacOS/${APP_NAME}" << 'LAUNCHER'
#!/usr/bin/env bash
#
# PII Buddy — Smart Launcher
#
# Handles first-run setup (Python detection, venv, deps) and normal launches.
#

# Locate the bundled project inside the .app
BUNDLE_DIR="$(cd "$(dirname "$0")/../Resources/pii_buddy" && pwd)"

# ---- Find Python 3.9+ on the system ----
PYTHON=""
for candidate in \
    /opt/homebrew/bin/python3.12 \
    /opt/homebrew/bin/python3.13 \
    /opt/homebrew/bin/python3.11 \
    /opt/homebrew/bin/python3.10 \
    /opt/homebrew/bin/python3.9 \
    /opt/homebrew/bin/python3 \
    /usr/local/bin/python3.12 \
    /usr/local/bin/python3.13 \
    /usr/local/bin/python3.11 \
    /usr/local/bin/python3.10 \
    /usr/local/bin/python3.9 \
    /usr/local/bin/python3 \
    /usr/bin/python3; do
    if [ -x "$candidate" ]; then
        version=$("$candidate" -c "import sys; print(sys.version_info[:2])" 2>/dev/null || true)
        major=$(echo "$version" | grep -oE '[0-9]+' | head -1)
        minor=$(echo "$version" | grep -oE '[0-9]+' | tail -1)
        if [ -n "$major" ] && [ -n "$minor" ] && [ "$major" -ge 3 ] && [ "$minor" -ge 9 ] 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    # Show a native macOS dialog — no Python found
    button=$(osascript -e '
    set r to display dialog "PII Buddy requires Python 3.9 or later.\n\nInstall it with:\n  brew install python@3.12\n\nOr download from python.org." \
        with title "PII Buddy — Python Not Found" \
        buttons {"Open python.org", "OK"} default button "OK" with icon caution
    return button returned of r
    ' 2>/dev/null || true)
    if [ "$button" = "Open python.org" ]; then
        open "https://www.python.org/downloads/"
    fi
    exit 1
fi

# ---- Check for .venv (first-run detection) ----
if [ ! -d "${BUNDLE_DIR}/.venv" ]; then
    # First run — show welcome dialog
    result=$(osascript -e '
    display dialog "Welcome to PII Buddy!\n\nFirst-time setup is needed. This will:\n\n  • Create a Python environment\n  • Install dependencies\n  • Download language models (~50 MB)\n\nThis takes about 2-3 minutes." \
        with title "PII Buddy — Setup" \
        buttons {"Cancel", "Set Up"} default button "Set Up" with icon note
    return button returned of result
    ' 2>/dev/null || echo "Cancel")

    if [ "$result" != "Set Up" ]; then
        exit 0
    fi

    # Run first-time setup in Terminal so the user sees progress
    SETUP_SCRIPT="${BUNDLE_DIR}/extras/first_run_setup.sh"
    chmod +x "$SETUP_SCRIPT"

    osascript -e "
    tell application \"Terminal\"
        activate
        do script \"bash '${SETUP_SCRIPT}' '${BUNDLE_DIR}' '${PYTHON}'\"
    end tell
    "
else
    # Normal launch — start menu bar app directly
    cd "$BUNDLE_DIR"
    exec .venv/bin/python -m pii_buddy.menubar
fi
LAUNCHER

chmod +x "${CONTENTS}/MacOS/${APP_NAME}"

echo "✓"

# ------------------------------------------------------------------
# Step 5: Write Info.plist
# ------------------------------------------------------------------

ICON_ENTRY=""
if [ -n "${ICNS_FILE:-}" ] && [ -f "${CONTENTS}/Resources/AppIcon.icns" ]; then
    ICON_ENTRY="    <key>CFBundleIconFile</key>
    <string>AppIcon</string>"
fi

cat > "${CONTENTS}/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>LSUIElement</key>
    <false/>
    <key>NSHighResolutionCapable</key>
    <true/>
${ICON_ENTRY}
</dict>
</plist>
PLIST

# ------------------------------------------------------------------
# Create /Applications symlink in staging dir
# ------------------------------------------------------------------
ln -s /Applications "${STAGE_DIR}/Applications"

# ------------------------------------------------------------------
# Build the DMG
# ------------------------------------------------------------------
echo ""
printf "[5/5] Building DMG...  "

DMG_PATH="${DIST_DIR}/${DMG_NAME}.dmg"
rm -f "$DMG_PATH"

hdiutil create \
    -volname "$APP_NAME" \
    -srcfolder "$STAGE_DIR" \
    -ov \
    -format UDZO \
    "$DMG_PATH" &>/dev/null

echo "✓"

# Clean up staging
rm -rf "$STAGE_DIR"

# Report
DMG_SIZE=$(du -h "$DMG_PATH" | cut -f1 | xargs)
echo ""
echo "=== Done! ==="
echo ""
echo "  DMG:  ${DMG_PATH}"
echo "  Size: ${DMG_SIZE}"
echo ""
echo "To test:"
echo "  open '${DMG_PATH}'"
echo ""
echo "To create a GitHub release:"
echo "  gh release create v${VERSION} --title 'PII Buddy v${VERSION}' \\"
echo "    --notes 'First release' '${DMG_PATH}'"
echo ""
