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

# ---- Check if running from a read-only volume (e.g. DMG) ----
if ! touch "${BUNDLE_DIR}/.write_test" 2>/dev/null; then
    # Find the .app bundle path (two levels up from MacOS/ → Contents/ → X.app/)
    APP_BUNDLE="$(cd "$(dirname "$0")/../.." && pwd)"
    APP_NAME="$(basename "$APP_BUNDLE")"
    DEST="/Applications/${APP_NAME}"

    result=$(osascript <<'APPLESCRIPT'
display dialog "PII Buddy needs to be installed first." & return & return & "Copy to your Applications folder and launch?" with title "PII Buddy - Install" buttons {"Cancel", "Install & Launch"} default button "Install & Launch" with icon note
return button returned of result
APPLESCRIPT
    )

    if [ "$result" != "Install & Launch" ]; then
        exit 0
    fi

    # Remove old version if present
    rm -rf "$DEST"
    # Copy app to /Applications
    cp -R "${APP_BUNDLE}" "$DEST"
    # Eject the DMG
    VOLUME_PATH="$(cd "$(dirname "$0")/../../../.." && pwd)"
    if [[ "$VOLUME_PATH" == /Volumes/* ]]; then
        hdiutil detach "$VOLUME_PATH" -quiet 2>/dev/null &
    fi
    # Launch the installed copy
    open "$DEST"
    exit 0
fi
rm -f "${BUNDLE_DIR}/.write_test"

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
    button=$(osascript <<'APPLESCRIPT'
set r to display dialog "PII Buddy requires Python 3.9 or later." & return & return & "Install it with:" & return & "  brew install python@3.12" & return & return & "Or download from python.org." with title "PII Buddy - Python Not Found" buttons {"Open python.org", "OK"} default button "OK" with icon caution
return button returned of r
APPLESCRIPT
    )
    if [ "$button" = "Open python.org" ]; then
        open "https://www.python.org/downloads/"
    fi
    exit 1
fi

# ---- Check for .venv (first-run detection) ----
if [ ! -d "${BUNDLE_DIR}/.venv" ]; then
    # First run — show welcome dialog
    result=$(osascript <<'APPLESCRIPT'
display dialog "Welcome to PII Buddy!" & return & return & "First-time setup is needed. This will:" & return & return & "  - Create a Python environment" & return & "  - Install dependencies" & return & "  - Download language models (~50 MB)" & return & return & "This takes about 2-3 minutes." with title "PII Buddy Setup" buttons {"Cancel", "Set Up"} default button "Set Up" with icon note
return button returned of result
APPLESCRIPT
    )

    if [ "$result" != "Set Up" ]; then
        exit 0
    fi

    # Run first-time setup in Terminal so the user sees progress
    SETUP_SCRIPT="${BUNDLE_DIR}/extras/first_run_setup.sh"
    chmod +x "$SETUP_SCRIPT"

    osascript -e "
    tell application \"Terminal\"
        activate
        set setupTab to do script \"bash '${SETUP_SCRIPT}' '${BUNDLE_DIR}' '${PYTHON}'\"
        -- Wait for the setup script to finish, then close the tab
        repeat
            delay 2
            if not busy of setupTab then exit repeat
        end repeat
        delay 1
        close (every window whose selected tab is setupTab)
    end tell
    " &
else
    # Normal launch — use launchctl for proper GUI access without Terminal
    PLIST="/tmp/dev.piibuddy.launcher.plist"
    launchctl unload "$PLIST" 2>/dev/null
    cat > "$PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.piibuddy.launcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BUNDLE_DIR}/.venv/bin/python</string>
        <string>-m</string>
        <string>pii_buddy.menubar</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${BUNDLE_DIR}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>${BUNDLE_DIR}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLISTEOF
    launchctl load "$PLIST"
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
    <true/>
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
