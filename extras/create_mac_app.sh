#!/usr/bin/env bash
#
# Create a "PII Buddy" menu bar app for macOS.
#
# This wraps the PII Buddy menu bar module in a .app bundle that can
# live in ~/Applications or /Applications and optionally launch at login.
#
# Usage:
#   ./extras/create_mac_app.sh              # creates ~/Applications/PII Buddy.app
#   ./extras/create_mac_app.sh /Applications # creates /Applications/PII Buddy.app
#
# Prerequisites:
#   pip install rumps    (inside your PII Buddy venv)

set -euo pipefail

# Where to install the .app
INSTALL_DIR="${1:-$HOME/Applications}"
APP_NAME="PII Buddy"
APP_PATH="${INSTALL_DIR}/${APP_NAME}.app"

# Find the PII Buddy project root (parent of this script's directory)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Find the Python interpreter — prefer the project venv
if [ -f "${PROJECT_DIR}/.venv/bin/python" ]; then
    PYTHON="${PROJECT_DIR}/.venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON="$(command -v python3)"
else
    echo "Error: No Python interpreter found."
    exit 1
fi

# Verify rumps is installed
if ! "$PYTHON" -c "import rumps" 2>/dev/null; then
    echo "Error: 'rumps' is not installed."
    echo "Install it with:  ${PYTHON} -m pip install rumps"
    exit 1
fi

echo "Creating ${APP_PATH} ..."

# Create .app bundle structure
mkdir -p "${APP_PATH}/Contents/MacOS"
mkdir -p "${APP_PATH}/Contents/Resources"

# Launcher script
cat > "${APP_PATH}/Contents/MacOS/${APP_NAME}" << LAUNCHER
#!/usr/bin/env bash
cd "${PROJECT_DIR}"
exec "${PYTHON}" -m pii_buddy.menubar
LAUNCHER
chmod +x "${APP_PATH}/Contents/MacOS/${APP_NAME}"

# Info.plist — LSUIElement=true hides the Dock icon (menu bar apps only)
cat > "${APP_PATH}/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>PII Buddy</string>
    <key>CFBundleIdentifier</key>
    <string>dev.piibuddy.menubar</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>PII Buddy</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

echo ""
echo "Done!  ${APP_PATH}"
echo ""
echo "To launch:    open '${APP_PATH}'"
echo "To auto-start at login:"
echo "  System Settings > General > Login Items > add '${APP_NAME}'"
echo ""
echo "The app shows \"PII\" in the menu bar. Click it to remove PII"
echo "from your clipboard."
