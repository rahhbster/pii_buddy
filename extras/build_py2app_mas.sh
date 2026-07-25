#!/usr/bin/env bash
#
# Build the sandboxed Mac App Store (MAS) variant of PII Buddy and
# package it as a signed .pkg for App Store Connect upload.
#
# This is a SEPARATE script from build_py2app.sh on purpose: the
# existing direct-download/notarized build must keep working exactly as
# before, untouched. This script only adds a new, opt-in output.
#
# Usage:
#   ./extras/build_py2app_mas.sh
#
# Output:
#   dist/mas/PII Buddy.app        (sandboxed, signed if certs provided)
#   dist/mas/PII_Buddy.pkg        (installer package for App Store Connect)
#
# Requirements (all manual, account-specific — see docs/app_store_sandbox.md):
#   - An Apple Developer Program membership with Mac App Store access
#   - A "3rd Party Mac Developer Application" certificate installed in
#     Keychain, exported as MAS_APP_SIGNING_ID, e.g.:
#       export MAS_APP_SIGNING_ID="3rd Party Mac Developer Application: Your Name (TEAMID)"
#   - A "3rd Party Mac Developer Installer" certificate, exported as
#     MAS_INSTALLER_SIGNING_ID, e.g.:
#       export MAS_INSTALLER_SIGNING_ID="3rd Party Mac Developer Installer: Your Name (TEAMID)"
#   - A matching provisioning profile installed for the app's bundle ID
#     (CFBundleIdentifier in setup_py2app.py), embedded as
#     dist/mas/embedded.provisionprofile before signing (Xcode/Apple
#     Developer portal — manual, not something this script can do).
#
# IMPORTANT: this script cannot be verified by running tests. Whether the
# resulting .app actually launches inside the sandbox without violations,
# and whether the .pkg is accepted by App Store Connect, can only be
# confirmed by a human running this on real macOS with real certificates.
# See docs/app_store_sandbox.md for the full list of manual steps.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_DIR}/dist/mas"
VENV_PYTHON="${PROJECT_DIR}/.venv/bin/python"

APP_NAME="PII Buddy"
PKG_NAME="PII_Buddy"
ENTITLEMENTS="${SCRIPT_DIR}/entitlements_mas.plist"

cd "$PROJECT_DIR"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "ERROR: No .venv found. Run ./setup.sh first."
    exit 1
fi

if ! "$VENV_PYTHON" -c "import py2app" 2>/dev/null; then
    echo "Installing py2app..."
    .venv/bin/pip install py2app
fi

if [ ! -f "$ENTITLEMENTS" ]; then
    echo "ERROR: Missing $ENTITLEMENTS"
    exit 1
fi

echo "=== Building ${APP_NAME} (MAS variant) ==="
echo ""

# ------------------------------------------------------------------
# Step 1: Icon (reuse the one built by build_py2app.sh if present)
# ------------------------------------------------------------------
if [ ! -f "${PROJECT_DIR}/dist/AppIcon.icns" ]; then
    echo "[1/5] No dist/AppIcon.icns found — run extras/build_py2app.sh once"
    echo "      first to generate it (or the MAS build will ship without a"
    echo "      custom icon)."
fi

# ------------------------------------------------------------------
# Step 2: Clean previous MAS build
# ------------------------------------------------------------------
printf "[2/5] Cleaning previous MAS build...  "
rm -rf "${PROJECT_DIR}/build"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"
echo "done"

# ------------------------------------------------------------------
# Step 3: Run py2app with the MAS variant
# ------------------------------------------------------------------
echo "[3/5] Running py2app (MAS variant, this takes 1-2 minutes)..."
PII_BUDDY_BUILD_VARIANT=mas "$VENV_PYTHON" setup_py2app.py py2app

if [ ! -d "${DIST_DIR}/${APP_NAME}.app" ]; then
    echo ""
    echo "ERROR: py2app build failed — no ${DIST_DIR}/${APP_NAME}.app produced."
    exit 1
fi
echo "  py2app build complete: ${DIST_DIR}/${APP_NAME}.app"

# ------------------------------------------------------------------
# Step 4: Code sign with the sandbox entitlements
# ------------------------------------------------------------------
if [ -n "${MAS_APP_SIGNING_ID:-}" ]; then
    printf "[4/5] Signing with: ${MAS_APP_SIGNING_ID}...  "

    if [ -f "${DIST_DIR}/embedded.provisionprofile" ]; then
        cp "${DIST_DIR}/embedded.provisionprofile" \
           "${DIST_DIR}/${APP_NAME}.app/Contents/embedded.provisionprofile"
    else
        echo ""
        echo "  WARNING: no embedded.provisionprofile found in ${DIST_DIR}."
        echo "  App Store Connect will reject an unprovisioned sandboxed app."
    fi

    codesign --deep --force --options runtime \
        --entitlements "$ENTITLEMENTS" \
        --sign "$MAS_APP_SIGNING_ID" \
        "${DIST_DIR}/${APP_NAME}.app"
    echo "done"

    echo "  Verifying signature..."
    codesign --verify --deep --strict --verbose=2 "${DIST_DIR}/${APP_NAME}.app" || {
        echo "  WARNING: codesign --verify reported problems above."
    }
else
    echo "[4/5] Skipping code signing — set MAS_APP_SIGNING_ID to enable."
    echo "       An unsigned .app cannot be uploaded to App Store Connect."
fi

# ------------------------------------------------------------------
# Step 5: Package as .pkg via productbuild
# ------------------------------------------------------------------
PKG_PATH="${DIST_DIR}/${PKG_NAME}.pkg"

if [ -n "${MAS_INSTALLER_SIGNING_ID:-}" ]; then
    printf "[5/5] Building signed installer package...  "
    productbuild \
        --component "${DIST_DIR}/${APP_NAME}.app" /Applications \
        --sign "$MAS_INSTALLER_SIGNING_ID" \
        "$PKG_PATH"
    echo "done"
else
    echo "[5/5] Skipping .pkg creation — set MAS_INSTALLER_SIGNING_ID to enable."
    echo "       (App Store Connect only accepts signed installer packages.)"
fi

# ------------------------------------------------------------------
# Report
# ------------------------------------------------------------------
echo ""
echo "=== MAS Build Complete ==="
echo ""
echo "  App: ${DIST_DIR}/${APP_NAME}.app"
if [ -f "$PKG_PATH" ]; then
    echo "  Pkg: ${PKG_PATH}"
    echo ""
    echo "To upload to App Store Connect (requires Transporter or altool/notarytool):"
    echo "  xcrun altool --upload-app -f '${PKG_PATH}' -t macos \\"
    echo "    -u YOUR_APPLE_ID -p APP_SPECIFIC_PASSWORD"
fi
echo ""
echo "REMINDER: this script's output has NOT been verified end-to-end on"
echo "real macOS by this change. See docs/app_store_sandbox.md before"
echo "assuming the sandboxed app actually works or that Apple will accept it."
echo ""
