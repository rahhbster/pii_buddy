#!/usr/bin/env bash
#
# Build a self-contained PII Buddy.app using py2app.
#
# Unlike build_dmg.sh (which bundles source and requires system Python),
# this bundles the Python runtime, all pip packages, and spaCy models
# into a single .app that any Mac user can run with zero setup.
#
# Usage:
#   ./extras/build_py2app.sh
#
# Output:
#   dist/PII_Buddy.dmg   (self-contained, ~80-120MB)
#
# Requirements:
#   - macOS with hdiutil, iconutil, sips (all standard)
#   - .venv with all dependencies installed (run setup.sh first)
#   - py2app installed: .venv/bin/pip install py2app
#
# Optional:
#   - Apple Developer ID for code signing (set DEVELOPER_ID env var)
#     export DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_DIR}/dist"
VENV_PYTHON="${PROJECT_DIR}/.venv/bin/python"

APP_NAME="PII Buddy"
DMG_NAME="PII_Buddy"

cd "$PROJECT_DIR"

# Verify venv exists
if [ ! -x "$VENV_PYTHON" ]; then
    echo "ERROR: No .venv found. Run ./setup.sh first."
    exit 1
fi

# Verify py2app is installed
if ! "$VENV_PYTHON" -c "import py2app" 2>/dev/null; then
    echo "Installing py2app..."
    .venv/bin/pip install py2app
fi

echo "=== Building ${APP_NAME} (py2app) ==="
echo ""

# ------------------------------------------------------------------
# Step 1: Convert icon PNG → .icns
# ------------------------------------------------------------------
printf "[1/5] Converting app icon...  "

ICON_SRC="${PROJECT_DIR}/arbie_pii_buddy_ready.png"
ICONSET_DIR="${DIST_DIR}/PII_Buddy.iconset"
mkdir -p "$DIST_DIR"

if [ ! -f "$ICON_SRC" ]; then
    echo "SKIP (no arbie_pii_buddy_ready.png)"
else
    rm -rf "$ICONSET_DIR"
    mkdir -p "$ICONSET_DIR"

    for size in 16 32 64 128 256 512; do
        sips -z $size $size "$ICON_SRC" --out "${ICONSET_DIR}/icon_${size}x${size}.png" &>/dev/null
        double=$((size * 2))
        sips -z $double $double "$ICON_SRC" --out "${ICONSET_DIR}/icon_${size}x${size}@2x.png" &>/dev/null
    done
    sips -z 1024 1024 "$ICON_SRC" --out "${ICONSET_DIR}/icon_512x512@2x.png" &>/dev/null

    iconutil -c icns "$ICONSET_DIR" -o "${DIST_DIR}/AppIcon.icns"
    rm -rf "$ICONSET_DIR"
    echo "done"
fi

# ------------------------------------------------------------------
# Step 2: Clean previous py2app build
# ------------------------------------------------------------------
printf "[2/5] Cleaning previous build...  "
rm -rf "${PROJECT_DIR}/build"
rm -rf "${DIST_DIR}/${APP_NAME}.app"
rm -f "${DIST_DIR}/${DMG_NAME}.dmg"
echo "done"

# ------------------------------------------------------------------
# Step 3: Create a wrapper entry point that passes --menubar
# ------------------------------------------------------------------
printf "[3/5] Creating app entry point...  "

# py2app needs a script that starts the menu bar app directly.
# We create a thin wrapper so main.py stays as the CLI entry point.
cat > "${PROJECT_DIR}/_py2app_entry.py" << 'ENTRY'
#!/usr/bin/env python3
"""Entry point for the py2app .app bundle.

Launches the menu bar app directly — no CLI argument parsing needed.
"""
import logging
import sys

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Import and run the menu bar app
    from pii_buddy.menubar import _exit_if_already_running, PIIBuddyMenuBar

    _exit_if_already_running()
    app = PIIBuddyMenuBar()
    app.run()

if __name__ == "__main__":
    main()
ENTRY

echo "done"

# ------------------------------------------------------------------
# Step 4: Run py2app
# ------------------------------------------------------------------
echo "[4/5] Running py2app (this takes 1-2 minutes)..."

# Temporarily swap the APP target in setup_py2app.py to use our entry point
"$VENV_PYTHON" -c "
import site
import sys
from pathlib import Path
from setuptools import setup

site_packages = Path(site.getsitepackages()[0])

# Include spaCy model data
spacy_models = []
for model_name in ('en_core_web_md', 'en_core_web_sm'):
    model_dir = site_packages / model_name
    if model_dir.exists():
        for f in model_dir.rglob('*'):
            if f.is_file():
                rel = f.relative_to(site_packages)
                spacy_models.append((str(rel.parent), [str(f)]))

icns = 'dist/AppIcon.icns' if Path('dist/AppIcon.icns').exists() else None

setup(
    name='PII Buddy',
    app=['_py2app_entry.py'],
    data_files=spacy_models,
    options={'py2app': {
        'argv_emulation': False,
        'iconfile': icns,
        'plist': {
            'CFBundleName': 'PII Buddy',
            'CFBundleDisplayName': 'PII Buddy',
            'CFBundleIdentifier': 'dev.piibuddy.menubar',
            'CFBundleVersion': '0.6.0',
            'CFBundleShortVersionString': '0.6.0',
            'LSUIElement': True,
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '12.0',
        },
        'packages': [
            'pii_buddy',
            'spacy', 'thinc', 'blis', 'cymem', 'preshed', 'murmurhash',
            'srsly', 'wasabi', 'catalogue', 'confection', 'weasel',
            'typer', 'click',
            'pydantic', 'pydantic_core',
            'numpy',
            'pdfplumber', 'pdfminer', 'pypdfium2',
            'docx', 'fpdf',
            'httpx', 'httpcore', 'anyio', 'certifi', 'idna',
            'rumps', 'watchdog',
            'lxml', 'jinja2', 'markupsafe',
            'en_core_web_md', 'en_core_web_sm',
            'smart_open', 'cloudpathlib',
            'tqdm', 'requests', 'urllib3', 'charset_normalizer',
        ],
        'includes': [
            'rumps',
            'spacy.lang.en',
        ],
        'excludes': [
            'tkinter', 'matplotlib', 'scipy', 'PIL.ImageTk',
            'test', 'unittest', 'distutils',
        ],
        'resources': ['pii_buddy/data'],
    }},
    setup_requires=['py2app'],
)
" py2app 2>&1 | while IFS= read -r line; do
    # Show progress without flooding the terminal
    case "$line" in
        *"copying"*) ;;
        *"byte-compiling"*) ;;
        *) echo "  $line" ;;
    esac
done

# Clean up entry point
rm -f "${PROJECT_DIR}/_py2app_entry.py"

if [ ! -d "${DIST_DIR}/${APP_NAME}.app" ]; then
    echo ""
    echo "ERROR: py2app build failed. Check output above."
    exit 1
fi

echo "  py2app build complete."

# ------------------------------------------------------------------
# Step 4b: Code signing (optional)
# ------------------------------------------------------------------
if [ -n "${DEVELOPER_ID:-}" ]; then
    printf "  Signing with: ${DEVELOPER_ID}...  "
    codesign --deep --force --options runtime \
        --entitlements /dev/stdin \
        --sign "$DEVELOPER_ID" \
        "${DIST_DIR}/${APP_NAME}.app" << 'ENTITLEMENTS'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.automation.apple-events</key>
    <true/>
</dict>
</plist>
ENTITLEMENTS
    echo "done"
else
    echo "  (Skipping code signing — set DEVELOPER_ID to enable)"
fi

# ------------------------------------------------------------------
# Step 5: Build DMG
# ------------------------------------------------------------------
printf "[5/5] Building DMG...  "

DMG_STAGING="${DIST_DIR}/dmg_staging"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"

cp -R "${DIST_DIR}/${APP_NAME}.app" "$DMG_STAGING/"
ln -s /Applications "$DMG_STAGING/Applications"

DMG_PATH="${DIST_DIR}/${DMG_NAME}.dmg"
hdiutil create \
    -volname "$APP_NAME" \
    -srcfolder "$DMG_STAGING" \
    -ov \
    -format UDZO \
    "$DMG_PATH" &>/dev/null

rm -rf "$DMG_STAGING"

echo "done"

# ------------------------------------------------------------------
# Report
# ------------------------------------------------------------------
APP_SIZE=$(du -sh "${DIST_DIR}/${APP_NAME}.app" | cut -f1 | xargs)
DMG_SIZE=$(du -h "$DMG_PATH" | cut -f1 | xargs)

echo ""
echo "=== Build Complete ==="
echo ""
echo "  App:  ${DIST_DIR}/${APP_NAME}.app  (${APP_SIZE})"
echo "  DMG:  ${DMG_PATH}  (${DMG_SIZE})"
echo ""
echo "To test locally:"
echo "  open '${DIST_DIR}/${APP_NAME}.app'"
echo ""
echo "To test the DMG:"
echo "  open '${DMG_PATH}'"
echo ""

if [ -z "${DEVELOPER_ID:-}" ]; then
    echo "To sign for distribution (avoids Gatekeeper warnings):"
    echo "  export DEVELOPER_ID='Developer ID Application: Your Name (TEAMID)'"
    echo "  ./extras/build_py2app.sh"
    echo ""
    echo "To notarize (requires Apple Developer account, \$99/year):"
    echo "  xcrun notarytool submit '${DMG_PATH}' --apple-id YOU@EMAIL --team-id TEAMID --password APP_PASSWORD --wait"
    echo "  xcrun stapler staple '${DMG_PATH}'"
    echo ""
fi

echo "To create a GitHub release:"
echo "  gh release create v0.6.0 --title 'PII Buddy v0.6.0' \\"
echo "    --notes 'Self-contained Mac app — no Python required' '${DMG_PATH}'"
echo ""
