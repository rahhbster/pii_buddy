"""
py2app build configuration for PII Buddy.

Bundles the Python runtime, all dependencies (including spaCy + models),
and app resources into a self-contained PII Buddy.app.

Usage:
    .venv/bin/python setup_py2app.py py2app

Output:
    dist/PII Buddy.app

--- MAS (Mac App Store) build variant ---

Set PII_BUDDY_BUILD_VARIANT=mas to produce the sandboxed App Store
target instead, writing to a separate dist/mas/ directory so it never
collides with (or risks overwriting) the direct-download build above:

    PII_BUDDY_BUILD_VARIANT=mas .venv/bin/python setup_py2app.py py2app

This only changes py2app's own inputs (dist dir, bundled
LSEnvironment flag). It does NOT sign the app or apply entitlements —
py2app has no concept of sandbox entitlements. Signing with
extras/entitlements_mas.plist and packaging as a .pkg via productbuild
is a separate, manual step — see extras/build_py2app_mas.sh and
docs/app_store_sandbox.md for exactly what still needs to be run/
verified by hand on real macOS with a Mac Developer Application
certificate.

The existing direct-download/notarized build (default, no env var) is
completely untouched by this variant support.
"""

import os
import site
import sys
from pathlib import Path
from setuptools import setup

MAS_VARIANT = os.environ.get("PII_BUDDY_BUILD_VARIANT", "").strip().lower() == "mas"

# Locate spaCy models in the venv's site-packages
site_packages = Path(site.getsitepackages()[0])

# spaCy models must be included as data files since py2app
# won't discover them through import tracing.
spacy_models = []
for model_name in ("en_core_web_md", "en_core_web_sm"):
    model_dir = site_packages / model_name
    if model_dir.exists():
        for f in model_dir.rglob("*"):
            if f.is_file():
                rel = f.relative_to(site_packages)
                spacy_models.append((str(rel.parent), [str(f)]))

# Icon file
icon_file = "arbie_pii_buddy_ready.png"
icns_file = "dist/AppIcon.icns"

# Check if we have an .icns already (built by build_py2app.sh)
icns_path = Path(icns_file)
if not icns_path.exists():
    icns_file = None

APP = ["main.py"]

_plist = {
    "CFBundleName": "PII Buddy",
    "CFBundleDisplayName": "PII Buddy",
    "CFBundleIdentifier": "dev.piibuddy.menubar",
    "CFBundleVersion": "0.6.0",
    "CFBundleShortVersionString": "0.6.0",
    "LSUIElement": True,  # Menu bar app — hide from Dock by default
    "NSHighResolutionCapable": True,
    "LSMinimumSystemVersion": "12.0",
    "NSHumanReadableCopyright": "Copyright © 2025-2026 PII Buddy",
}

if MAS_VARIANT:
    # Auto-enable the sandbox code paths (BookmarkStore, "Choose Watch
    # Folder…" menu item) when this build launches — no manual env var
    # needed by the end user. Actual sandboxing/entitlements come from
    # codesign, not from this plist key; see extras/build_py2app_mas.sh.
    _plist["LSEnvironment"] = {"PII_BUDDY_MAS_BUILD": "1"}

OPTIONS = {
    "argv_emulation": False,
    "iconfile": icns_file,
    "plist": _plist,
    "packages": [
        "pii_buddy",
        "spacy",
        "thinc",
        "blis",
        "cymem",
        "preshed",
        "murmurhash",
        "srsly",
        "wasabi",
        "catalogue",
        "confection",
        "weasel",
        "typer_slim",
        "pydantic",
        "pydantic_core",
        "numpy",
        "pdfplumber",
        "pdfminer",
        "pypdfium2",
        "docx",  # python-docx
        "fpdf",  # fpdf2
        "httpx",
        "httpcore",
        "anyio",
        "certifi",
        "rumps",
        "watchdog",
        "lxml",
        "Jinja2",
        "markupsafe",
        "en_core_web_md",
        "en_core_web_sm",
    ],
    "includes": [
        "rumps",
        "spacy.lang.en",
        "AppKit",
        "Foundation",
        "objc",
    ],
    "excludes": [
        "tkinter",
        "matplotlib",
        "scipy",
        "PIL.ImageTk",
        "test",
        "unittest",
        "email.test",
        "distutils",
    ],
    "resources": [
        "pii_buddy/data",
    ],
    # Pass --menubar automatically when launched as .app
    "extra_scripts": [],
}

# Keep MAS output fully separate from the direct-download build's
# dist/PII Buddy.app so `PII_BUDDY_BUILD_VARIANT=mas ... py2app` can
# never clobber it. distutils reads --dist-dir from script_args, not
# from the py2app-specific OPTIONS dict above.
if MAS_VARIANT and "--dist-dir" not in " ".join(sys.argv):
    sys.argv += ["--dist-dir", "dist/mas"]

setup(
    name="PII Buddy",
    app=APP,
    data_files=spacy_models,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
