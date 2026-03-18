"""
py2app build configuration for PII Buddy.

Bundles the Python runtime, all dependencies (including spaCy + models),
and app resources into a self-contained PII Buddy.app.

Usage:
    .venv/bin/python setup_py2app.py py2app

Output:
    dist/PII Buddy.app
"""

import site
import sys
from pathlib import Path
from setuptools import setup

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

OPTIONS = {
    "argv_emulation": False,
    "iconfile": icns_file,
    "plist": {
        "CFBundleName": "PII Buddy",
        "CFBundleDisplayName": "PII Buddy",
        "CFBundleIdentifier": "dev.piibuddy.menubar",
        "CFBundleVersion": "0.6.0",
        "CFBundleShortVersionString": "0.6.0",
        "LSUIElement": True,  # Menu bar app — hide from Dock by default
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "12.0",
        "NSHumanReadableCopyright": "Copyright © 2025-2026 PII Buddy",
    },
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

setup(
    name="PII Buddy",
    app=APP,
    data_files=spacy_models,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
