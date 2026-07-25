import os
from pathlib import Path

# Base directory — defaults to ~/PII_Buddy but can be overridden via env var
BASE_DIR = Path(os.environ.get("PII_BUDDY_DIR", Path.home() / "PII_Buddy"))

INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
MAPPINGS_DIR = BASE_DIR / "mappings"
ORIGINALS_DIR = BASE_DIR / "originals"
LOGS_DIR = BASE_DIR / "logs"
USER_BLOCKLISTS_DIR = BASE_DIR / "blocklists"
FEEDBACK_DIR = BASE_DIR / "feedback"

ALL_DIRS = [INPUT_DIR, OUTPUT_DIR, MAPPINGS_DIR, ORIGINALS_DIR, LOGS_DIR, USER_BLOCKLISTS_DIR, FEEDBACK_DIR]

# Set (by the MAS build's entry point / Info.plist environment, or manually
# for local dry-run testing) when running as the sandboxed Mac App Store
# variant. Gates sandbox-only behavior (security-scoped bookmarks, the
# "Choose Watch Folder…" menu item, cloud-verify feature availability) so
# the existing direct-download/notarized build is completely unaffected.
PII_BUDDY_MAS_BUILD = os.environ.get("PII_BUDDY_MAS_BUILD", "0") == "1"

# Supported file extensions
SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".doc", ".txt"}

# How long to keep originals before cleanup (hours)
ORIGINALS_RETENTION_HOURS = 24

# Settings file
SETTINGS_FILENAME = "settings.conf"

# GitHub repo for blocklist updates
GITHUB_REPO = "rahhbster/pii_buddy"
GITHUB_BRANCH = "main"
GITHUB_BLOCKLIST_PATH = "pii_buddy/data/blocklists/person_blocklist.txt"

# Tag formats for each PII type
TAG_TEMPLATES = {
    "PERSON": "<NAME {initials}>",
    "EMAIL": "<<EMAIL_{n}>>",
    "PHONE": "<<PHONE_{n}>>",
    "SSN": "<<SSN_{n}>>",
    "URL": "<<URL_{n}>>",
    "DOB": "<<DOB_{n}>>",
    "ID_NUMBER": "<<ID_{n}>>",
    "ADDRESS": "<<ADDR_{n}>>",
}
