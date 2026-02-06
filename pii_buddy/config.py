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

ALL_DIRS = [INPUT_DIR, OUTPUT_DIR, MAPPINGS_DIR, ORIGINALS_DIR, LOGS_DIR, USER_BLOCKLISTS_DIR]

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
    "PERSON": "<<{initials}>>",
    "EMAIL": "<<EMAIL_{n}>>",
    "PHONE": "<<PHONE_{n}>>",
    "SSN": "<<SSN_{n}>>",
    "URL": "<<URL_{n}>>",
    "DOB": "<<DOB_{n}>>",
    "ID_NUMBER": "<<ID_{n}>>",
    "ADDRESS": "<<ADDR_{n}>>",
}
