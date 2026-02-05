import os
from pathlib import Path

# Base directory — defaults to ~/PII_Buddy but can be overridden via env var
BASE_DIR = Path(os.environ.get("PII_BUDDY_DIR", Path.home() / "PII_Buddy"))

INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
MAPPINGS_DIR = BASE_DIR / "mappings"
ORIGINALS_DIR = BASE_DIR / "originals"
LOGS_DIR = BASE_DIR / "logs"

ALL_DIRS = [INPUT_DIR, OUTPUT_DIR, MAPPINGS_DIR, ORIGINALS_DIR, LOGS_DIR]

# Supported file extensions
SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".doc", ".txt"}

# How long to keep originals before cleanup (hours)
ORIGINALS_RETENTION_HOURS = 24

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
