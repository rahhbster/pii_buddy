"""Detect PII in text using spaCy NER + regex patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class PIIEntity:
    text: str
    label: str
    start: int
    end: int


# --- Regex patterns for structured PII ---

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)

PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[-.\s]?)?"
    r"(?:\(?\d{3}\)?[-.\s]?)"
    r"\d{3}[-.\s]?\d{4}"
    r"(?!\d)"
)

SSN_RE = re.compile(
    r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"
)

URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
)

# Dates that look like DOB: MM/DD/YYYY, MM-DD-YYYY, Month DD YYYY, etc.
DOB_RE = re.compile(
    r"\b(?:"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
    r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
    r"\s+\d{1,2},?\s+\d{2,4}"
    r")\b",
    re.IGNORECASE,
)

# ID-like numbers: driver's license patterns, passport-like, etc.
ID_NUMBER_RE = re.compile(
    r"\b(?:"
    r"[A-Z]{1,2}\d{6,8}"       # e.g., DL numbers like D1234567
    r"|\d{9,10}"                # 9-10 digit numbers (passport, DL)
    r")\b"
)

# Street address pattern (number + street name + type)
ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+"
    r"(?:[A-Z][a-z]+\s+){1,4}"
    r"(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|"
    r"Rd|Road|Ct|Court|Pl(?:ace)?|Way|Cir(?:cle)?|Pkwy|Parkway|"
    r"Ter(?:race)?|Loop|Run|Pass|Pike|Hwy|Highway)"
    r"\.?"
    r"(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#)\s*\d+[A-Za-z]?)?"
    r"\b",
    re.IGNORECASE,
)

# ZIP codes (US 5-digit and 5+4)
ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")

REGEX_PATTERNS = [
    (EMAIL_RE, "EMAIL"),
    (PHONE_RE, "PHONE"),
    (SSN_RE, "SSN"),
    (URL_RE, "URL"),
    (DOB_RE, "DOB"),
    (ID_NUMBER_RE, "ID_NUMBER"),
    (ADDRESS_RE, "ADDRESS"),
]

# Pattern to validate that a PERSON entity looks like an actual name
_NAME_RE = re.compile(r"^[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}$")

# Patterns that indicate a DATE entity is NOT a specific date/DOB
_VAGUE_DATE_RE = re.compile(
    r"(?:years?|months?|weeks?|days?|present|current|today|now|ago)",
    re.IGNORECASE,
)


def _load_spacy():
    import spacy
    try:
        return spacy.load("en_core_web_sm")
    except OSError:
        print("Downloading spaCy model (one-time)...")
        spacy.cli.download("en_core_web_sm")
        return spacy.load("en_core_web_sm")


_nlp = None


def get_nlp():
    global _nlp
    if _nlp is None:
        _nlp = _load_spacy()
    return _nlp


def _is_valid_person(text: str) -> bool:
    """Check that a PERSON entity looks like an actual name."""
    # Reject if it contains @, digits, or special chars (except spaces/hyphens/apostrophes)
    if "@" in text or any(c.isdigit() for c in text):
        return False
    # Reject if it contains newlines
    if "\n" in text:
        return False
    # Should be 1-4 words, each starting with a capital letter
    parts = text.strip().split()
    if not parts or len(parts) > 5:
        return False
    return True


def _is_specific_date(text: str) -> bool:
    """Check that a DATE entity looks like a specific date (DOB, etc.), not vague."""
    if not any(c.isdigit() for c in text):
        return False
    if _VAGUE_DATE_RE.search(text):
        return False
    # Reject date ranges like "January 2020 - Present"
    if " - " in text or " to " in text.lower():
        return False
    # Must be reasonably short (a date, not a paragraph)
    if len(text) > 30:
        return False
    return True


def detect_pii(text: str) -> list[PIIEntity]:
    """Return all PII entities found in the text, sorted by position."""
    # 1. Regex-based detection (structured PII) — these get priority
    regex_entities = []
    for pattern, label in REGEX_PATTERNS:
        for match in pattern.finditer(text):
            regex_entities.append(PIIEntity(
                text=match.group(),
                label=label,
                start=match.start(),
                end=match.end(),
            ))

    # Build a set of covered character ranges from regex matches
    regex_ranges = set()
    for ent in regex_entities:
        regex_ranges.update(range(ent.start, ent.end))

    # 2. spaCy NER (names, dates) — only add if they don't overlap regex matches
    nlp = get_nlp()
    doc = nlp(text)
    spacy_entities = []

    for ent in doc.ents:
        # Skip if this entity overlaps any regex match
        ent_range = set(range(ent.start_char, ent.end_char))
        if ent_range & regex_ranges:
            continue

        if ent.label_ == "PERSON" and _is_valid_person(ent.text):
            spacy_entities.append(PIIEntity(
                text=ent.text,
                label="PERSON",
                start=ent.start_char,
                end=ent.end_char,
            ))
        elif ent.label_ == "DATE" and _is_specific_date(ent.text):
            spacy_entities.append(PIIEntity(
                text=ent.text,
                label="DOB",
                start=ent.start_char,
                end=ent.end_char,
            ))

    # 3. Combine and deduplicate overlapping entities
    entities = regex_entities + spacy_entities
    entities.sort(key=lambda e: (e.start, -(e.end - e.start)))
    deduped = []
    last_end = -1
    for ent in entities:
        if ent.start >= last_end:
            deduped.append(ent)
            last_end = ent.end

    return deduped
