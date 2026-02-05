"""Detect PII in text using spaCy NER + regex patterns + validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .validation import validate_entities


@dataclass
class PIIEntity:
    text: str
    label: str
    start: int
    end: int
    confidence: float = 1.0


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

DOB_RE = re.compile(
    r"\b(?:"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
    r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
    r"\s+\d{1,2},?\s+\d{2,4}"
    r")\b",
    re.IGNORECASE,
)

ID_NUMBER_RE = re.compile(
    r"\b(?:"
    r"[A-Z]{1,2}\d{6,8}"
    r"|[A-Z]{2,4}-[A-Z]{1,4}-\d{5,10}"
    r"|\d{9,10}"
    r")\b"
)

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

_VAGUE_DATE_RE = re.compile(
    r"(?:years?|months?|weeks?|days?|present|current|today|now|ago)",
    re.IGNORECASE,
)

SPACY_MODEL = "en_core_web_md"
SPACY_FALLBACK = "en_core_web_sm"


def _load_spacy():
    import spacy
    for model in (SPACY_MODEL, SPACY_FALLBACK):
        try:
            return spacy.load(model)
        except OSError:
            pass
    # Download fallback
    import spacy.cli
    print(f"Downloading spaCy model {SPACY_FALLBACK} (one-time)...")
    spacy.cli.download(SPACY_FALLBACK)
    return spacy.load(SPACY_FALLBACK)


_nlp = None


def get_nlp():
    global _nlp
    if _nlp is None:
        _nlp = _load_spacy()
    return _nlp


def _is_specific_date(text: str) -> bool:
    if not any(c.isdigit() for c in text):
        return False
    if _VAGUE_DATE_RE.search(text):
        return False
    if "\n" in text:
        return False
    if " - " in text or " to " in text.lower():
        return False
    if len(text) > 25:
        return False
    return True


def _basic_person_check(text: str) -> bool:
    """Quick pre-filter before full validation."""
    if "@" in text or "\n" in text:
        return False
    if any(c.isdigit() for c in text):
        return False
    parts = text.strip().split()
    if not parts or len(parts) > 5:
        return False
    return True


def _detect_allcaps_names(text: str) -> list[PIIEntity]:
    """Detect ALL CAPS names in resume headers."""
    entities = []
    header = text[:500]
    for match in re.finditer(r"^([A-Z][A-Z]+(?:\s+[A-Z][A-Z]+){0,3})\s*$", header, re.MULTILINE):
        name = match.group(1)
        words = name.split()
        if len(words) >= 2 and all(w.isalpha() for w in words):
            entities.append(PIIEntity(
                text=name.title(),
                label="PERSON",
                start=match.start(),
                end=match.end(),
                confidence=0.9,
            ))
    return entities


def _detect_doc_type(text: str) -> str:
    """Auto-detect document type: resume, transcript, or general."""
    sample = text[:1500].lower()

    transcript_score = 0
    if re.search(r'\b(?:interviewer|interviewee|moderator|speaker\s*\d+)\s*:', sample):
        transcript_score += 3
    if re.search(r'^\s*[A-Z][a-z]+\s*:', text[:1500], re.MULTILINE):
        transcript_score += 1
    if re.search(r'\b(?:q:|a:|question:|answer:)', sample):
        transcript_score += 2

    resume_score = 0
    if re.search(r'\b(?:resume|curriculum vitae|cv)\b', sample):
        resume_score += 3
    if re.search(r'\b(?:professional summary|work experience|education)\b', sample):
        resume_score += 2
    if re.search(r'\b(?:years? of experience|proficient in|responsible for)\b', sample):
        resume_score += 1

    if transcript_score > resume_score and transcript_score >= 3:
        return "transcript"
    elif resume_score >= 2:
        return "resume"
    return "general"


def detect_pii(text: str, doc_type: str = "auto") -> list[PIIEntity]:
    """
    Detect PII in text using regex + spaCy NER + validation.

    Two-pass approach:
      1. Detect all candidate entities (permissive)
      2. Validate and score confidence (selective)
    """
    if doc_type == "auto":
        doc_type = _detect_doc_type(text)

    # --- Pass 1: Detection ---

    # 1a. Regex (structured PII — high confidence)
    regex_entities = []
    for pattern, label in REGEX_PATTERNS:
        for match in pattern.finditer(text):
            regex_entities.append(PIIEntity(
                text=match.group(),
                label=label,
                start=match.start(),
                end=match.end(),
                confidence=1.0,
            ))

    regex_ranges = set()
    for ent in regex_entities:
        regex_ranges.update(range(ent.start, ent.end))

    # 1b. spaCy NER (names and dates)
    nlp = get_nlp()
    doc = nlp(text)
    spacy_entities = []

    for ent in doc.ents:
        ent_range = set(range(ent.start_char, ent.end_char))
        if ent_range & regex_ranges:
            continue

        if ent.label_ == "PERSON" and _basic_person_check(ent.text):
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
                confidence=0.8,
            ))

    # 1c. ALL CAPS names in resume headers
    allcaps_entities = _detect_allcaps_names(text)

    # Combine all candidates
    all_candidates = regex_entities + spacy_entities + allcaps_entities

    # --- Pass 2: Validation ---
    validated = validate_entities(all_candidates, text, doc, doc_type)

    # --- Deduplicate overlapping entities ---
    validated.sort(key=lambda e: (e.start, -e.confidence, -(e.end - e.start)))
    deduped = []
    last_end = -1
    for ent in validated:
        if ent.start >= last_end:
            deduped.append(ent)
            last_end = ent.end

    return deduped
