"""Pass 2 — Structural self-audit of redacted text.

Scans redacted output for PII that the spaCy + regex pass likely missed,
using pattern matching around existing tags and known person names.
Runs locally with no external dependencies.
"""

import logging
import re
from collections import defaultdict

from .redactor import _make_initials
from .validation import _get_blocklist

logger = logging.getLogger("pii_buddy")

# Titles that strongly signal a following name
_TITLE_RE = re.compile(
    r"\b(Mr|Mrs|Ms|Miss|Dr|Prof|Professor|Rev|Judge|Hon)"
    r"\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"
)

# Capitalized multi-word phrases (2-3 words)
_CAP_PHRASE_RE = re.compile(
    r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,2})\b"
)

# Possessive form: CapitalizedWord's
_POSSESSIVE_RE = re.compile(r"\b([A-Z][a-z]{2,})'s\b")

# Existing tag patterns (to skip already-tagged text)
_NAME_TAG_RE = re.compile(r"<NAME\s+[A-Z]+\d*>")
_TYPED_TAG_RE = re.compile(r"<<[A-Z]+_\d+>>")


def _collect_known_names(mapping: dict) -> set[str]:
    """Extract all known person surface forms from the mapping."""
    names = set()
    for surface in mapping.get("persons", {}):
        names.add(surface.lower())
        for part in surface.split():
            if len(part) >= 3:
                names.add(part.lower())
    return names


def _is_already_tagged(text: str, start: int, end: int) -> bool:
    """Check if position falls inside an existing tag."""
    for m in _NAME_TAG_RE.finditer(text):
        if m.start() <= start < m.end() or m.start() < end <= m.end():
            return True
    for m in _TYPED_TAG_RE.finditer(text):
        if m.start() <= start < m.end() or m.start() < end <= m.end():
            return True
    return False


def _check_orphaned_conjunctions(text: str) -> list[str]:
    """Find 'CapWord and <NAME XX>' or '<NAME XX> and CapWord' patterns."""
    findings = []

    # Pattern: <NAME XX> and CapitalizedWord
    for m in re.finditer(
        r"<NAME\s+[A-Z]+\d*>\s+and\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\b",
        text,
    ):
        candidate = m.group(1)
        if not _is_already_tagged(text, m.start(1), m.end(1)):
            findings.append(candidate)

    # Pattern: CapitalizedWord and <NAME XX>
    for m in re.finditer(
        r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\s+and\s+<NAME\s+[A-Z]+\d*>",
        text,
    ):
        candidate = m.group(1)
        if not _is_already_tagged(text, m.start(1), m.end(1)):
            findings.append(candidate)

    return findings


def _check_title_prefixed(text: str) -> list[str]:
    """Find 'Mr./Mrs./Dr./Prof.' followed by an untagged capitalized word."""
    findings = []
    for m in _TITLE_RE.finditer(text):
        name = m.group(2)
        if not _is_already_tagged(text, m.start(2), m.end(2)):
            findings.append(name)
    return findings


def _check_capitalized_phrases(text: str, blocklist: set[str]) -> list[str]:
    """Find remaining 2-3 capitalized word sequences that aren't tagged or blocklisted."""
    findings = []
    for m in _CAP_PHRASE_RE.finditer(text):
        phrase = m.group(1)
        if _is_already_tagged(text, m.start(), m.end()):
            continue
        if phrase.lower() in blocklist:
            continue
        # Skip if any word is very short (likely not a name)
        words = phrase.split()
        if any(len(w) < 3 for w in words):
            continue
        # Must have at least 2 words
        if len(words) >= 2:
            findings.append(phrase)
    return findings


def _check_possessive_references(text: str, known_names: set[str]) -> list[str]:
    """Find CapWord's where CapWord matches a known first/last name."""
    findings = []
    for m in _POSSESSIVE_RE.finditer(text):
        word = m.group(1)
        if word.lower() in known_names and not _is_already_tagged(text, m.start(1), m.end(1)):
            findings.append(word)
    return findings


def audit_redacted(redacted_text: str, mapping: dict) -> tuple[str, dict]:
    """Run structural audit on redacted text, apply additional redactions.

    Returns (patched_text, updated_mapping).
    """
    blocklist = _get_blocklist()
    known_names = _collect_known_names(mapping)

    # Collect all findings
    all_findings: list[str] = []
    all_findings.extend(_check_orphaned_conjunctions(redacted_text))
    all_findings.extend(_check_title_prefixed(redacted_text))
    all_findings.extend(_check_capitalized_phrases(redacted_text, blocklist))
    all_findings.extend(_check_possessive_references(redacted_text, known_names))

    # Deduplicate
    seen = set()
    unique_findings = []
    for f in all_findings:
        if f.lower() not in seen and f.lower() not in blocklist:
            seen.add(f.lower())
            unique_findings.append(f)

    if not unique_findings:
        return redacted_text, mapping

    # Apply redactions using the same pattern as verifier._apply_findings
    tags = dict(mapping.get("tags", {}))
    persons = dict(mapping.get("persons", {}))

    # Track existing initials numbering
    initials_max: dict[str, int] = defaultdict(int)
    for tag in tags:
        pm = re.match(r"^<NAME ([A-Z]+?)(\d+)?>$", tag)
        if pm:
            n = int(pm.group(2)) if pm.group(2) else 1
            initials_max[pm.group(1)] = max(initials_max[pm.group(1)], n)

    patched = redacted_text
    applied = 0

    for pii_text in unique_findings:
        # Skip if already a tag or inside a tag
        if "<NAME " in pii_text or "<<" in pii_text:
            continue
        # Skip if already a known redacted value
        if pii_text in tags.values():
            continue
        # Must appear in text
        if pii_text not in patched:
            continue

        # Check if this name maps to an existing person's tag
        existing_tag = None
        for surface, tag in persons.items():
            surface_parts = surface.lower().split()
            if pii_text.lower() in surface_parts:
                existing_tag = tag
                break

        if existing_tag:
            tag = existing_tag
        else:
            initials = _make_initials(pii_text)
            initials_max[initials] += 1
            if initials_max[initials] > 1:
                tag = f"<NAME {initials}{initials_max[initials]}>"
            else:
                tag = f"<NAME {initials}>"

        tags[tag] = pii_text
        persons[pii_text] = tag

        pattern = re.compile(re.escape(pii_text), re.IGNORECASE)
        patched = pattern.sub(tag, patched)
        applied += 1

    if applied:
        logger.info(f"  Audit: {applied} additional redactions applied")

    updated_mapping = dict(mapping)
    updated_mapping["tags"] = tags
    updated_mapping["persons"] = persons
    return patched, updated_mapping
