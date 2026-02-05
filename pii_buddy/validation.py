"""Entity validation and confidence scoring to minimize false positives."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from pii_buddy.config import USER_BLOCKLISTS_DIR

BLOCKLISTS_DIR = Path(__file__).parent / "data" / "blocklists"

MIN_PERSON_CONFIDENCE = 0.6

# --- Patterns that indicate a false positive ---

JOB_TITLE_PATTERNS = [
    re.compile(r'\b(?:Senior|Junior|Lead|Principal|Staff|Chief|Associate|Assistant)\s+(?:\w+\s+)?(?:Engineer|Developer|Architect|Manager|Designer|Analyst|Consultant|Specialist|Coordinator|Administrator)\b', re.IGNORECASE),
    re.compile(r'\b(?:Software|Hardware|Cloud|Data|Security|DevOps|Full[- ]?Stack|Frontend|Backend|Platform|Mobile|Web|QA|Test)\s+(?:Engineer|Developer|Architect)\b', re.IGNORECASE),
    re.compile(r'\b(?:Product|Program|Project|Engineering|Account|Sales|Marketing|Operations)\s+Manager\b', re.IGNORECASE),
    re.compile(r'\bScrum\s+Master\b', re.IGNORECASE),
    re.compile(r'\b(?:Business|Data|Security|Systems|Network)\s+(?:Analyst|Administrator)\b', re.IGNORECASE),
    re.compile(r'\b(?:Vice\s+President|Managing\s+Director|General\s+Manager)\b', re.IGNORECASE),
    re.compile(r'\b(?:Technical|Creative|Art|Design)\s+(?:Lead|Director)\b', re.IGNORECASE),
]

CERTIFICATION_PATTERNS = [
    re.compile(r'\bAWS\s+(?:Certified\s+)?(?:Solutions?\s+)?(?:Architect|Developer|Practitioner|SysOps|DevOps)\b', re.IGNORECASE),
    re.compile(r'\b(?:Certified\s+)?Scrum\s+(?:Master|Alliance|Product\s+Owner)\b', re.IGNORECASE),
    re.compile(r'\b(?:PMP|CISSP|CISM|CRISC|CEH|OSCP|CompTIA|ITIL)\b'),
    re.compile(r'\bGoogle\s+Cloud\b', re.IGNORECASE),
    re.compile(r'\bMicrosoft\s+(?:Certified|Azure)\b', re.IGNORECASE),
    re.compile(r'\bCisco\s+Certified\b', re.IGNORECASE),
    re.compile(r'\bOracle\s+Certified\b', re.IGNORECASE),
    re.compile(r'\bRed\s+Hat\s+Certified\b', re.IGNORECASE),
    re.compile(r'\bSix\s+Sigma\b', re.IGNORECASE),
]

SECTION_HEADERS = {
    'professional summary', 'executive summary', 'career summary',
    'career objective', 'objective', 'profile', 'summary',
    'work experience', 'professional experience', 'employment history',
    'education', 'academic background', 'skills', 'technical skills',
    'core competencies', 'certifications', 'licenses', 'credentials',
    'projects', 'key projects', 'notable projects',
    'references', 'contact information', 'personal information',
    'achievements', 'accomplishments', 'awards', 'publications',
    'presentations', 'volunteer work', 'languages', 'interests',
    'activities', 'experience', 'qualifications',
}

# Lowercase particles in international names
NAME_PARTICLES = {
    'de', 'del', 'della', 'di', 'da', 'van', 'von', 'der', 'den',
    'ter', 'te', 'la', 'le', 'bin', 'ibn', 'al', 'el',
}


@dataclass
class ValidationContext:
    doc_type: str
    text: str
    spacy_doc: object
    non_person_labels: set = field(default_factory=set)


def _load_blocklist(filepath: Path) -> set[str]:
    if not filepath.exists():
        return set()
    entries = set()
    with filepath.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                entries.add(line.lower())
    return entries


_blocklist_cache = None


def _get_blocklist() -> set[str]:
    global _blocklist_cache
    if _blocklist_cache is None:
        _blocklist_cache = set()
        # Package blocklists (official + custom template)
        for name in ("person_blocklist.txt", "custom_blocklist.txt"):
            _blocklist_cache |= _load_blocklist(BLOCKLISTS_DIR / name)
        # User's local blocklist (never overwritten by --update)
        _blocklist_cache |= _load_blocklist(USER_BLOCKLISTS_DIR / "user_blocklist.txt")
    return _blocklist_cache


def reload_blocklist():
    """Force reload of all blocklists (called after --update)."""
    global _blocklist_cache
    _blocklist_cache = None


def _is_job_title(text: str) -> bool:
    return any(p.fullmatch(text) or p.search(text) for p in JOB_TITLE_PATTERNS)


def _is_certification(text: str) -> bool:
    return any(p.search(text) for p in CERTIFICATION_PATTERNS)


def _is_section_header(text: str) -> bool:
    return text.lower().strip() in SECTION_HEADERS


def _has_proper_name_capitalization(text: str) -> bool:
    """Check for valid name capitalization, including international names."""
    parts = text.split()
    for part in parts:
        if len(part) <= 2:
            continue
        if part.lower() in NAME_PARTICLES:
            continue
        # O'Connor, McDonald, MacArthur
        if part.startswith("O'") or part.startswith("Mc") or part.startswith("Mac"):
            continue
        # Hyphenated: Marie-Anne
        if '-' in part:
            subparts = part.split('-')
            if all(sp[0:1].isupper() for sp in subparts if sp):
                continue
            return False
        if not part[0].isupper():
            return False
    return True


def score_person_entity(entity, context: ValidationContext) -> float:
    """
    Score a PERSON entity from 0.0 (definitely not a person) to 1.0 (definitely is).
    """
    text = entity.text.strip()
    text_lower = text.lower()

    # Immediate rejects
    if text_lower in _get_blocklist():
        return 0.0
    if text in context.non_person_labels:
        return 0.0
    if _is_section_header(text):
        return 0.0
    if _is_certification(text):
        return 0.0
    if '@' in text or '\n' in text:
        return 0.0
    if any(c.isdigit() for c in text):
        return 0.0

    score = 0.5
    parts = text.split()

    # Word count scoring
    if len(parts) == 0 or len(parts) > 5:
        return 0.0
    if 2 <= len(parts) <= 3:
        score += 0.25
    if len(parts) == 1:
        score -= 0.15
        if len(parts[0]) <= 3:
            score -= 0.2

    # Job title check
    if _is_job_title(text):
        score -= 0.4

    # Capitalization
    if not _has_proper_name_capitalization(text):
        score -= 0.25

    # POS tag analysis — proper nouns (NNP) are a good sign
    try:
        doc = context.spacy_doc
        tokens = [t for t in doc if entity.start <= t.idx < entity.end]
        if tokens:
            nnp_ratio = sum(1 for t in tokens if t.tag_ in ('NNP', 'NNPS')) / len(tokens)
            if nnp_ratio > 0.8:
                score += 0.2
            elif nnp_ratio < 0.3:
                score -= 0.2
    except Exception:
        pass

    return max(0.0, min(1.0, score))


def validate_entities(entities: list, text: str, doc, doc_type: str = "general") -> list:
    """
    Filter false positives and add confidence scores to entities.
    Non-PERSON entities pass through unchanged.
    """
    non_person_labels = set()
    for ent in doc.ents:
        if ent.label_ in ("ORG", "GPE", "LOC", "NORP", "FAC", "PRODUCT", "WORK_OF_ART"):
            non_person_labels.add(ent.text)

    context = ValidationContext(
        doc_type=doc_type,
        text=text,
        spacy_doc=doc,
        non_person_labels=non_person_labels,
    )

    validated = []
    for entity in entities:
        if entity.label == "PERSON":
            confidence = score_person_entity(entity, context)
            if confidence >= MIN_PERSON_CONFIDENCE:
                entity.confidence = confidence
                validated.append(entity)
        else:
            entity.confidence = 1.0
            validated.append(entity)

    return validated
