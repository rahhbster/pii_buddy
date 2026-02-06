"""Shard redacted text for cloud verification.

Splits redacted text into sentence-level shards with UUID identifiers,
neutralizes initials-based tags, and shuffles for privacy before sending
to the PII Buddy Verify API.
"""

import re
import secrets
import uuid
from dataclasses import dataclass


@dataclass
class Shard:
    """A sentence-level text shard for verification."""
    id: str
    text: str
    start: int   # character offset in source text
    end: int     # character offset in source text
    is_canary: bool = False


_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Max characters per shard (~200 tokens)
_MAX_SHARD_CHARS = 800

# Sentences shorter than this merge with predecessor
_MIN_SENTENCE_WORDS = 5


def _letter_suffix(n: int) -> str:
    """Convert index to letter suffix: 0->A, 1->B, ..., 25->Z, 26->AA."""
    if n < 26:
        return _LETTERS[n]
    return _LETTERS[n // 26 - 1] + _LETTERS[n % 26]


def neutralize_tags(text: str, mapping: dict) -> tuple[str, dict]:
    """Replace initials-based tags with generic sequential tags.

    Converts ``<<SJ>>`` to ``<<PERSON_A>>``, ``<<EMAIL_1>>`` to
    ``<<EMAIL_A>>``, etc.  This prevents initials-based re-identification
    when shards are sent to the cloud.

    Returns:
        (neutralized_text, reverse_map) where reverse_map maps
        neutralized tag -> original tag for later reassembly.
    """
    tags = mapping.get("tags", {})

    person_tags = []
    typed_tags: dict[str, list[str]] = {}

    for tag in tags:
        inner = tag.strip("<>")
        # Person tags: letters + optional collision digit (SJ, SJ2, ABC)
        if re.match(r"^[A-Z]+\d*$", inner):
            person_tags.append(tag)
        else:
            # Typed tags: EMAIL_1, PHONE_2, ADDR_1, etc.
            m = re.match(r"^([A-Z]+)_\d+$", inner)
            if m:
                typed_tags.setdefault(m.group(1), []).append(tag)

    reverse_map: dict[str, str] = {}

    for i, tag in enumerate(sorted(person_tags)):
        neutral = f"<<PERSON_{_letter_suffix(i)}>>"
        reverse_map[neutral] = tag

    for entity_type in sorted(typed_tags):
        for i, tag in enumerate(sorted(typed_tags[entity_type])):
            neutral = f"<<{entity_type}_{_letter_suffix(i)}>>"
            reverse_map[neutral] = tag

    # Replace original tags with neutralized versions.
    # Sort by original tag length descending to avoid partial replacements.
    result = text
    for neutral, original in sorted(
        reverse_map.items(), key=lambda x: len(x[1]), reverse=True
    ):
        result = result.replace(original, neutral)

    return result, reverse_map


def shard_text(text: str, nlp) -> list[Shard]:
    """Split text into sentence-level shards using spaCy.

    - Merges sentences under ``_MIN_SENTENCE_WORDS`` with predecessor.
    - Caps shards at ``_MAX_SHARD_CHARS`` (~200 tokens), splitting at
      whitespace boundaries.
    """
    doc = nlp(text)
    raw = [(sent.text, sent.start_char, sent.end_char) for sent in doc.sents]

    if not raw:
        stripped = text.strip()
        if stripped:
            return [Shard(id=str(uuid.uuid4()), text=stripped, start=0, end=len(text))]
        return []

    # Merge short sentences with predecessor
    merged: list[tuple[str, int, int]] = []
    for sent_text, start, end in raw:
        if merged and len(sent_text.split()) < _MIN_SENTENCE_WORDS:
            _, prev_start, _ = merged[-1]
            merged[-1] = (text[prev_start:end], prev_start, end)
        else:
            merged.append((sent_text, start, end))

    # Cap at _MAX_SHARD_CHARS per shard
    capped: list[tuple[str, int, int]] = []
    for chunk_text, start, end in merged:
        if len(chunk_text) <= _MAX_SHARD_CHARS:
            capped.append((chunk_text, start, end))
            continue

        # Split at whitespace boundaries
        pos = start
        remaining = chunk_text
        while remaining:
            if len(remaining) <= _MAX_SHARD_CHARS:
                capped.append((remaining, pos, pos + len(remaining)))
                break
            split_at = remaining.rfind(" ", 0, _MAX_SHARD_CHARS)
            if split_at <= 0:
                split_at = _MAX_SHARD_CHARS
            capped.append((remaining[:split_at], pos, pos + split_at))
            pos += split_at
            remaining = remaining[split_at:].lstrip()
            pos += 1  # account for stripped whitespace

    # Assign UUIDs, drop empty shards
    shards = []
    for chunk_text, start, end in capped:
        stripped = chunk_text.strip()
        if stripped:
            shards.append(Shard(
                id=str(uuid.uuid4()),
                text=stripped,
                start=start,
                end=end,
            ))

    return shards


def shuffle_shards(shards: list[Shard]) -> list[Shard]:
    """Cryptographically random shuffle. Returns a new shuffled list."""
    result = list(shards)
    secrets.SystemRandom().shuffle(result)
    return result


def build_context(mapping: dict, doc_type: str = "general") -> dict:
    """Build entity-count-only context header from mapping.

    Returns counts of each entity type (e.g. {"PERSON": 3, "EMAIL": 2})
    without exposing tag values or initials.
    """
    counts: dict[str, int] = {}
    for tag in mapping.get("tags", {}):
        inner = tag.strip("<>")
        if re.match(r"^[A-Z]+\d*$", inner):
            counts["PERSON"] = counts.get("PERSON", 0) + 1
        else:
            m = re.match(r"^([A-Z]+)_\d+$", inner)
            if m:
                etype = m.group(1)
                counts[etype] = counts.get(etype, 0) + 1

    return {"entity_counts": counts, "document_type": doc_type}
