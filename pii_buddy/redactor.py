"""Replace detected PII with reversible tags and produce a mapping file."""

import re
from collections import defaultdict


def _make_initials(name: str) -> str:
    """Turn 'Steve Johnson' into 'SJ', 'Mary' into 'M'."""
    parts = name.strip().split()
    return "".join(p[0].upper() for p in parts if p)


def _group_names(person_entities: list) -> dict[str, str]:
    """
    Group name variants that refer to the same person.

    If we see "Steve Johnson" and later just "Steve", both map to the same tag.
    Returns {surface_form: canonical_full_name}.
    """
    # Collect all unique name strings, longest first
    names = sorted(set(e.text for e in person_entities), key=len, reverse=True)

    canonical = {}  # surface_form -> full_name
    for name in names:
        if name in canonical:
            continue
        # Check if this name is a component of an already-seen longer name
        matched = False
        for full in canonical.values():
            full_parts = full.lower().split()
            if name.lower() in full_parts:
                canonical[name] = full
                matched = True
                break
        if not matched:
            canonical[name] = name

    return canonical


def redact(text: str, entities: list) -> tuple[str, dict]:
    """
    Replace PII entities with tags. Returns (redacted_text, mapping).

    The mapping dict can be saved as JSON for later reversal:
    {
        "tags": {"<<SJ>>": "Steve Johnson", "<<EMAIL_1>>": "steve@co.com", ...},
        "persons": {"Steve Johnson": "<<SJ>>", "Steve": "<<SJ>>"},
    }
    """
    person_entities = [e for e in entities if e.label == "PERSON"]
    other_entities = [e for e in entities if e.label != "PERSON"]

    # --- Build person tag assignments ---
    name_groups = _group_names(person_entities)

    # Assign initials-based tags, handling collisions
    initials_count = defaultdict(int)
    canonical_to_tag = {}

    for canonical_name in sorted(set(name_groups.values())):
        initials = _make_initials(canonical_name)
        initials_count[initials] += 1
        if initials_count[initials] > 1:
            tag = f"<<{initials}{initials_count[initials]}>>"
        else:
            tag = f"<<{initials}>>"
        canonical_to_tag[canonical_name] = tag

    # Map every surface form to its tag
    surface_to_tag = {}
    for surface, canonical in name_groups.items():
        surface_to_tag[surface] = canonical_to_tag[canonical]

    # --- Build tags for other entity types ---
    type_counters = defaultdict(int)
    value_to_tag = {}  # dedup: same email appearing twice gets same tag

    for ent in other_entities:
        if ent.text in value_to_tag:
            continue
        type_counters[ent.label] += 1
        n = type_counters[ent.label]
        tag = f"<<{ent.label}_{n}>>"
        value_to_tag[ent.text] = tag

    # --- Perform replacements (work from end to start to preserve positions) ---
    all_entities = sorted(entities, key=lambda e: e.start, reverse=True)
    redacted = text

    for ent in all_entities:
        if ent.label == "PERSON":
            tag = surface_to_tag.get(ent.text, f"<<{_make_initials(ent.text)}>>")
        else:
            tag = value_to_tag.get(ent.text, f"<<{ent.label}>>")
        redacted = redacted[:ent.start] + tag + redacted[ent.end:]

    # --- Also catch person name references that spaCy missed ---
    # Sort by length descending so "Steve Johnson" is replaced before "Steve"
    for surface in sorted(surface_to_tag, key=len, reverse=True):
        tag = surface_to_tag[surface]
        # Replace remaining occurrences that weren't entity-tagged
        # Use word boundaries to avoid partial matches
        pattern = re.compile(re.escape(surface), re.IGNORECASE)
        redacted = pattern.sub(tag, redacted)

    # --- Build the reversible mapping ---
    tag_to_original = {}
    for surface, tag in surface_to_tag.items():
        # Store the canonical (longest) name as the primary value
        canonical = name_groups[surface]
        tag_to_original[tag] = canonical
    for value, tag in value_to_tag.items():
        tag_to_original[tag] = value

    mapping = {
        "tags": tag_to_original,
        "persons": {surface: surface_to_tag[surface] for surface in surface_to_tag},
    }

    return redacted, mapping
