"""Replace detected PII with reversible tags and produce a mapping file."""

import re


def _make_initials(name: str) -> str:
    """Turn 'Steve Johnson' into 'SJ', 'Mary' into 'M'."""
    parts = name.strip().split()
    return "".join(p[0].upper() for p in parts if p)


def _group_names(person_entities: list) -> dict[str, str]:
    """
    Group name variants that refer to the same person.

    If we see "Steve Johnson" and later just "Steve", both map to the same tag.
    Also adds individual parts of multi-word names (first name, last name) so
    partial references like just "Steve" are caught even if not detected as entities.
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

    # Add individual parts of multi-word names as surface forms
    for name in list(canonical):
        parts = name.split()
        if len(parts) >= 2:
            full = canonical[name]
            for part in parts:
                if len(part) >= 3 and part not in canonical:
                    canonical[part] = full

    return canonical


_TAG_SHAPED_RE = re.compile(r"(?=(<<[A-Za-z0-9_]+_\d+>>|<NAME [^>]+>))")


class _TagAllocator:
    """Hands out tags that are neither literal source text nor already assigned.

    The source is scanned once; each key keeps a counter that only moves forward.
    """

    def __init__(self, text: str):
        self._literal = {m.group(1) for m in _TAG_SHAPED_RE.finditer(text)}
        self._used = set()
        self._next = {}

    def allocate(self, key, make_tag) -> str:
        n = self._next.get(key, 1)
        while True:
            tag = make_tag(n)
            n += 1
            if tag not in self._literal and tag not in self._used:
                self._next[key] = n
                self._used.add(tag)
                return tag


def redact(text: str, entities: list) -> tuple[str, dict]:
    """
    Replace PII entities with tags. Returns (redacted_text, mapping).

    The mapping dict can be saved as JSON for later reversal:
    {
        "tags": {"<NAME SJ>": "Steve Johnson", "<<EMAIL_1>>": "steve@co.com", ...},
        "persons": {"Steve Johnson": "<NAME SJ>", "Steve": "<NAME SJ>"},
    }
    """
    person_entities = [e for e in entities if e.label == "PERSON"]
    other_entities = [e for e in entities if e.label != "PERSON"]

    # --- Build person tag assignments ---
    name_groups = _group_names(person_entities)

    # Tags that already appear in the source are skipped so restore() can
    # never mistake a literal tag in the document for one we generated.
    tags = _TagAllocator(text)
    canonical_to_tag = {}

    for canonical_name in sorted(set(name_groups.values())):
        initials = _make_initials(canonical_name)
        tag = tags.allocate(
            ("NAME", initials),
            lambda n, i=initials: f"<NAME {i}>" if n == 1 else f"<NAME {i}{n}>",
        )
        canonical_to_tag[canonical_name] = tag

    # Map every surface form to its tag
    surface_to_tag = {}
    for surface, canonical in name_groups.items():
        surface_to_tag[surface] = canonical_to_tag[canonical]

    # --- Build tags for other entity types ---
    value_to_tag = {}  # dedup: same email appearing twice gets same tag

    for ent in other_entities:
        if ent.text in value_to_tag:
            continue
        tag = tags.allocate(
            ("OTHER", ent.label), lambda n, label=ent.label: f"<<{label}_{n}>>"
        )
        value_to_tag[ent.text] = tag

    # --- Plan every replacement against the ORIGINAL text, then apply once ---
    # `claimed` marks characters already assigned to a tag, so nothing can match
    # inside an inserted tag or inside another entity's span.
    claimed = bytearray(len(text))
    spans = []

    def claim(start, end, tag, partial_ok):
        if claimed.find(1, start, end) == -1:
            claimed[start:end] = b"\x01" * (end - start)
            spans.append((start, end, tag))
            return
        if not partial_ok:
            return
        # Overlapping detected entities: tag only the part not yet covered.
        i = start
        while i < end:
            if claimed[i]:
                i += 1
                continue
            j = i
            while j < end and not claimed[j]:
                j += 1
            claimed[i:j] = b"\x01" * (j - i)
            spans.append((i, j, tag))
            i = j

    for ent in sorted(entities, key=lambda e: (e.start, e.start - e.end)):
        start, end = max(ent.start, 0), min(ent.end, len(text))
        if end <= start:
            continue
        if ent.label == "PERSON":
            tag = surface_to_tag.get(ent.text, f"<NAME {_make_initials(ent.text)}>")
        else:
            tag = value_to_tag.get(ent.text, f"<<{ent.label}>>")
        claim(start, end, tag, True)

    # --- Also catch name references that spaCy missed ---
    # Case-insensitive substring match, longest surface first so
    # "Steve Johnson" wins over "Steve". One pattern per surface keeps the
    # match -> tag mapping exact (no .lower() round trip).
    for surface in sorted(surface_to_tag, key=len, reverse=True):
        tag = surface_to_tag[surface]
        for m in re.finditer(re.escape(surface), text, re.IGNORECASE):
            claim(m.start(), m.end(), tag, False)

    pieces = []
    pos = 0
    for start, end, tag in sorted(spans):
        pieces.append(text[pos:start])
        pieces.append(tag)
        pos = end
    pieces.append(text[pos:])
    redacted = "".join(pieces)

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
