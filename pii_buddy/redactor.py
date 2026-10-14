"""Replace detected PII with reversible tags and produce a mapping file."""

import re
from bisect import bisect_right


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


_LETTER = "A-Za-z\u00c0-\u024f"
_CJK_RE = re.compile(
    "[\u2e80-\u9fff\u3400-\u4dbf\uf900-\ufaff\uac00-\ud7af\u3040-\u30ff]"
)
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


def _name_pattern(surfaces, left_boundary=True) -> "re.Pattern":
    """Whole-name matcher: letter-only boundaries, CJK surfaces unanchored.

    Underscores, digits and CJK glued to a name still match; a trailing plural
    or possessive is tolerated and left in place after the tag.
    left_boundary=False drops the left anchor (used for CamelCase continuations).
    """
    left = rf"(?<![{_LETTER}])" if left_boundary else ""
    alts = []
    for s in sorted(surfaces, key=len, reverse=True):
        esc = re.escape(s)
        if _CJK_RE.search(s):
            alts.append(esc)
        else:
            alts.append(
                rf"{left}{esc}(?:(?=(?:'s|\u2019s|s)?(?![{_LETTER}]))"
                r"|(?<=(?-i:[a-z]))(?=(?-i:[A-Z])))"
            )
    return re.compile("|".join(alts), re.IGNORECASE)


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
    # Detected entities win; spans are never rewritten by the name pass, and
    # inserted tags are never re-scanned.
    spans = []
    last_end = 0
    for ent in sorted(entities, key=lambda e: (e.start, e.start - e.end)):
        if ent.start < last_end:
            continue
        if ent.label == "PERSON":
            tag = surface_to_tag.get(ent.text, f"<NAME {_make_initials(ent.text)}>")
        else:
            tag = value_to_tag.get(ent.text, f"<<{ent.label}>>")
        spans.append((ent.start, ent.end, tag))
        last_end = ent.end

    # --- Also catch whole-word name references that spaCy missed ---
    # Longest surface first so "Steve Johnson" wins over "Steve".
    if surface_to_tag:
        lowered = {}
        for surface in sorted(surface_to_tag, key=len, reverse=True):
            lowered.setdefault(surface.lower(), surface_to_tag[surface])
        name_re = _name_pattern(surface_to_tag)
        glued_re = _name_pattern(surface_to_tag, left_boundary=False)
        entity_starts = [s[0] for s in spans]
        entity_spans = list(spans)
        for m in name_re.finditer(text):
            i = bisect_right(entity_starts, m.start()) - 1
            if i >= 0 and entity_spans[i][1] > m.start():
                continue
            if i + 1 < len(entity_spans) and entity_spans[i + 1][0] < m.end():
                continue
            spans.append((m.start(), m.end(), lowered[m.group().lower()]))
            # "AnnTestperson": a name glued to the next by a lower->Upper hump.
            end = m.end()
            while end < len(text) and text[end].isupper() and text[end - 1].islower():
                g = glued_re.match(text, end)
                if not g:
                    break
                if end < len(text) and entity_spans:
                    j = bisect_right(entity_starts, end) - 1
                    if j >= 0 and entity_spans[j][1] > end:
                        break
                    if j + 1 < len(entity_spans) and entity_spans[j + 1][0] < g.end():
                        break
                spans.append((g.start(), g.end(), lowered[g.group().lower()]))
                end = g.end()

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
