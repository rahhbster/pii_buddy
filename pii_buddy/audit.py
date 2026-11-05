"""Pass 2 — Structural self-audit of redacted text.

Scans redacted output for PII that the spaCy + regex pass likely missed,
using pattern matching around existing tags and known person names.
Runs locally with no external dependencies.
"""

import logging
import re
from bisect import bisect_right

from .redactor import TAG_RE, _TAG_SHAPED_RE, _make_initials
from .validation import LOWER_CLASS, UPPER_CLASS, _get_blocklist

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

# Unicode forms of the patterns above ("Núñez", "O'Brien", "Anne-Marie").
# They only ADD findings: the ASCII patterns stay, so nothing they found is
# lost to a different tiling of the same words. The new phrase forms stay
# within one line.
_U, _L = UPPER_CLASS, LOWER_CLASS
_NAME_WORD = rf"{_U}{_L}*(?:['’]{_U}{_L}+|-{_U}{_L}+)*"
_WORD_END = r"(?![\w'’-])"
_TITLE_U_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Professor|Rev|Judge|Hon)"
    rf"\.?[^\S\n]+({_NAME_WORD}(?:[^\S\n]+{_NAME_WORD})?){_WORD_END}"
)
_CAP_PHRASE_U_RE = re.compile(
    rf"(?<![\w'’-])({_NAME_WORD}(?:[^\S\n]+{_NAME_WORD}){{1,2}}){_WORD_END}"
)
_POSSESSIVE_U_RE = re.compile(rf"(?<![\w'’-])({_NAME_WORD})['’]s\b")
_CONJ_AFTER_U_RE = re.compile(
    rf"<NAME [^<>\r\n]+>[^\S\n]+and[^\S\n]+({_NAME_WORD}(?:[^\S\n]+{_NAME_WORD})?){_WORD_END}"
)
_CONJ_BEFORE_U_RE = re.compile(
    rf"(?<![\w'’-])({_NAME_WORD}(?:[^\S\n]+{_NAME_WORD})?)[^\S\n]+and[^\S\n]+<NAME [^<>\r\n]+>"
)

# A capitalized fragment glued to a NAME tag: the redactor's substring sweep
# cut a word ("Placehol<NAME VDB>" from "Placeholder" and "Der").
_GLUED_RE = re.compile(rf"(?<![\w'’-])({_U}{_L}{{2,}})(?=<NAME )")

# A lone capitalized word beside a NAME tag on the same line is usually the
# other half of the name ("Uma <NAME KS>", "<NAME LE> Ibáñez").
_BESIDE_TAG_RES = (
    re.compile(rf"(?<![\w'’-])({_NAME_WORD})[^\S\n]+(?=<NAME )"),
    re.compile(rf"<NAME [^<>\r\n]+>[^\S\n]+({_NAME_WORD}){_WORD_END}"),
)
_HONORIFICS = {"mr", "mrs", "ms", "miss", "dr", "prof", "professor", "rev",
               "hon", "sir", "dame"}

# Capitalized only because they open a sentence or a greeting; as a lone
# neighbour of a tag they are not the other half of a name, and the substring
# sweep would otherwise spread them ("whenever", "ours"). Fail closed: any word
# that is also a plausible given name or surname (April, May, June, Jan, March,
# Per, Even, Ask, Sun, Best, Senior, Head, Judge, ...) stays OUT of this list.
_COMMON_WORDS = _HONORIFICS | {
    # greetings and sign-offs
    "hi", "hello", "hey", "dear", "thanks", "thank", "regards", "cheers",
    "welcome", "congrats", "congratulations", "sincerely", "attn",
    # weekdays and the months that are not names
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "mon", "tue", "tues", "wed", "thu", "thur", "thurs", "fri",
    "january", "february", "september", "october", "november", "december",
    "feb", "sept", "oct", "nov",
    # function words
    "the", "and", "but", "nor", "for", "yet", "our", "ours", "your", "yours",
    "his", "her", "hers", "its", "their", "theirs", "she", "they", "them",
    "you", "who", "whom", "whose", "what", "when", "where", "while", "why",
    "how", "which", "that", "this", "these", "those", "then", "than", "there",
    "here", "with", "without", "from", "into", "onto", "over", "under", "about",
    "after", "before", "since", "until", "during", "via", "also", "both",
    "each", "every", "all", "any", "some", "many", "most", "much", "only",
    "just", "later", "again", "once", "today", "tomorrow", "yesterday",
    "tonight", "please", "contact", "meet", "met", "call", "called", "email",
    "see", "fwd",
    # job titles (no seniority words: Senior, Junior, Chief, Head are surnames)
    "associate", "assistant", "intern", "manager", "director", "president",
    "engineer", "analyst", "developer", "consultant", "officer", "executive",
    "team", "former", "acting", "interim",
}

# Existing tag patterns (to skip already-tagged text)
_NAME_TAG_RE = re.compile(r"<NAME\s+[A-Z]+\d*>")
_TYPED_TAG_RE = re.compile(r"<<[A-Z]+_\d+>>")


def _letters(s: str) -> int:
    return sum(c.isalpha() for c in s)


def _long_words(phrase: str, n: int = 3) -> bool:
    return all(_letters(w) >= n for w in phrase.split())


def _collect_known_names(mapping: dict) -> set[str]:
    """Extract all known person surface forms from the mapping."""
    names = set()
    for surface in mapping.get("persons", {}):
        names.add(surface.lower())
        for part in surface.split():
            if len(part) >= 3:
                names.add(part.lower())
    return names


class _Spans:
    """Disjoint, sorted tag spans; membership by bisect, not a scan."""

    def __init__(self, spans):
        merged = []
        for s, e in sorted(spans):
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        self.pairs = [tuple(p) for p in merged]
        self._starts = [p[0] for p in merged]

    def __iter__(self):
        return iter(self.pairs)

    def inside(self, pos: int) -> bool:
        i = bisect_right(self._starts, pos) - 1
        return i >= 0 and pos < self.pairs[i][1]


def _tag_spans(text: str, tags=None) -> _Spans:
    """Spans restore would swap back: TAG_RE matches that are mapping keys.

    With no mapping, every tag-shaped span counts (unit-level callers).
    """
    spans = [(m.start(), m.end()) for m in TAG_RE.finditer(text)
             if tags is None or m.group() in tags]
    if tags is None:
        for pattern in (_NAME_TAG_RE, _TYPED_TAG_RE):
            spans += [(m.start(), m.end()) for m in pattern.finditer(text)]
    return _Spans(spans)


def _is_already_tagged(text: str, start: int, end: int, spans=None) -> bool:
    """Check if position falls inside an existing tag."""
    if spans is None:
        spans = _tag_spans(text)
    elif not isinstance(spans, _Spans):
        spans = _Spans(spans)
    return spans.inside(start) or (end > start and spans.inside(end - 1))


def _check_orphaned_conjunctions(text: str, spans=None) -> list[str]:
    """Find 'CapWord and <NAME XX>' or '<NAME XX> and CapWord' patterns."""
    findings = []

    # Pattern: <NAME XX> and CapitalizedWord
    for m in re.finditer(
        r"<NAME\s+[A-Z]+\d*>\s+and\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\b",
        text,
    ):
        candidate = m.group(1)
        if not _is_already_tagged(text, m.start(1), m.end(1), spans):
            findings.append(candidate)

    # Pattern: CapitalizedWord and <NAME XX>
    for m in re.finditer(
        r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\s+and\s+<NAME\s+[A-Z]+\d*>",
        text,
    ):
        candidate = m.group(1)
        if not _is_already_tagged(text, m.start(1), m.end(1), spans):
            findings.append(candidate)

    for pattern in (_CONJ_AFTER_U_RE, _CONJ_BEFORE_U_RE):
        for m in pattern.finditer(text):
            candidate = m.group(1)
            if (_long_words(candidate)
                    and not _is_already_tagged(text, m.start(1), m.end(1), spans)):
                findings.append(candidate)

    return findings


def _check_title_prefixed(text: str, spans=None) -> list[str]:
    """Find 'Mr./Mrs./Dr./Prof.' followed by an untagged capitalized word."""
    findings = []
    for pattern in (_TITLE_RE, _TITLE_U_RE):
        group = pattern.groups
        for m in pattern.finditer(text):
            name = m.group(group)
            if _letters(name) < 2:
                continue
            if not _is_already_tagged(text, m.start(group), m.end(group), spans):
                findings.append(name)
    return findings


# Every window, not one left-to-right tiling: a tiling depends on which words
# are already tagged, so a better first pass could shift it and leave a word
# of a longer run uncovered.
_CAP_WINDOW_RES = tuple(
    re.compile(f"(?=({p.pattern}))") for p in (_CAP_PHRASE_RE, _CAP_PHRASE_U_RE)
)


def _check_capitalized_phrases(text: str, blocklist: set[str], spans=None) -> list[str]:
    """Find remaining 2-3 capitalized word sequences that aren't tagged or blocklisted."""
    findings = []
    for pattern in _CAP_WINDOW_RES:
        for m in pattern.finditer(text):
            phrase = m.group(2)
            if _is_already_tagged(text, m.start(2), m.end(2), spans):
                continue
            if phrase.lower() in blocklist:
                continue
            # Skip if any word is very short (likely not a name)
            words = phrase.split()
            if not _long_words(phrase):
                continue
            # Must have at least 2 words
            if len(words) >= 2:
                findings.append(phrase)
    return findings


def _check_possessive_references(text: str, known_names: set[str], spans=None) -> list[str]:
    """Find CapWord's where CapWord matches a known first/last name."""
    findings = []
    for pattern in (_POSSESSIVE_RE, _POSSESSIVE_U_RE):
        for m in pattern.finditer(text):
            word = m.group(1)
            if (word.lower() in known_names
                    and not _is_already_tagged(text, m.start(1), m.end(1), spans)):
                findings.append(word)
    return findings


def _check_glued_fragments(text: str, spans=None) -> list[str]:
    """Find a capitalized word fragment that runs straight into a NAME tag."""
    return [m.group(1) for m in _GLUED_RE.finditer(text)
            if m.group(1).lower() not in _COMMON_WORDS
            and not _is_already_tagged(text, m.start(1), m.end(1), spans)]


def _check_beside_tags(text: str, blocklist: set[str], spans=None) -> list[str]:
    """Find a single capitalized word right before or after a NAME tag."""
    findings = []
    for pattern in _BESIDE_TAG_RES:
        for m in pattern.finditer(text):
            word = m.group(1)
            if (_letters(word) >= 3 and word.lower() not in _COMMON_WORDS
                    and word.lower() not in blocklist
                    and not _is_already_tagged(text, m.start(1), m.end(1), spans)):
                findings.append(word)
    return findings


def _covered_runs(text: str, findings: list[str], spans) -> list[tuple[int, int]]:
    """Every case-insensitive occurrence of every finding, outside existing tags.

    Planned against the input text and merged, so one finding can never land
    inside a tag another one inserted.
    """
    covered = bytearray(len(text))
    if findings:
        # One pass for all findings, longest first so each position covers the
        # longest one that starts there; the lookahead finds overlapping
        # occurrences ("Ann Lee Ann" in "Ann Lee Ann Lee Ann").
        alternatives = "|".join(
            re.escape(f) for f in sorted(set(findings), key=len, reverse=True))
        for m in re.finditer(f"(?=({alternatives}))", text, re.IGNORECASE):
            covered[m.start(1):m.end(1)] = b"\x01" * (m.end(1) - m.start(1))
    for s, e in spans:
        covered[s:e] = b"\x00" * (e - s)
    runs = []
    i = covered.find(1)
    while i != -1:
        j = covered.find(0, i)
        if j == -1:
            j = len(text)
        runs.append((i, j))
        i = covered.find(1, j)
    return runs


# A tag added in one round can expose a neighbour ("Ciarán <NAME W>") that
# only the next round sees.
_MAX_ROUNDS = 3


def audit_redacted(redacted_text: str, mapping: dict) -> tuple[str, dict]:
    """Run structural audit on redacted text, apply additional redactions.

    Returns (patched_text, updated_mapping). Existing tags keep their
    originals, and every new tag maps to exactly the text it replaced, so
    restore gives back the input.
    """
    patched, updated = redacted_text, mapping
    for _ in range(_MAX_ROUNDS):
        nxt, updated = _audit_once(patched, updated)
        if nxt == patched:
            break
        patched = nxt
    return patched, updated


def _audit_once(redacted_text: str, mapping: dict) -> tuple[str, dict]:
    blocklist = _get_blocklist()
    known_names = _collect_known_names(mapping)
    tags = dict(mapping.get("tags", {}))
    persons = dict(mapping.get("persons", {}))
    spans = _tag_spans(redacted_text, tags)

    # Collect all findings
    all_findings: list[str] = []
    all_findings.extend(_check_orphaned_conjunctions(redacted_text, spans))
    all_findings.extend(_check_title_prefixed(redacted_text, spans))
    all_findings.extend(_check_capitalized_phrases(redacted_text, blocklist, spans))
    all_findings.extend(_check_possessive_references(redacted_text, known_names, spans))
    all_findings.extend(_check_glued_fragments(redacted_text, spans))
    all_findings.extend(_check_beside_tags(redacted_text, blocklist, spans))

    # Deduplicate
    seen = set()
    unique_findings = []
    for f in all_findings:
        if f.lower() not in seen and f.lower() not in blocklist:
            seen.add(f.lower())
            unique_findings.append(f)
    # Skip if already a tag or inside a tag
    unique_findings = [f for f in unique_findings if "<NAME " not in f and "<<" not in f]

    runs = _covered_runs(redacted_text, unique_findings, spans)
    finding_set = set(unique_findings)
    if not runs:
        return redacted_text, mapping

    # A new tag must be neither an existing key nor literal tag-shaped text,
    # or restore would swap the wrong thing back.
    used = set(tags)
    used.update(m.group(1) for m in _TAG_SHAPED_RE.finditer(redacted_text))
    used.update(m.group() for m in TAG_RE.finditer(redacted_text))
    by_value = {}
    for tag, value in tags.items():
        by_value.setdefault(value, tag)

    pieces = []
    pos = 0
    added = set()
    for start, end in runs:
        pii_text = redacted_text[start:end]
        tag = by_value.get(pii_text)
        if tag is None:
            initials = "".join(c for c in _make_initials(pii_text) if c.isalpha())[:20] or "X"
            n = 1
            while True:
                tag = f"<NAME {initials}>" if n == 1 else f"<NAME {initials}{n}>"
                n += 1
                if tag not in used:
                    break
            used.add(tag)
            tags[tag] = pii_text
            by_value[pii_text] = tag
            added.add(tag)
        # Only whole findings: a fragment such as "li" (from "reliable")
        # would let watcher._redact_filename rewrite unrelated filenames.
        if pii_text in finding_set:
            persons.setdefault(pii_text, tag)
        pieces.append(redacted_text[pos:start])
        pieces.append(tag)
        pos = end
    pieces.append(redacted_text[pos:])
    patched = "".join(pieces)

    logger.info(f"  Audit: {len(runs)} additional redactions applied ({len(added)} new tags)")

    updated_mapping = dict(mapping)
    updated_mapping["tags"] = tags
    updated_mapping["persons"] = persons
    return patched, updated_mapping
