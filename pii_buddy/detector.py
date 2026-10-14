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

# The lookbehind pins the start to the beginning of a run of local-part
# characters; without it every position in "a.a.a.…" rescans the whole run.
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    r"(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)*"
)

PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[-.\s]?)?"
    r"(?:\(?\d{3}\)?[-.\s]?)"
    r"\d{3}[-.\s]?\d{4}"
    r"(?!\d)"
)

INTL_PHONE_RE = re.compile(
    r"(?<![\w+])\+(?:"
    r"\d{1,3}[\s.-]?(?:\(0\)[\s.-]?)?\d{1,5}(?:[\s.-]\d{2,8}){1,5}"
    r"|\d{8,15}"
    r")(?!\d)"
)

_CARD_NUMBER = r"\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}|\d{4}[ -]?\d{6}[ -]?\d{4,5}"
# The optional tail is a trailing 1-4 digit group ("4111 1111 1111 1111 123");
# _check_card absorbs it when the number before it is a valid PAN.
CARD_RE = re.compile(
    rf"(?<![\d-])(?P<base>{_CARD_NUMBER})(?P<tail>[ -]\d{{1,4}})?(?![\d-]?\d)"
)

# Separators: hyphen, en/em dash, minus, and any whitespace (tab, NBSP from PDF
# extraction). Every optional-separator shape main redacted is kept (3-2-4,
# 5-4, 3-6, 9); a dotted form needs both dots so "123.456789" decimals are left
# alone. A ZIP+4 after a state code is dropped by _check_ssn and read as ADDRESS.
_SSN_SEP = r"[-\u2010-\u2015\u2212\s]"
SSN_RE = re.compile(
    rf"\b(?:"
    rf"\d{{3}}{_SSN_SEP}?\d{{2}}{_SSN_SEP}?\d{{4}}"
    r"|\d{3}\.\d{2}\.\d{4}"
    r")\b"
)

URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
)

# Matching is case-insensitive ("JANETEST.COM") and a path, query, fragment or
# port is swallowed with the host. "file.pdf" and "Node.js" are not in the TLD
# list; the .NET family is dropped in _check_bare_url. Hosts like "tsconfig.dev",
# "settings.app", "index.ai", "model.io", "x.page", "q.me" and "r.ly" are
# indistinguishable from filenames or words, so those TLDs only count with a
# path. The negative lookahead keeps "docker-compose.com.yml"-style names out.
_URL_TAIL = r"(?::\d{1,5})?(?:[/?#][^\s<>\"']*)?"
BARE_URL_RE = re.compile(
    r"(?<![\w.@/-])(?:[A-Za-z0-9-]+\.)+(?:"
    rf"(?:com|org|net|edu|gov|info|biz|uk|co|us|ca|de|tech|xyz)\b(?!\.[A-Za-z0-9]){_URL_TAIL}"
    r"|(?:io|dev|app|ai|page|me|ly)\b(?::\d{1,5})?/[^\s<>\"']*"
    r")",
    re.IGNORECASE,
)
_NOT_HOSTS = frozenset({"asp.net", "vb.net", "ado.net"})

# Not preceded by a letter, digit or "@", so "user@host" and "a.b@c" are never
# handles but "**@jane**", ">@jane" and "_@jane_" are. Letters are Unicode-aware
# ("@jos\u00e9") and the run has no length cap. A trailing "@host" is swallowed so
# "@jane@localhost" is one span. The lookahead hands "@jane@host.tld" to EMAIL
# only when EMAIL_RE would really match that tail; otherwise it is a handle.
HANDLE_RE = re.compile(
    r"(?<![^\W_])(?<!@)@"
    r"(?![A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)"
    r"[^\W\d_][\w.-]+(?:@[\w.-]+)?(?![\w])"
)
# Decorator and at-rule names are skipped only where code puts them: at the
# start of a line and followed by "(", end of line, or a declaration keyword.
# In prose ("ask @author about it") they are redacted.
_NON_HANDLES = frozenset(
    "override property staticmethod classmethod dataclass abstractmethod "
    "cached_property wraps pytest functools deprecated overload final "
    "media import font-face keyframes supports charset container layer "
    "tailwind apply namespace page "
    "param return returns see author since throws type example todo "
    "autowired component injectable entity nullable nonnull "
    "suppresswarnings functionalinterface".split()
)
# "@pytest.fixture", "@functools.wraps(f)": only these module prefixes are
# skipped as dotted names; "@author.jane" is a handle.
_DECORATOR_NAMESPACES = frozenset(
    "pytest functools abc dataclasses typing contextlib unittest mock".split()
)
_CODE_CONTEXT_RE = re.compile(
    r"[ \t]*(?:\(|$)"
    r"|[ \t]+(?:def|class|public|private|protected|function|static|final|interface)\b",
    re.MULTILINE,
)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# A version prefix hides a dotted quad only when it is glued to it ("v10.1.2.3")
# or "version"/"build" (lower or Title case, not an all-caps label) sits one
# whitespace run away, and nothing nearby says the number is an address.
_VERSION_ATTACHED_RE = re.compile(r"\bv$", re.IGNORECASE)
_VERSION_WORD_RE = re.compile(r"\b(?:[Vv]ersion|[Bb]uild)[ \t]+$")
_IP_CONTEXT_RE = re.compile(
    r"\bip\b|host|server|address|vpn|connect|from|client"
    r"|\b(?:gateway|router|dns|ssh|ping|proxy|network|subnet|endpoint|node|ipv[46])",
    re.IGNORECASE
)
IPV4_RE = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\.?\d)")

_MONTH = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
)

DOB_RE = re.compile(
    r"\b(?:"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
    r"|(?:0?[1-9]|[12]\d|3[01])\.(?:0?[1-9]|1[0-2])\.(?:19|20)\d{2}"
    r"|(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    rf"|{_MONTH}\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{2,4}}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH},?\s+(?:19|20)\d{{2}}"
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

# A bare five-digit run is far too common (counts, ticket IDs) to redact on its
# own, so a ZIP only counts directly after a US state code.
_US_STATES = frozenset(
    "AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS "
    "MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY".split()
)
# Codes that are also ordinary uppercase words or abbreviations ("ID 12345");
# these count only when set off after a comma, as in "Boise, ID 83702".
_AMBIGUOUS_STATES = frozenset({"ID", "IN", "OR", "ME", "OK", "HI", "LA", "DE", "MA"})
ZIP_RE = re.compile(
    r"(?<![A-Za-z])(?P<state>[A-Z]{2})\.?,?[ \t]+(?P<zip>\d{5}(?:-\d{4})?)(?![\d-]?\d)"
)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _pan_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    return 13 <= len(digits) <= 19 and _luhn_ok(digits)


def _check_card(m: re.Match, text: str):
    # A valid PAN swallows a short trailing group so no digits are left visible.
    if _pan_ok(m.group("base")):
        return m.span()
    if m.group("tail") and _pan_ok(m.group()):
        return m.span()
    return None


def _check_intl_phone(m: re.Match, text: str):
    if 8 <= len(re.sub(r"\D", "", m.group())) <= 15:
        return m.span()
    return None


def _check_zip(m: re.Match, text: str):
    state = m.group("state")
    if state not in _US_STATES:
        return None
    if state in _AMBIGUOUS_STATES and not text[:m.start("state")].rstrip().endswith(","):
        return None
    return m.span("zip")


_SSN_ZIP4_RE = re.compile(r"\d{5}-\d{4}")


def _check_ssn(m: re.Match, text: str):
    # A ZIP+4 right after a state code is an address, not an SSN. Anywhere
    # else a 5-4 shape stays an SSN: a missed ID costs more than an extra tag.
    if _SSN_ZIP4_RE.fullmatch(m.group()):
        for z in ZIP_RE.finditer(text, max(0, m.start() - 12), m.end()):
            if z.start("zip") == m.start() and _check_zip(z, text) is not None:
                return None
    return m.span()


def _check_handle(m: re.Match, text: str):
    start, end = m.span()
    while end - 1 > start and text[end - 1] in ".-":
        end -= 1
    name = text[start + 1:end]
    if len(name) < 2:
        return None
    if name.casefold() in _NON_HANDLES or (
        name.split(".")[0].casefold() in _DECORATOR_NAMESPACES
    ):
        line_start = text.rfind("\n", 0, start) + 1
        if not text[line_start:start].strip() and _CODE_CONTEXT_RE.match(text, end):
            return None
    return (start, end)


def _check_ip(m: re.Match, text: str):
    before = text[max(0, m.start() - 60):m.start()]
    prefix = _VERSION_ATTACHED_RE.search(before) or _VERSION_WORD_RE.search(before)
    if prefix:
        context = before[:prefix.start()][-40:] + " " + text[m.end():m.end() + 40]
        if not _IP_CONTEXT_RE.search(context):
            return None
    return m.span()


def _check_bare_url(m: re.Match, text: str):
    end = m.end()
    while end > m.start() and text[end - 1] in ".,;:!?)]}":
        end -= 1
    if text[m.start():end].casefold() in _NOT_HOSTS:
        return None
    return (m.start(), end)


# Optional per-pattern gate: returns the (start, end) to report, or None to drop.
_SPAN_CHECKS = {
    CARD_RE: _check_card,
    INTL_PHONE_RE: _check_intl_phone,
    ZIP_RE: _check_zip,
    BARE_URL_RE: _check_bare_url,
    SSN_RE: _check_ssn,
    HANDLE_RE: _check_handle,
    IPV4_RE: _check_ip,
}

REGEX_PATTERNS = [
    (EMAIL_RE, "EMAIL"),
    (INTL_PHONE_RE, "PHONE"),
    (PHONE_RE, "PHONE"),
    (CARD_RE, "CARD"),
    (SSN_RE, "SSN"),
    (URL_RE, "URL"),
    (BARE_URL_RE, "URL"),
    (HANDLE_RE, "HANDLE"),
    (IPV4_RE, "IP"),
    (DOB_RE, "DOB"),
    (ID_NUMBER_RE, "ID_NUMBER"),
    (ADDRESS_RE, "ADDRESS"),
    (ZIP_RE, "ADDRESS"),
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


def _subtract_spans(start: int, end: int, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Return the pieces of [start, end) not covered by any of ``spans``."""
    pieces = []
    pos = start
    for s, e in sorted(spans):
        if e <= pos or s >= end:
            continue
        if s > pos:
            pieces.append((pos, s))
        pos = max(pos, e)
    if pos < end:
        pieces.append((pos, end))
    return pieces


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


def _detect_header_names(text: str) -> list[PIIEntity]:
    """Detect names in document title/header lines like '# Name1 and Name2 - Job Title'."""
    entities = []
    for line in text[:500].split('\n')[:5]:
        stripped = line.strip().lstrip('#').strip()
        if not stripped or ' - ' not in stripped:
            continue
        name_part = stripped.split(' - ', 1)[0].strip()
        # Remove trailing link/emoji artifacts
        name_part = re.sub(r'\s*[\(\[].+$', '', name_part).strip()
        candidates = re.split(r'\s+and\s+', name_part, flags=re.IGNORECASE)
        for name in candidates:
            name = name.strip()
            words = name.split()
            if 2 <= len(words) <= 4 and all(w[0:1].isupper() and w.isalpha() for w in words):
                start = text.find(name)
                if start >= 0:
                    entities.append(PIIEntity(
                        text=name,
                        label="PERSON",
                        start=start,
                        end=start + len(name),
                        confidence=0.85,
                    ))
    return entities


def _clean_person_entities(entities: list[PIIEntity]) -> list[PIIEntity]:
    """Strip job title suffixes that spaCy incorrectly includes in PERSON entities."""
    cleaned = []
    for ent in entities:
        if ent.label != "PERSON" or ' - ' not in ent.text:
            cleaned.append(ent)
            continue
        name_part = ent.text.split(' - ', 1)[0].strip()
        words = name_part.split()
        if len(words) >= 2:
            ent.text = name_part
            ent.end = ent.start + len(name_part)
        cleaned.append(ent)
    return cleaned


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
        check = _SPAN_CHECKS.get(pattern)
        for match in pattern.finditer(text):
            span = check(match, text) if check else match.span()
            if span is None:
                continue
            regex_entities.append(PIIEntity(
                text=text[span[0]:span[1]],
                label=label,
                start=span[0],
                end=span[1],
                confidence=1.0,
            ))

    regex_spans = [(ent.start, ent.end) for ent in regex_entities]

    # 1b. spaCy NER (names and dates)
    nlp = get_nlp()
    doc = nlp(text)
    spacy_entities = []

    for ent in doc.ents:
        pieces = _subtract_spans(ent.start_char, ent.end_char, regex_spans)

        if ent.label_ == "PERSON":
            # spaCy often fuses a name with an adjacent email/phone; keep the
            # name text and let the regex hit stand as its own entity.
            for s, e in pieces:
                raw = text[s:e]
                piece = raw.strip(" \t\r\n|,;:-")
                if not piece or not _basic_person_check(piece):
                    continue
                s += raw.index(piece)
                spacy_entities.append(PIIEntity(
                    text=piece,
                    label="PERSON",
                    start=s,
                    end=s + len(piece),
                ))
            continue

        if pieces != [(ent.start_char, ent.end_char)]:
            continue

        if ent.label_ == "DATE" and _is_specific_date(ent.text):
            spacy_entities.append(PIIEntity(
                text=ent.text,
                label="DOB",
                start=ent.start_char,
                end=ent.end_char,
                confidence=0.8,
            ))

    # 1c. Clean up spaCy PERSON entities (strip job title suffixes)
    spacy_entities = _clean_person_entities(spacy_entities)

    # 1d. ALL CAPS names in resume headers
    allcaps_entities = _detect_allcaps_names(text)

    # 1e. Header/title line names (e.g. "# Name1 and Name2 - Job Title")
    header_entities = _detect_header_names(text)

    # Combine all candidates
    all_candidates = regex_entities + spacy_entities + allcaps_entities + header_entities

    # --- Pass 2: Validation ---
    validated = validate_entities(all_candidates, text, doc, doc_type)

    # --- Deduplicate overlapping entities ---
    # "@jane@host.tld" is an address, not a handle followed by a stray host.
    email_spans = [(e.start, e.end) for e in validated if e.label == "EMAIL"]
    validated = [
        e for e in validated
        if not (e.label == "HANDLE"
                and any(e.start < ee and s < e.end for s, ee in email_spans))
    ]
    validated.sort(key=lambda e: (e.start, -e.confidence, -(e.end - e.start)))
    deduped = []
    last_end = -1
    for ent in validated:
        if ent.start >= last_end:
            deduped.append(ent)
            last_end = ent.end

    return deduped
