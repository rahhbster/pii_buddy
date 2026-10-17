"""Detect PII in text using spaCy NER + regex patterns + validation."""

from __future__ import annotations

import bisect
import re
import threading
import unicodedata
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
# Two bounded alternatives start inside a run: right after a hyphen
# ("--x@y.io") and at a "- + . _ %" that follows a letter or digit
# ("a@b.co+c@d.io", where main's word boundary started the match at the "+"),
# so the glue character is covered too. The 64-character cap keeps each start
# constant-time. The TLD class keeps main's "|" ("[A-Z|a-z]"), so a pipe that
# closes an address stays covered as it was on main. A single "@" ahead of the
# local part is taken with it: HANDLE_RE hands "@jane@host.tld" to this pattern,
# and the "@" would otherwise stay visible.
EMAIL_RE = re.compile(
    r"(?:(?:(?<![\w@])@(?=[A-Za-z0-9._%+-]+@))?(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+"
    r"|(?<=-)[A-Za-z0-9._%+-]{1,64}"
    r"|(?<=[A-Za-z0-9])(?=[-+._%])[A-Za-z0-9._%+-]{1,64})"
    r"@[A-Za-z0-9.-]+\.[A-Za-z|]{2,}\b"
    r"(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)*"
)

PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?1[-.\s]?)?"
    r"(?:\(?\d{3}\)?[-.\s]?)"
    r"\d{3}[-.\s]?\d{4}"
    r"(?!\d)"
)

_INTL_BODY = (
    r"(?<!\+)\+(?:"
    r"\d{1,3}[\s.-]?(?:\(0\)[\s.-]?)?\d{1,5}(?:[\s.-]\d{2,8}){1,5}"
    r"|\d{8,15}"
    r")(?!\d)"
)
# "(?![-/]\d)" stops the tail from eating the head of a following SSN or date
# ("+33 1 42 68 53 00 123-45-6789"). The unnarrowed pattern is kept as a
# fallback so a tail that is not really another item stays redacted.
INTL_PHONE_RE = re.compile(_INTL_BODY + r"(?![-/]\d)")
INTL_PHONE_WIDE_RE = re.compile(_INTL_BODY)

# Card groups may be split by a space, hyphen, any Unicode space (NBSP, narrow
# NBSP, thin space from PDF extraction) or dash (en/em dash, minus). Luhn still
# gates every match.
_CSEP = r"[ \-\u00a0\u2000-\u200a\u202f\u2010-\u2015\u2212]"
# CARD_RE only finds a run of up to six digit groups that starts where no digit
# precedes it (a hyphen or letter before it is a separator, so "ab-4111 ..." is
# found) and is at least four digits long; _check_card decides what is a card.
# Starts are bounded to run starts and every repetition is bounded, so each
# start does constant work. A run that begins mid-way through a longer one is
# reached from its own start.
CARD_RE = re.compile(
    rf"(?<!\d)\d{{4,128}}(?:{_CSEP}\d{{1,128}}){{0,5}}"
)
# Separated numbers count as a card only in a standard grouping: 4-4-4-4,
# 4-6-5 (Amex), 4-6-4 (Diners), 4-4-8, 8-8, or the short last groups 4-4-4-3,
# 4-4-4-2, 4-4-4-1 (15-, 14- and 13-digit PANs). A trailing 1-4 digit group is
# absorbed when the whole is a valid PAN ("4111 1111 1111 111 1", 4-4-4-4-3).
# Anything else ("INV-5642-29793087-1525", "91-4066-4944-80939-07") is an
# ordinary hyphenated ID, not a card. The flag says the last group may carry
# glued digits ("4111 1111 1111 1111326", as PDF extraction produces); the whole
# group is then redacted. The first group may likewise carry glued leading
# digits ("123 45 67894111 1111 1111 1111") and is redacted whole. An unseparated
# run of 13-19 digits is a candidate whatever the grouping.
_CARD_SHAPES = (
    ((4, 4, 4, 4), True), ((4, 4, 4, 4, 3), True), ((4, 6, 5), True), ((4, 6, 4), True),
    ((4, 4, 8), True), ((8, 8), True),
    ((4, 4, 4, 3), True), ((4, 4, 4, 2), True), ((4, 4, 4, 1), True),
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
# The hyphen-glued start ("10.0.0.1-example.com") is capped at 4 labels: every
# hyphen is a start, and an uncapped or deeper run rescans the same labels from
# each one (quadratic; 4 keeps the worst 400 KB shape near 0.5 s).
_URL_TAIL = r"(?::\d{1,5})?(?:[/?#][^\s<>\"']*)?"
BARE_URL_RE = re.compile(
    r"(?:(?<![\w.@-])(?:[A-Za-z0-9-]+\.)+|(?<=-)(?:[A-Za-z0-9-]{1,63}\.){1,4})(?:"
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
_LINE_LOOKBACK = 256
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


_LUHN_DOUBLE = str.maketrans("0123456789", "0246813579")


def _luhn_ok(digits: str) -> bool:
    if digits.isascii():
        # Byte sums at C speed: each byte is 48 + digit, so subtract 48 per
        # digit; every second digit from the right is doubled (and folded) by
        # the translate table.
        total = (sum(digits[-1::-2].encode())
                 + sum(digits[-2::-2].translate(_LUHN_DOUBLE).encode()))
        return (total - 48 * len(digits)) % 10 == 0
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


_CSEP_TO_SPACE = {c: 32 for c in
                  [0x20, 0x2D, 0xA0, *range(0x2000, 0x200B), 0x202F,
                   *range(0x2010, 0x2016), 0x2212]}
_SHAPES_BY_SECOND: dict[int, list] = {}
for _shape, _glue in _CARD_SHAPES:
    # Keyed by the second group's length; 9 stands for "longer than 8" (the
    # glued last group of 8-8).
    _SHAPES_BY_SECOND.setdefault(_shape[1], []).append(
        (_shape, _glue, list(_shape[1:-1])))
_SHAPES_BY_SECOND[9] = [s for s in _SHAPES_BY_SECOND[8] if len(s[0]) == 2]


def _card_reach(groups, lens, last: int, digits: str, absorb_tail: bool) -> int:
    """Index of the last group a PAN ending at group ``last`` reaches, or -1.
    A valid PAN swallows one short trailing group so no digits are left
    visible; an invalid base may still be a valid PAN with that group."""
    nxt = last + 1
    tail = absorb_tail and nxt < len(groups) and lens[nxt] <= 4
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return nxt if tail else last
    if tail:
        both = digits + groups[nxt]
        if 13 <= len(both) <= 19 and _luhn_ok(both):
            return nxt
    return -1


def _check_card(m: re.Match, text: str):
    groups = m.group().translate(_CSEP_TO_SPACE).split(" ")
    n = len(groups)
    g0 = groups[0]
    if n == 1:
        return m.span() if 13 <= len(g0) <= 19 and _luhn_ok(g0) else None
    lens = [len(g) for g in groups]
    if sum(lens) < 13:
        return None
    best = -1  # index of the last group the card (plus its tail) reaches
    if 13 <= lens[0] <= 19:
        best = _card_reach(groups, lens, 0, g0, True)
    second = lens[1]
    for shape, glue, mid in _SHAPES_BY_SECOND.get(second if second <= 8 else 9, ()):
        k = len(shape)
        if k > n or lens[0] < shape[0]:
            continue
        last = lens[k - 1]
        if last < shape[-1] or (last > shape[-1] and not glue):
            continue
        if lens[1:k - 1] != mid:
            continue
        head = g0[-shape[0]:] + "".join(groups[1:k - 1])
        if last > shape[-1] and shape != (4, 4, 4, 4):
            # glued digits close the card at group k-1; nothing follows
            if best < k - 1 and _luhn_ok(head + groups[k - 1][:shape[-1]]):
                best = k - 1
            continue
        # A group that carries glued digits closes the card (no tail after it),
        # except 4-4-4-4 with up to three glued digits, where a trailing group
        # was always absorbed ("4111 1111 1111 1111078 12").
        r = _card_reach(groups, lens, k - 1, head + groups[k - 1][:shape[-1]],
                        last == shape[-1] or (shape == (4, 4, 4, 4) and last <= 7))
        if r > best:
            best = r
        if shape == (4, 4, 4, 4) and 4 < last <= 7:
            r = _card_reach(groups, lens, k - 1, head + groups[k - 1], True)
            if r > best:
                best = r
    if best < 0:
        return None
    return m.start(), m.start() + sum(lens[:best + 1]) + best


_INTL_SEP_RE = re.compile(r"[\s.-]")


def _check_intl_phone(m: re.Match, text: str):
    raw = m.group()
    if 8 <= len(re.sub(r"\D", "", raw)) <= 15:
        return m.span()
    # Too many digits: the tail ran into the next number. Cut at the longest
    # group boundary that is still a phone number instead of dropping it.
    fallback = None
    for sep in reversed(list(_INTL_SEP_RE.finditer(raw))):
        head = raw[:sep.start()]
        n = len(re.sub(r"\D", "", head))
        if n < 8 or n > 15 or not head[-1].isdigit():
            continue
        end = m.start() + sep.start()
        if not re.match(r"[-/]\d", text[end:end + 2]):
            return m.start(), end
        fallback = fallback or (m.start(), end)
    return fallback


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
        # Bounded lookback: an unbounded rfind is quadratic on one huge line.
        # A line start further back than the window is read as prose (redact).
        lo = max(0, start - _LINE_LOOKBACK)
        nl = text.rfind("\n", lo, start)
        line_start = nl + 1 if nl >= 0 else (0 if lo == 0 else None)
        if (line_start is not None
                and not text[line_start:start].strip()
                and _CODE_CONTEXT_RE.match(text, end)):
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


class ModelNotInstalledError(RuntimeError):
    """No spaCy model is installed and downloading was not allowed."""


def _load_spacy(allow_download=True):
    import spacy
    for model in (SPACY_MODEL, SPACY_FALLBACK):
        try:
            return spacy.load(model)
        except OSError:
            pass
    if not allow_download:
        raise ModelNotInstalledError(
            f"No spaCy model installed (need {SPACY_MODEL} or {SPACY_FALLBACK}); "
            f"run: python -m spacy download {SPACY_MODEL}"
        )
    # Download fallback
    import spacy.cli
    print(f"Downloading spaCy model {SPACY_FALLBACK} (one-time)...")
    spacy.cli.download(SPACY_FALLBACK)
    return spacy.load(SPACY_FALLBACK)


_nlp = None
_warmed = False
_load_lock = threading.Lock()
# spaCy pipelines are not documented as thread-safe; every nlp() call takes this.
_nlp_lock = threading.Lock()


def get_nlp(allow_download=True):
    global _nlp
    if _nlp is None:
        with _load_lock:
            if _nlp is None:
                _nlp = _load_spacy(allow_download)
    return _nlp


def preflight():
    """Load and pre-warm the model without ever downloading or printing.

    Raises ModelNotInstalledError if no model is installed. Idempotent.
    """
    global _warmed
    nlp = get_nlp(allow_download=False)
    with _nlp_lock:
        if not _warmed:
            nlp("Warm up.")
            _warmed = True


# Cost model for spaCy's English tokenizer, calibrated by timing the real
# tokenizer in subprocesses (units x templates x body families, then re-timed
# at the size where the estimate reaches the budget). Only three things are
# super-linear, all in whitespace-free chunks:
#  1. The affix loop. Each iteration strips one prefix and/or suffix and costs
#     a regex scan of the whole remaining chunk (~250-660 ns/char, digit-rich
#     bodies are slowest). Iterations = the leading run of prefix characters
#     plus the trailing run of suffix characters, including the letter-bearing
#     literals "US$" "C$" "A$" (prefix) and "'s" "'S" (suffix). Punctuation in
#     the middle of a chunk (fullwidth commas, URL and base64 punctuation) is
#     never stripped and costs nothing extra.
#  2. url_match's userinfo group "\S+(?::\S*)?@": backtracking costs about one
#     scan of the chunk per ":" (~6-12 ns/char), and about one host attempt per
#     ":" x "@" pair (~70 ns).
#  3. Nothing else: infix matching, lexeme creation and everything else is
#     linear (at most ~3 us/char measured, ~5 us/char budgeted).
# The constants below carry a 1.5-2x margin over the worst measurement.
_AFFIX_CATEGORIES = frozenset(("Pc", "Pd", "Pe", "Pf", "Pi", "Po", "Ps", "Sc", "Sk", "Sm", "So"))
_NOT_AFFIX_CHARS = frozenset("@|\\")  # empirically never split from a chunk edge
_PREFIX_LITERALS = ("US$", "C$", "A$")
_SUFFIX_LITERALS = ("'s", "'S", "\u2019s", "\u2019S")
_NS_PER_CHAR = 5000
_NS_PER_CHAR_PER_STRIP = 1000
_NS_PER_CHAR_PER_COLON = 20
_NS_PER_COLON_PER_AT = 120


def _is_affix_char(ch: str) -> bool:
    return ch not in _NOT_AFFIX_CHARS and unicodedata.category(ch) in _AFFIX_CATEGORIES


def _affix_strips(chunk: str) -> int:
    """Upper bound on affix-loop iterations for a whitespace-free chunk."""
    n = len(chunk)
    strips = 0
    i = 0
    while i < n:
        if chunk.startswith(_PREFIX_LITERALS, i):
            i += 3 if chunk.startswith("US$", i) else 2
        elif _is_affix_char(chunk[i]):
            i += 1
        else:
            break
        strips += 1
    j = n
    while j > i:
        if chunk.endswith(_SUFFIX_LITERALS, i, j):
            j -= 2
        elif _is_affix_char(chunk[j - 1]):
            j -= 1
        else:
            break
        strips += 1
    return min(strips, n)


def tokenizer_cost(text: str) -> int:
    """Upper-bound estimate, in microseconds, of the time spaCy's English
    tokenizer needs for `text` on a typical laptop core.

    Linear time, never calls the tokenizer. See the cost-model comment above
    for what is and is not charged; callers compare the result with a budget.
    """
    total = _NS_PER_CHAR * len(text)
    for chunk in text.split():
        n = len(chunk)
        total += n * _NS_PER_CHAR_PER_STRIP * _affix_strips(chunk)
        colons = chunk.count(":")
        if colons:
            total += colons * (n * _NS_PER_CHAR_PER_COLON + chunk.count("@") * _NS_PER_COLON_PER_AT)
    return total // 1000


def count_tokens(text: str) -> int:
    """Token count by the tokenizer alone (no pipeline); takes the spaCy lock.

    Callers must bound `tokenizer_cost(text)` first. Requires the model to be
    loaded (get_nlp(allow_download=False) first).
    """
    nlp = get_nlp(allow_download=False)
    with _nlp_lock:
        return len(nlp.make_doc(text))


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


_OVERLAPPING = frozenset({CARD_RE, DOB_RE})


def _iter_matches(pattern, text: str, overlapping: bool):
    """finditer; with ``overlapping`` the scan resumes one character after each
    match start, so a match cannot swallow a real one that starts inside it
    ("415.555.0132 5500 0000 0000 0004" must still yield the card, and
    "10.0.0.1/12/25/1990" the date). The resolver handles the overlaps."""
    if not overlapping:
        yield from pattern.finditer(text)
        return
    pos = 0
    while True:
        m = pattern.search(text, pos)
        if m is None:
            return
        yield m
        pos = m.start() + 1


def _regex_entities(text: str) -> list[PIIEntity]:
    entities = []
    for pattern, label in REGEX_PATTERNS:
        check = _SPAN_CHECKS.get(pattern)
        for match in _iter_matches(pattern, text, pattern in _OVERLAPPING):
            span = check(match, text) if check else match.span()
            if span is None:
                continue
            entities.append(PIIEntity(
                text=text[span[0]:span[1]],
                label=label,
                start=span[0],
                end=span[1],
                confidence=1.0,
            ))
    return entities


# Overlap priority, highest first. Longest span only breaks a tie within a
# label. A loser is never dropped: its un-overlapped remainder is kept.
_PRIORITY = {
    label: rank for rank, label in enumerate(
        "EMAIL URL CARD SSN PHONE IP HANDLE DOB ID_NUMBER ADDRESS PERSON".split()
    )
}
_LABEL_PATTERNS: dict[str, list] = {}
for _pat, _lab in REGEX_PATTERNS:
    _LABEL_PATTERNS.setdefault(_lab, []).append(_pat)


def _remainder_entities(ent: PIIEntity, pieces, text: str) -> list[PIIEntity]:
    out = []
    for s, e in pieces:
        while s < e and text[s].isspace():
            s += 1
        while e > s and text[e - 1].isspace():
            e -= 1
        if s >= e:
            continue
        piece = text[s:e]
        plausible = any(p.fullmatch(piece) for p in _LABEL_PATTERNS.get(ent.label, ()))
        out.append(PIIEntity(
            text=piece,
            label=ent.label,
            start=s,
            end=e,
            confidence=ent.confidence if plausible else min(ent.confidence, 0.5),
        ))
    return out


class _SpanSet:
    """Disjoint intervals kept sorted; bisect keeps lookups near-linear."""

    def __init__(self, spans=()):
        self.starts: list[int] = []
        self.ends: list[int] = []
        for s, e in spans:
            self.add(s, e)

    def add(self, s: int, e: int) -> None:
        i = bisect.bisect_left(self.starts, s)
        self.starts.insert(i, s)
        self.ends.insert(i, e)

    def free(self, s: int, e: int) -> list[tuple[int, int]]:
        """Pieces of [s, e) not covered by any interval."""
        i = max(0, bisect.bisect_right(self.starts, s) - 1)
        pieces, pos = [], s
        while i < len(self.starts) and self.starts[i] < e:
            if self.ends[i] > pos:
                if self.starts[i] > pos:
                    pieces.append((pos, self.starts[i]))
                pos = max(pos, self.ends[i])
            i += 1
        if pos < e:
            pieces.append((pos, e))
        return pieces


def _resolve_overlaps(entities: list[PIIEntity], text: str) -> list[PIIEntity]:
    # An address inside a URL ("site.com?email=a@b.c") is part of that link:
    # the URL stays whole rather than being cut around it.
    urls = sorted((e.start, e.end) for e in entities if e.label == "URL")
    if urls:
        url_starts = [u[0] for u in urls]
        prefix_max = []
        top = -1
        for _, t in urls:
            top = max(top, t)
            prefix_max.append(top)

        def _inside_url(e: PIIEntity) -> bool:
            # a different URL span that contains the email: either one starting
            # at or before it and ending after it, or starting strictly before
            # it and ending at the same place.
            i = bisect.bisect_right(url_starts, e.start)
            if i and prefix_max[i - 1] > e.end:
                return True
            j = bisect.bisect_left(url_starts, e.start)
            return bool(j and prefix_max[j - 1] >= e.end)

        entities = [
            e for e in entities
            if not (e.label == "EMAIL" and _inside_url(e))
        ]
    ordered = sorted(
        entities,
        key=lambda e: (_PRIORITY.get(e.label, len(_PRIORITY)), -(e.end - e.start),
                       e.start, -e.confidence),
    )
    kept: list[PIIEntity] = []
    taken = _SpanSet()
    for ent in ordered:
        pieces = taken.free(ent.start, ent.end)
        if pieces == [(ent.start, ent.end)]:
            kept.append(ent)
            taken.add(ent.start, ent.end)
            continue
        for rem in _remainder_entities(ent, pieces, text):
            kept.append(rem)
            taken.add(rem.start, rem.end)
    kept.sort(key=lambda e: (e.start, e.end))
    return kept


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
    regex_entities = _regex_entities(text)

    regex_spans = [(ent.start, ent.end) for ent in regex_entities]

    # 1b. spaCy NER (names and dates)
    nlp = get_nlp()
    with _nlp_lock:
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

        if ent.label_ != "DATE" or not _is_specific_date(ent.text):
            continue
        # A regex hit inside the date wins its own characters, but whatever of
        # the date it did not cover is still a date: keep that as DOB.
        for s, e in pieces:
            while s < e and text[s].isspace():
                s += 1
            while e > s and text[e - 1].isspace():
                e -= 1
            if s < e:
                spacy_entities.append(PIIEntity(
                    text=text[s:e],
                    label="DOB",
                    start=s,
                    end=e,
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
    deduped = _resolve_overlaps(validated, text)

    # The narrowed international-phone pattern is only a better boundary; any
    # characters the old wider match covered that nothing else did stay redacted.
    taken = _SpanSet((e.start, e.end) for e in deduped)
    extra = []
    for m in INTL_PHONE_WIDE_RE.finditer(text):
        if _check_intl_phone(m, text) is None:
            continue
        wide = PIIEntity(text=m.group(), label="PHONE", start=m.start(), end=m.end())
        extra += _remainder_entities(
            wide, taken.free(m.start(), m.end()), text
        )
    deduped = sorted(deduped + extra, key=lambda e: (e.start, e.end))

    return deduped
