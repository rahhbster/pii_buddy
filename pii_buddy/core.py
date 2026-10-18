"""Pure, in-memory check / redact / restore.

No file, clipboard or log I/O, no prints, and no reading of user preferences:
callers (CLI, local API, MCP) own persistence and options. Errors are CoreError with a stable
`code` and a fixed message that never contains input.

LATENCY: `core` has NO latency bound. The only size limit is MAX_TEXT_CHARS,
measured in characters. spaCy is superlinear on some inputs: "!" * 50_000
(single-character tokens) is quadratic and did not finish in 90 s (about 250 s
extrapolated); a dot run in the middle of a chunk such as "a" + "." * 49998 +
"b", or 25,000 line breaks, take 6-8 s on a quiet machine. Legitimate inputs
at the cap (for example a 5,000-SSN CSV) typically take a few seconds, up to
~10 s on a loaded machine. A caller that needs a bound (the HTTP / MCP server)
must run `core` in a worker process with a hard timeout of at least 30 s.
CoreError pickles, so it crosses that process boundary intact.

TYPES: parameters must be exactly `str`, `dict` and `bool`. Subclasses
(including OrderedDict and bool-likes such as 0 or "") are rejected with
CoreError("invalid_request"): a subclass can override __len__, __eq__,
__hash__ or items() and bypass the caps or raise a bare exception. Plain
json.load results are exact types and work unchanged.
"""

from __future__ import annotations

import functools
import re
import types
from collections import Counter
from dataclasses import dataclass, field
from . import audit as _audit
from . import detector
from .redactor import redact

MAX_TEXT_CHARS = 50_000
MAX_RESTORE_TEXT_CHARS = 4 * MAX_TEXT_CHARS
MAX_RESTORE_OUTPUT_CHARS = 1_000_000
MAX_MAPPING_ENTRIES = 10_000
MAX_VALUE_CHARS = MAX_TEXT_CHARS
MAX_TAG_CHARS = 128

DOCUMENT_TYPES = frozenset({"auto", "general", "resume", "transcript"})

_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")

# [0-9], not \d: \d also matches non-ASCII digits.
_WHERE_RE = re.compile(r"[A-Za-z0-9_.]+\.py:[A-Za-z0-9_]+:[0-9]+")
_WHERE_MAX_CHARS = 160

# Python < 3.12 names comprehension frames "<listcomp>" etc. A fixed allow-list,
# not a generic strip, so no other angle-bracket name can get through.
_CODE_NAMES = {
    "<listcomp>": "listcomp",
    "<genexpr>": "genexpr",
    "<lambda>": "lambda",
    "<dictcomp>": "dictcomp",
    "<setcomp>": "setcomp",
    "<module>": "module",
}

# A wrapped exception's class name reaches logs, so it is bounded and ASCII.
_EXC_TYPE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_EXC_TYPE_FALLBACK = "Exception"

# Bounded and '<'-free inside NAME tags so scanning stays linear and a tag
# can never swallow a following one.
TAG_RE = re.compile(r"<<[A-Za-z0-9_]{1,100}_\d{1,9}>>|<NAME [^<>\r\n]{1,100}>")


class CoreError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        exc_type: str | None = None,
        where: str | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        # Class name of a wrapped internal exception, for logs. Never its message.
        self.exc_type = exc_type
        # "file.py:function:lineno" of the innermost frame; never locals,
        # source text or the exception message. None unless it is safe.
        self.where = where

    def __reduce__(self):
        # Default exception pickling replays only args=(message,), which
        # __init__ rejects. Rebuild from the four fixed fields; the chain
        # (__cause__ / __context__) is deliberately not carried.
        return (type(self), (self.code, self.message, self.exc_type, self.where))

    def to_dict(self) -> dict:
        d = {"error": self.code, "message": self.message}
        if _where_ok(self.where):
            d["where"] = self.where
        return d


def _where_ok(where) -> bool:
    try:
        return (
            type(where) is str
            and str.__len__(where) <= _WHERE_MAX_CHARS
            and _WHERE_RE.fullmatch(where) is not None
        )
    except Exception:
        return False


@dataclass(frozen=True)
class Finding:
    type: str
    start_offset: int
    end_offset: int
    confidence: float

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class CheckResult:
    findings: tuple
    entity_counts: dict

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "entity_counts": dict(self.entity_counts),
        }


@dataclass(frozen=True)
class RedactResult:
    redacted_text: str = field(repr=False)
    mapping: dict = field(repr=False)
    findings: tuple
    entity_counts: dict
    audit_additions: int

    def to_dict(self) -> dict:
        return {
            "redacted_text": self.redacted_text,
            "mapping": dict(self.mapping),
            "findings": [f.to_dict() for f in self.findings],
            "entity_counts": dict(self.entity_counts),
            "audit_additions": self.audit_additions,
        }


def _is_subclass_of(value, base) -> bool:
    # type(value), never isinstance(): isinstance falls back to value.__class__,
    # which a hostile object can make raise or lie.
    return issubclass(type(value), base)


def _require_str(value, what, code="invalid_text"):
    if type(value) is str:
        return
    failed = False
    subclass = False
    try:
        subclass = _is_subclass_of(value, str)
    except Exception:
        failed = True
    if failed:
        raise CoreError("invalid_request", f"{what} must be a string")
    if subclass:
        raise CoreError("invalid_request", f"{what} must be a plain string")
    raise CoreError(code, f"{what} must be a string")


def _check_input(text, document_type):
    _require_str(text, "text")
    if str.__len__(text) > MAX_TEXT_CHARS:
        raise CoreError(
            "payload_too_large", f"text exceeds {MAX_TEXT_CHARS} characters"
        )
    _require_str(document_type, "document_type", "invalid_request")
    if document_type not in DOCUMENT_TYPES:
        raise CoreError("invalid_document_type", "unknown document_type")
    # A regex search, not text.encode(): a UnicodeEncodeError carries the whole
    # input in .object and would stay reachable as CoreError.__context__.
    if _SURROGATE_RE.search(text) is not None:
        raise CoreError("invalid_text", "text is not valid unicode")


def _scrubbed(fn):
    """Re-raise a CoreError with a traceback that holds none of the caller's data.

    A traceback keeps every frame it passed through alive, with their locals
    (the text, the entities, the mapping). The error is re-raised from here
    after the arguments are dropped, so only this frame is left in it.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        failed = None
        try:
            return fn(*args, **kwargs)
        except CoreError as exc:
            failed = exc
        args = kwargs = None
        raise failed.with_traceback(None)

    return wrapper


def _guarded(fn, *args):
    """Run one pipeline step; any Exception becomes a fixed-message CoreError.

    The raise happens after the except block so neither __cause__ nor
    __context__ can carry the original exception (and the input it holds).
    BaseException (KeyboardInterrupt, SystemExit) is not caught.
    """
    no_model = False
    failed = None
    where = None
    try:
        return fn(*args)
    except detector.ModelNotInstalledError:
        no_model = True
    except Exception as exc:
        failed = _safe_type_name(exc)
        where = _capture_where(exc)
    if no_model:
        raise CoreError("model_unavailable", "no spaCy model is installed")
    raise CoreError("internal_error", "internal error", failed, where)


def _safe_type_name(exc):
    try:
        name = type(exc).__name__
        if type(name) is str and _EXC_TYPE_RE.fullmatch(name):
            return name
    except Exception:
        pass
    return _EXC_TYPE_FALLBACK


def _capture_where(exc):
    """"file.py:function:lineno" of the innermost frame; None on any doubt.

    Never raises: a hostile exception can make __traceback__ itself raise.
    """
    try:
        tb = exc.__traceback__
        if type(tb) is not types.TracebackType:
            return None
        while tb.tb_next is not None:
            tb = tb.tb_next
        code = tb.tb_frame.f_code
        name = code.co_name
        name = _CODE_NAMES.get(name, name)
        base = code.co_filename.replace("\\", "/").rsplit("/", 1)[-1]
        where = f"{base}:{name}:{tb.tb_lineno}"
        return where if _where_ok(where) else None
    except Exception:
        return None


def _detect(text, document_type):
    _guarded(detector.get_nlp, False)
    return _guarded(detector.detect_pii, text, document_type)


def _findings(entities) -> tuple:
    return tuple(
        Finding(e.label, e.start, e.end, e.confidence) for e in entities
    )


def _counts(entities) -> dict:
    return dict(sorted(Counter(e.label for e in entities).items()))


@_scrubbed
def check_text(text: str, *, document_type: str = "auto") -> CheckResult:
    _check_input(text, document_type)
    entities = _detect(text, document_type)
    return CheckResult(_findings(entities), _counts(entities))


@_scrubbed
def redact_text(
    text: str, *, document_type: str = "auto", audit: bool = True
) -> RedactResult:
    if type(audit) is not bool:
        raise CoreError("invalid_request", "audit must be true or false")
    _check_input(text, document_type)
    entities = _detect(text, document_type)
    redacted, mapping = _guarded(redact, text, entities)
    before = len(mapping["tags"])
    if audit:
        redacted, mapping = _guarded(_audit.audit_redacted, redacted, mapping)
    tags = dict(mapping["tags"])
    # A tag restore_text would refuse must fail here, not at restore time.
    _validate_mapping(tags)
    return RedactResult(
        redacted_text=redacted,
        mapping=tags,
        findings=_findings(entities),
        entity_counts=_counts(entities),
        audit_additions=len(tags) - before,
    )


def _check_no_surrogates(*strings) -> None:
    for s in strings:
        if _SURROGATE_RE.search(s) is not None:
            raise CoreError("invalid_text", "text is not valid unicode")


def _check_mapping_types(mapping) -> None:
    if type(mapping) is not dict:
        failed = False
        subclass = False
        try:
            subclass = _is_subclass_of(mapping, dict)
        except Exception:
            failed = True
        if failed or subclass:
            raise CoreError("invalid_request", "mapping must be a plain dict")
        raise CoreError("invalid_mapping", "mapping must be an object")
    for tag, value in mapping.items():
        for item in (tag, value):
            if type(item) is not str:
                failed = False
                subclass = False
                try:
                    subclass = _is_subclass_of(item, str)
                except Exception:
                    failed = True
                if failed or subclass:
                    raise CoreError("invalid_request", "mapping must hold plain strings")
                raise CoreError("invalid_mapping", "mapping must map strings to strings")


def _validate_mapping(mapping) -> None:
    _check_mapping_types(mapping)
    if len(mapping) > MAX_MAPPING_ENTRIES:
        raise CoreError("invalid_mapping", "mapping has too many entries")
    for tag, value in mapping.items():
        _check_no_surrogates(tag, value)
        if str.__len__(tag) > MAX_TAG_CHARS or TAG_RE.fullmatch(tag) is None:
            raise CoreError("invalid_mapping", "mapping key is not a tag")
        if str.__len__(value) > MAX_VALUE_CHARS:
            raise CoreError("invalid_mapping", "mapping value is too long")


@_scrubbed
def restore_text(redacted_text: str, mapping: dict[str, str]) -> str:
    """Swap tags back for their originals in one pass (restored text is never rescanned).

    `mapping` must be a plain dict, never a path. Always validates: size caps,
    tag-shaped keys only, bounded output.
    """
    _require_str(redacted_text, "text")
    if str.__len__(redacted_text) > MAX_RESTORE_TEXT_CHARS:
        raise CoreError("payload_too_large", "text is too large")
    _check_no_surrogates(redacted_text)
    _validate_mapping(mapping)
    if not mapping:
        return redacted_text

    pieces = []
    pos = 0
    size = 0
    for m in TAG_RE.finditer(redacted_text):
        value = mapping.get(m.group())
        if value is None:
            continue
        pieces.append(redacted_text[pos:m.start()])
        pieces.append(value)
        size += m.start() - pos + len(value)
        if size > MAX_RESTORE_OUTPUT_CHARS:
            raise CoreError("payload_too_large", "restored text is too large")
        pos = m.end()
    if size + len(redacted_text) - pos > MAX_RESTORE_OUTPUT_CHARS:
        raise CoreError("payload_too_large", "restored text is too large")
    pieces.append(redacted_text[pos:])
    return "".join(pieces)


@_scrubbed
def _restore_unchecked(redacted_text: str, mapping: dict) -> str:
    """Restore from the caller's own mapping file (imported only by restorer.py).

    NOT a public API: no output bound, no size caps. The HTTP / MCP server
    must never call it; use restore_text.

    No size caps and no tag-shape check, so hand-edited keys and large
    mappings keep working; the type check stays and empty keys are ignored.
    Never expose this to API input: it has no output bound.
    """
    _require_str(redacted_text, "text")
    _check_mapping_types(mapping)
    keys = [t for t in mapping if t]
    if not keys:
        return redacted_text
    pattern = re.compile("|".join(re.escape(t) for t in sorted(keys, key=len, reverse=True)))
    return pattern.sub(lambda m: mapping[m.group()], redacted_text)
