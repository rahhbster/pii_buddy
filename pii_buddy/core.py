"""Pure, in-memory check / redact / restore.

No file, clipboard or log I/O, no prints, and no reading of user preferences:
callers (CLI, local API, MCP) own persistence and options. Errors are CoreError with a stable
`code` and a fixed message that never contains input.

LATENCY: `core` has NO latency bound. The only size limit is MAX_TEXT_CHARS,
measured in characters. spaCy can take many seconds on pathological inputs
(for example a 50,000-character run of one-character tokens, a dot run in the
middle of a chunk such as "a" + "." * 49998 + "b", or very name-dense text,
about 2.5 s after the validation speed-up). A caller that needs a bound (the
HTTP / MCP server) must run `core` under a hard timeout in a worker process.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Mapping

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

# Bounded and '<'-free inside NAME tags so scanning stays linear and a tag
# can never swallow a following one.
TAG_RE = re.compile(r"<<[A-Za-z0-9_]{1,100}_\d{1,9}>>|<NAME [^<>\r\n]{1,100}>")


class CoreError(ValueError):
    def __init__(self, code: str, message: str, exc_type: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        # Class name of a wrapped internal exception, for logs. Never its message.
        self.exc_type = exc_type

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message}


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


def _check_input(text, document_type):
    if not isinstance(text, str):
        raise CoreError("invalid_text", "text must be a string")
    if len(text) > MAX_TEXT_CHARS:
        raise CoreError(
            "payload_too_large", f"text exceeds {MAX_TEXT_CHARS} characters"
        )
    if not isinstance(document_type, str):
        raise CoreError("invalid_request", "document_type must be a string")
    if document_type not in DOCUMENT_TYPES:
        raise CoreError("invalid_document_type", "unknown document_type")
    # A regex search, not text.encode(): a UnicodeEncodeError carries the whole
    # input in .object and would stay reachable as CoreError.__context__.
    if _SURROGATE_RE.search(text) is not None:
        raise CoreError("invalid_text", "text is not valid unicode")


def _guarded(fn, *args):
    """Run one pipeline step; any Exception becomes a fixed-message CoreError.

    The raise happens after the except block so neither __cause__ nor
    __context__ can carry the original exception (and the input it holds).
    BaseException (KeyboardInterrupt, SystemExit) is not caught.
    """
    no_model = False
    failed = None
    try:
        return fn(*args)
    except detector.ModelNotInstalledError:
        no_model = True
    except Exception as exc:
        failed = type(exc).__name__
    if no_model:
        raise CoreError("model_unavailable", "no spaCy model is installed")
    raise CoreError("internal_error", "internal error", failed)


def _detect(text, document_type):
    _guarded(detector.get_nlp, False)
    return _guarded(detector.detect_pii, text, document_type)


def _findings(entities) -> tuple:
    return tuple(
        Finding(e.label, e.start, e.end, e.confidence) for e in entities
    )


def _counts(entities) -> dict:
    return dict(sorted(Counter(e.label for e in entities).items()))


def check_text(text: str, *, document_type: str = "auto") -> CheckResult:
    _check_input(text, document_type)
    entities = _detect(text, document_type)
    return CheckResult(_findings(entities), _counts(entities))


def redact_text(
    text: str, *, document_type: str = "auto", audit: bool = True
) -> RedactResult:
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
    if not isinstance(mapping, dict):
        raise CoreError("invalid_mapping", "mapping must be an object")
    for tag, value in mapping.items():
        if not isinstance(tag, str) or not isinstance(value, str):
            raise CoreError("invalid_mapping", "mapping must map strings to strings")


def _validate_mapping(mapping) -> None:
    _check_mapping_types(mapping)
    if len(mapping) > MAX_MAPPING_ENTRIES:
        raise CoreError("invalid_mapping", "mapping has too many entries")
    for tag, value in mapping.items():
        _check_no_surrogates(tag, value)
        if len(tag) > MAX_TAG_CHARS or TAG_RE.fullmatch(tag) is None:
            raise CoreError("invalid_mapping", "mapping key is not a tag")
        if len(value) > MAX_VALUE_CHARS:
            raise CoreError("invalid_mapping", "mapping value is too long")


def restore_text(redacted_text: str, mapping: Mapping[str, str]) -> str:
    """Swap tags back for their originals in one pass (restored text is never rescanned).

    `mapping` must be a plain dict, never a path. Always validates: size caps,
    tag-shaped keys only, bounded output.
    """
    if not isinstance(redacted_text, str):
        raise CoreError("invalid_text", "text must be a string")
    if len(redacted_text) > MAX_RESTORE_TEXT_CHARS:
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
    pieces.append(redacted_text[pos:])
    return "".join(pieces)


def _restore_unchecked(redacted_text: str, mapping: dict) -> str:
    """Restore from the caller's own mapping file (imported only by restorer.py).

    No size caps and no tag-shape check, so hand-edited keys and large
    mappings keep working; the type check stays and empty keys are ignored.
    Never expose this to API input: it has no output bound.
    """
    if not isinstance(redacted_text, str):
        raise CoreError("invalid_text", "text must be a string")
    _check_mapping_types(mapping)
    keys = [t for t in mapping if t]
    if not keys:
        return redacted_text
    pattern = re.compile("|".join(re.escape(t) for t in sorted(keys, key=len, reverse=True)))
    return pattern.sub(lambda m: mapping[m.group()], redacted_text)
