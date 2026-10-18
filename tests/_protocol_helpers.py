"""Shared helpers for the protocol tests: a fast deterministic stand-in for
core (real input validation, fake detection) and small call wrappers."""

import json

from pii_buddy import core
from pii_buddy.server import protocol

HEADERS = (
    ("Content-Type", "application/json"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
)
RID = "r_00ab12cd"
CANARY = "Zq7f3a9cXk"

# The exact strings guard.Decision.route carries; protocol must dispatch on these.
ROUTE = {
    "health": "GET /v1/health",
    "usage": "GET /v1/usage",
    "check": "POST /v1/check",
    "redact": "POST /v1/redact",
    "restore": "POST /v1/restore",
    "mcp": "POST /mcp",
}


def _findings(text):
    if type(text) is str and "@" in text:
        return (core.Finding("EMAIL", 0, len(text), 0.5),)
    return ()


def _counts(findings):
    return {"EMAIL": len(findings)} if findings else {}


def fake_check_text(text, *, document_type="auto"):
    core._check_input(text, document_type)
    f = _findings(text)
    return core.CheckResult(f, _counts(f))


def fake_redact_text(text, *, document_type="auto", audit=True):
    if type(audit) is not bool:
        raise core.CoreError("invalid_request", "audit must be true or false")
    core._check_input(text, document_type)
    f = _findings(text)
    mapping = {"<<EMAIL_1>>": text} if f else {}
    return core.RedactResult(
        "R%d" % len(text), mapping, f, _counts(f), 1 if audit else 0
    )


def install_fake_core(monkeypatch):
    monkeypatch.setattr(protocol.core, "check_text", fake_check_text)
    monkeypatch.setattr(protocol.core, "redact_text", fake_redact_text)


def raw(obj):
    return json.dumps(obj).encode()


def call(route, obj=None, *, usage=None, rid=RID):
    usage = usage if usage is not None else protocol.UsageCounter()
    if obj is None:
        body = None
    elif isinstance(obj, bytes):
        body = obj
    else:
        body = raw(obj)
    return protocol.handle(ROUTE.get(route, route), body, request_id=rid, usage=usage)


def jbody(resp):
    return json.loads(resp.body)
