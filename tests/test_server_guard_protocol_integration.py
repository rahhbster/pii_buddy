"""guard -> protocol seam: whatever ``guard.check_request`` admits and labels
with ``Decision.route`` must be dispatched by ``protocol.handle`` under that
exact string.  Fake token and port; the core is the deterministic stand-in."""

import json

import pytest

from pii_buddy.server import guard, protocol
from tests._protocol_helpers import RID, install_fake_core

TOKEN = "fake-token_AbCdEf0123456789-ZyXwVu_9876543210"
PORT = 8123

SIX = {
    "GET /v1/health", "GET /v1/usage", "POST /v1/check",
    "POST /v1/redact", "POST /v1/restore", "POST /mcp",
}


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    install_fake_core(monkeypatch)


def _admit(method, path, obj=None):
    body = b"" if obj is None else json.dumps(obj).encode()
    headers = [
        ("Host", "127.0.0.1:%d" % PORT),
        ("Authorization", "Bearer " + TOKEN),
    ]
    if method == "POST":
        headers += [("Content-Type", "application/json"),
                    ("Content-Length", str(len(body)))]
    d = guard.check_request(method, path, headers, expected_ports=(PORT,), token=TOKEN)
    assert d.allowed is True, d
    return d, body


def _through(method, path, obj=None, usage=None):
    d, body = _admit(method, path, obj)
    usage = usage if usage is not None else protocol.UsageCounter()
    resp = protocol.handle(d.route, body if method == "POST" else None,
                           request_id=RID, usage=usage)
    return d, resp


def _rpc(method, params=None):
    m = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        m["params"] = params
    return m


class TestEveryAdmittedRouteIsDispatched:
    def test_health(self):
        d, r = _through("GET", "/v1/health")
        assert d.route == "GET /v1/health"
        assert (r.status, json.loads(r.body)) == (200, {"ok": True})

    def test_usage(self):
        u = protocol.UsageCounter()
        u.increment()
        d, r = _through("GET", "/v1/usage", usage=u)
        assert d.route == "GET /v1/usage"
        b = json.loads(r.body)
        assert r.status == 200 and b["requests_served"] == 1 and b["period"] == "local"

    def test_check(self):
        d, r = _through("POST", "/v1/check", {"text": "mail a@b.c now"})
        assert d.route == "POST /v1/check"
        b = json.loads(r.body)
        assert r.status == 200 and b["entity_counts"] == {"EMAIL": 1}
        assert r.entity_count == 1

    def test_redact(self):
        d, r = _through("POST", "/v1/redact", {"text": "mail a@b.c now"})
        assert d.route == "POST /v1/redact"
        b = json.loads(r.body)
        assert r.status == 200 and "mapping" in b and r.entity_count == 1

    def test_restore(self):
        d, r = _through("POST", "/v1/restore",
                        {"redacted_text": "hi <<EMAIL_1>>", "mapping": {"<<EMAIL_1>>": "a@b.c"}})
        assert d.route == "POST /v1/restore"
        assert (r.status, json.loads(r.body)) == (200, {"text": "hi a@b.c"})
        assert r.entity_count is None

    def test_mcp_ping_and_tool_call(self):
        d, r = _through("POST", "/mcp", _rpc("ping"))
        assert d.route == "POST /mcp"
        assert (r.status, json.loads(r.body)) == (
            200, {"jsonrpc": "2.0", "id": 1, "result": {}})
        _, r = _through("POST", "/mcp", _rpc(
            "tools/call", {"name": "pii_check", "arguments": {"text": "a@b.c"}}))
        res = json.loads(r.body)["result"]
        assert r.status == 200 and res["isError"] is False
        assert res["structuredContent"]["entity_counts"] == {"EMAIL": 1}

    def test_mcp_notification_is_202(self):
        d, body = _admit("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"})
        r = protocol.handle(d.route, body, request_id=RID, usage=protocol.UsageCounter())
        assert (r.status, r.body) == (202, b"")


class TestRouteSetsCannotDrift:
    def test_guard_emits_exactly_the_six(self):
        emitted = {
            _admit("GET", "/v1/health")[0].route,
            _admit("GET", "/v1/usage")[0].route,
            _admit("POST", "/v1/check", {"text": "x"})[0].route,
            _admit("POST", "/v1/redact", {"text": "x"})[0].route,
            _admit("POST", "/v1/restore", {})[0].route,
            _admit("POST", "/mcp", {})[0].route,
        }
        assert emitted == SIX

    def test_guard_table_equals_protocol_table(self):
        from_guard = {"%s %s" % (m, p) for p, ms in guard._ROUTES.items() for m in ms}
        assert from_guard == SIX
        assert protocol.ROUTES == from_guard
        assert isinstance(protocol.ROUTES, frozenset)

    def test_every_route_the_guard_can_emit_is_handled(self):
        for route in {"%s %s" % (m, p) for p, ms in guard._ROUTES.items() for m in ms}:
            r = protocol.handle(route, b"{}", request_id=RID, usage=protocol.UsageCounter())
            assert not (r.status == 404 and json.loads(r.body).get("error") == "not_found"), route


class TestTolerant404:
    @pytest.mark.parametrize("route", [
        "health", "check", "redact", "restore", "usage", "mcp",
        "POST /v1/health", "GET /v1/check", "GET /mcp", "POST /v1/nope",
        "get /v1/health", "POST  /mcp", "POST /mcp ", "", None, 5, b"POST /mcp",
    ])
    def test_unknown_route_is_404(self, route):
        r = protocol.handle(route, b"{}", request_id=RID, usage=protocol.UsageCounter())
        assert r.status == 404
        assert json.loads(r.body)["error"] == "not_found"
