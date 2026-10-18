"""pii_buddy.server.protocol, MCP half: a JSON-RPC 2.0 subset (initialize, ping,
tools/list, tools/call), plus a seeded differential fuzz of the whole JSON-RPC
layer against an independent oracle written in this file."""

import json
import random

import pytest

import pii_buddy
from pii_buddy import core
from pii_buddy.server import protocol
from tests._protocol_helpers import (
    CANARY,
    HEADERS,
    RID,
    ROUTE,
    call,
    install_fake_core,
    jbody,
)

SUPPORTED = ("2025-06-18", "2025-03-26", "2024-11-05")
VERSION = getattr(pii_buddy, "__version__", "0")
CANARY_WINDOWS = {CANARY[i:i + 6] for i in range(len(CANARY) - 5)}


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    install_fake_core(monkeypatch)


def rpc(method, params=None, id=1, **extra):
    m = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        m["id"] = id
    if params is not None:
        m["params"] = params
    m.update(extra)
    return m


def tool(name, arguments=None, id=1, **kw):
    p = {"name": name}
    if arguments is not None:
        p["arguments"] = arguments
    return call("mcp", rpc("tools/call", p, id=id), **kw)


def err(resp, code, status=None, id=...):
    b = jbody(resp)
    assert set(b) == {"jsonrpc", "id", "error"}, b
    assert b["jsonrpc"] == "2.0"
    assert b["error"]["code"] == code, b
    assert set(b["error"]) == {"code", "message"}
    if id is not ...:
        assert b["id"] == id and type(b["id"]) is type(id)
    if status is not None:
        assert resp.status == status
    return b


# --------------------------------------------------------------- initialize

class TestInitialize:
    def test_shape(self):
        r = call("mcp", rpc("initialize", {"protocolVersion": "2025-06-18",
                                          "capabilities": {}, "clientInfo": {"name": "x"}}))
        assert r.status == 200 and r.headers == HEADERS
        assert jbody(r) == {
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "pii-buddy", "version": VERSION},
            },
        }

    @pytest.mark.parametrize("v", SUPPORTED)
    def test_echoes_supported_versions(self, v):
        r = call("mcp", rpc("initialize", {"protocolVersion": v}))
        assert jbody(r)["result"]["protocolVersion"] == v

    @pytest.mark.parametrize("v", ["1999-01-01", "", "2099-12-31", "2025-06-18 ", "latest"])
    def test_unsupported_gets_newest(self, v):
        r = call("mcp", rpc("initialize", {"protocolVersion": v}))
        assert jbody(r)["result"]["protocolVersion"] == "2025-06-18"

    @pytest.mark.parametrize("params", [None, {}, {"protocolVersion": 5},
                                        {"protocolVersion": None}, {"capabilities": {}}])
    def test_bad_params(self, params):
        err(call("mcp", rpc("initialize", params)), -32602, 200, id=1)

    def test_supported_tuple_exported(self):
        assert tuple(protocol.SUPPORTED_PROTOCOL_VERSIONS) == SUPPORTED


class TestSimpleMethods:
    def test_ping(self):
        r = call("mcp", rpc("ping", id="abc"))
        assert jbody(r) == {"jsonrpc": "2.0", "id": "abc", "result": {}}

    def test_ping_with_params_object(self):
        assert jbody(call("mcp", rpc("ping", {"x": 1})))["result"] == {}

    @pytest.mark.parametrize("method", [
        "notifications/initialized", "notifications/cancelled", "notifications/zzz",
        "tools/call", "initialize", "ping", "anything",
    ])
    def test_notifications_get_202_and_empty_body(self, method):
        r = call("mcp", {"jsonrpc": "2.0", "method": method})
        assert (r.status, r.body) == (202, b"")
        assert r.headers == HEADERS

    def test_tools_call_as_notification_never_reaches_core(self, monkeypatch):
        hits = []
        monkeypatch.setattr(protocol.core, "check_text",
                            lambda *a, **k: hits.append(1))
        u = protocol.UsageCounter()
        r = call("mcp", {"jsonrpc": "2.0", "method": "tools/call",
                         "params": {"name": "pii_check", "arguments": {"text": "x"}}},
                 usage=u)
        assert r.status == 202 and hits == [] and u.requests_served == 0

    @pytest.mark.parametrize("method", [
        "resources/list", "resources/read", "resources/templates/list",
        "resources/subscribe", "prompts/list", "prompts/get", "completion/complete",
        "logging/setLevel", "sampling/createMessage", "roots/list", "tools/foo",
        "", "Initialize", "initialized", "notifications/initialized", "tools", "tools/",
    ])
    def test_unknown_methods(self, method):
        err(call("mcp", rpc(method)), -32601, 200, id=1)


# -------------------------------------------------------------- id / shape

class TestEnvelope:
    @pytest.mark.parametrize("i", [0, 1, -7, 2 ** 40, "", "x", "0", "r_1", "é"])
    def test_id_echoed_with_exact_type(self, i):
        b = jbody(call("mcp", rpc("ping", id=i)))
        assert b["id"] == i and type(b["id"]) is type(i)

    @pytest.mark.parametrize("i", [True, False, 1.5, 1.0, None, [], {}, [1], {"a": 1}])
    def test_invalid_ids(self, i):
        m = rpc("ping", id=None)
        m["id"] = i
        err(call("mcp", m), -32600, 400, id=None)

    @pytest.mark.parametrize("v", ["1.0", "2", 2.0, 2, None, True, "", [], "2.0 "])
    def test_jsonrpc_must_be_exactly_2_0(self, v):
        m = rpc("ping")
        m["jsonrpc"] = v
        err(call("mcp", m), -32600, 400, id=1)

    def test_jsonrpc_missing(self):
        err(call("mcp", {"id": 1, "method": "ping"}), -32600, 400, id=1)

    @pytest.mark.parametrize("m", [5, None, [], {}, True, 1.5])
    def test_method_must_be_string(self, m):
        err(call("mcp", {"jsonrpc": "2.0", "id": 1, "method": m}), -32600, 400)

    def test_method_missing(self):
        err(call("mcp", {"jsonrpc": "2.0", "id": 1}), -32600, 400, id=1)

    @pytest.mark.parametrize("p", [[], [1], "x", 5, True, None, 1.5])
    def test_params_must_be_object(self, p):
        m = rpc("ping")
        m["params"] = p
        err(call("mcp", m), -32600, 400, id=1)

    def test_unknown_top_level_member(self):
        err(call("mcp", rpc("ping", extra=1)), -32600, 400, id=1)

    def test_invalid_notification_shape_is_an_error(self):
        err(call("mcp", {"jsonrpc": "1.0", "method": "x"}), -32600, 400, id=None)
        err(call("mcp", {"jsonrpc": "2.0", "method": 5}), -32600, 400, id=None)

    @pytest.mark.parametrize("body", [[], [rpc("ping")], [rpc("ping"), rpc("ping", id=2)],
                                      [[]], [1], 5, "x", None, True, 1.5])
    def test_batches_and_non_objects(self, body):
        r = protocol.handle(ROUTE["mcp"], json.dumps(body).encode(), request_id=RID,
                            usage=protocol.UsageCounter())
        err(r, -32600, 400, id=None)

    def test_error_responses_keep_fixed_headers(self):
        assert call("mcp", b"{").headers == HEADERS


class TestParseErrors:
    @pytest.mark.parametrize("body", [
        None, b"", b"{", b"nope", b"\xef\xbb\xbf{}", b'{"a":1}x', b"\xff",
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":' + b"9" * 21 + b',"method":"ping"}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":"\\ud800"}}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":' + b'{"a":' * 17 + b"1" + b"}" * 17 + b"}",
    ])
    def test_minus_32700_with_null_id(self, body):
        r = protocol.handle(ROUTE["mcp"], body, request_id=RID, usage=protocol.UsageCounter())
        err(r, -32700, 400, id=None)

    def test_oversize_body(self):
        r = protocol.handle(ROUTE["mcp"], b" " * (512 * 1024 + 1), request_id=RID,
                            usage=protocol.UsageCounter())
        assert r.status == 413
        assert jbody(r)["error"]["code"] == -32600

    def test_parse_error_never_echoes_input(self):
        r = protocol.handle(ROUTE["mcp"], ('{"%s":1,"%s":2}' % (CANARY, CANARY)).encode(),
                            request_id=RID, usage=protocol.UsageCounter())
        assert CANARY not in r.body.decode()


# --------------------------------------------------------------- tools/list

class TestToolsList:
    def tools(self):
        return jbody(call("mcp", rpc("tools/list")))["result"]["tools"]

    def test_exactly_three_tools_in_order(self):
        assert [t["name"] for t in self.tools()] == ["pii_check", "pii_redact", "pii_usage"]
        assert set(jbody(call("mcp", rpc("tools/list")))["result"]) == {"tools"}

    def test_tool_entries(self):
        for t in self.tools():
            assert set(t) == {"name", "description", "inputSchema"}
            assert "untrusted" in t["description"].lower()
            s = t["inputSchema"]
            assert s["type"] == "object"
            assert s["additionalProperties"] is False

    def test_schemas(self):
        check, redact, usage = self.tools()
        assert set(check["inputSchema"]["properties"]) == {"text", "document_type"}
        assert check["inputSchema"]["required"] == ["text"]
        assert check["inputSchema"]["properties"]["text"]["type"] == "string"
        assert check["inputSchema"]["properties"]["text"]["maxLength"] == core.MAX_TEXT_CHARS
        assert set(check["inputSchema"]["properties"]["document_type"]["enum"]) == set(
            core.DOCUMENT_TYPES)
        p = redact["inputSchema"]["properties"]
        assert set(p) == {"text", "document_type", "return_mapping", "verify"}
        assert p["return_mapping"] == {
            "type": "boolean", "default": False,
            "description": p["return_mapping"]["description"]}
        assert p["verify"]["type"] == "boolean"
        assert redact["inputSchema"]["required"] == ["text"]
        assert usage["inputSchema"]["properties"] == {}
        assert not usage["inputSchema"].get("required")

    def test_descriptions_have_no_instruction_like_filler(self):
        for t in self.tools():
            assert len(t["description"]) < 600

    def test_list_is_a_fresh_copy(self):
        a = self.tools()
        a[0]["name"] = "mutated"
        assert self.tools()[0]["name"] == "pii_check"


# --------------------------------------------------------------- tools/call

def structured(resp):
    b = jbody(resp)
    res = b["result"]
    assert set(res) == {"content", "structuredContent", "isError"}
    assert len(res["content"]) == 1 and res["content"][0]["type"] == "text"
    assert set(res["content"][0]) == {"type", "text"}
    assert json.loads(res["content"][0]["text"]) == res["structuredContent"]
    return res["structuredContent"], res["isError"]


class TestToolsCall:
    def test_check(self):
        s, e = structured(tool("pii_check", {"text": "a@b.c"}))
        assert e is False
        assert s == {"findings": [{"type": "EMAIL", "start_offset": 0, "end_offset": 5,
                                   "confidence": 0.5}], "entity_counts": {"EMAIL": 1}}

    def test_redact_omits_mapping_by_default(self):
        s, e = structured(tool("pii_redact", {"text": "a@b.c"}))
        assert e is False
        assert "mapping" not in s
        assert set(s) == {"redacted_text", "findings", "entity_counts", "audit_additions"}

    def test_redact_mapping_only_when_exactly_true(self):
        s, _ = structured(tool("pii_redact", {"text": "a@b.c", "return_mapping": True}))
        assert s["mapping"] == {"<<EMAIL_1>>": "a@b.c"}
        s, _ = structured(tool("pii_redact", {"text": "a@b.c", "return_mapping": False}))
        assert "mapping" not in s

    @pytest.mark.parametrize("bad", [1, 0, "true", "", None, [], {}, 1.0])
    def test_return_mapping_must_be_exact_bool(self, bad):
        s, e = structured(tool("pii_redact", {"text": "a@b.c", "return_mapping": bad}))
        assert e is True and s["error"] == "invalid_request"

    def test_verify_true_is_not_supported(self):
        r = tool("pii_redact", {"text": "a@b.c", "verify": True})
        s, e = structured(r)
        assert e is True
        assert s["error"] == "verify_not_supported"
        assert "result" in jbody(r) and "error" not in jbody(r)

    def test_verify_false_accepted_and_non_bool_rejected(self):
        assert structured(tool("pii_redact", {"text": "x", "verify": False}))[1] is False
        for bad in (1, "yes", None):
            s, e = structured(tool("pii_redact", {"text": "x", "verify": bad}))
            assert e and s["error"] == "invalid_request"

    def test_verify_true_does_not_reach_core(self, monkeypatch):
        hits = []
        monkeypatch.setattr(protocol.core, "redact_text", lambda *a, **k: hits.append(1))
        tool("pii_redact", {"text": "x", "verify": True})
        assert hits == []

    def test_usage_tool(self):
        u = protocol.UsageCounter()
        tool("pii_check", {"text": "x"}, usage=u)
        s, e = structured(tool("pii_usage", {}, usage=u))
        assert e is False
        assert s == {"period": "local", "requests_served": 1, "shards_used": 0,
                     "shards_limit": None, "cost_cents": 0.0}
        assert u.requests_served == 1

    def test_usage_tool_without_arguments(self):
        assert structured(tool("pii_usage"))[1] is False

    def test_usage_rejects_arguments(self):
        s, e = structured(tool("pii_usage", {"x": 1}))
        assert e and s["error"] == "invalid_request"

    def test_counting(self):
        u = protocol.UsageCounter()
        tool("pii_check", {"text": "x"}, usage=u)
        tool("pii_redact", {"text": "x"}, usage=u)
        tool("pii_check", {"text": 5}, usage=u)
        tool("pii_redact", {"text": "x", "verify": True}, usage=u)
        tool("pii_usage", {}, usage=u)
        assert u.requests_served == 2

    @pytest.mark.parametrize("name,args", [
        ("pii_check", {}), ("pii_redact", {}), ("pii_check", {"text": "x", "bogus": 1}),
        ("pii_redact", {"text": "x", "audit": False}),
        ("pii_check", {"text": "x", "return_mapping": True}),
    ])
    def test_argument_errors_are_tool_errors(self, name, args):
        s, e = structured(tool(name, args))
        assert e is True and s["error"] == "invalid_request"
        assert set(s) == {"error", "message", "request_id"} and s["request_id"] == RID

    def test_core_validation_errors_are_tool_errors(self):
        s, e = structured(tool("pii_check", {"text": 5}))
        assert e and s["error"] == "invalid_text"
        s, e = structured(tool("pii_check", {"text": "x", "document_type": "q"}))
        assert e and s["error"] == "invalid_document_type"
        s, e = structured(tool("pii_check", {"text": "x" * 50_001}))
        assert e and s["error"] == "payload_too_large"

    @pytest.mark.parametrize("params", [
        None, {}, {"name": 5}, {"name": None}, {"name": "nope"}, {"name": ""},
        {"name": "PII_CHECK"}, {"name": "pii_check", "arguments": []},
        {"name": "pii_check", "arguments": "x"}, {"name": "pii_check", "arguments": None},
        {"name": ["pii_check"]}, {"arguments": {"text": "x"}},
    ])
    def test_protocol_level_param_errors(self, params):
        err(call("mcp", rpc("tools/call", params)), -32602, 200, id=1)

    def test_extra_params_keys_are_ignored(self):
        r = call("mcp", rpc("tools/call", {"name": "pii_usage", "_meta": {"progressToken": 1}}))
        assert structured(r)[1] is False

    @pytest.mark.parametrize("exc", [
        ValueError(CANARY), MemoryError(CANARY), RecursionError(CANARY),
        UnicodeEncodeError("utf-8", CANARY, 0, 1, CANARY),
        core.CoreError("internal_error", CANARY, "KeyError", "a.py:f:1"),
        core.CoreError("model_unavailable", CANARY),
        core.CoreError(CANARY, CANARY),
    ])
    @pytest.mark.parametrize("name", ["pii_check", "pii_redact"])
    def test_exceptions_become_fixed_tool_errors(self, monkeypatch, exc, name):
        def boom(*a, **k):
            raise exc

        monkeypatch.setattr(protocol.core, "check_text", boom)
        monkeypatch.setattr(protocol.core, "redact_text", boom)
        u = protocol.UsageCounter()
        r = tool(name, {"text": "x"}, usage=u)
        blob = r.body.decode() + repr(r.headers) + repr(r.diag)
        assert not any(w in blob for w in CANARY_WINDOWS)
        s, e = structured(r)
        assert e is True and r.status == 200
        assert s["error"] in {"internal_error", "model_unavailable"}
        assert set(s) == {"error", "message", "request_id"}
        assert u.requests_served == 0
        assert r.diag is not None

    def test_model_unavailable_message_is_fixed(self, monkeypatch):
        monkeypatch.setattr(protocol.core, "check_text",
                            lambda *a, **k: (_ for _ in ()).throw(
                                core.CoreError("model_unavailable", "m")))
        s, _ = structured(tool("pii_check", {"text": "x"}))
        assert s["error"] == "model_unavailable"

    def test_id_echo_on_tool_results(self):
        for i in (0, "abc", 2 ** 33):
            b = jbody(tool("pii_usage", {}, id=i))
            assert b["id"] == i and type(b["id"]) is type(i)


class TestCanaryThroughRealCore:
    TEXT = f"Please write to {CANARY.lower()}@example.test about it."

    @pytest.fixture(autouse=True)
    def real(self, monkeypatch):
        # undo the autouse fake: use the real functions
        monkeypatch.undo()

    def test_full_response_has_no_canary(self):
        for name, args in (("pii_check", {"text": self.TEXT}),
                           ("pii_redact", {"text": self.TEXT}),
                           ("pii_redact", {"text": self.TEXT, "return_mapping": False})):
            r = tool(name, args)
            blob = r.body.decode().lower() + repr(r.headers).lower() + repr(r.diag).lower()
            assert CANARY.lower() not in blob, name
            assert not any(w.lower() in blob for w in CANARY_WINDOWS), name

    def test_return_mapping_true_carries_it_only_in_mapping(self):
        r = tool("pii_redact", {"text": self.TEXT, "return_mapping": True})
        s, e = structured(r)
        assert e is False
        assert CANARY.lower() in json.dumps(s["mapping"]).lower()
        rest = json.dumps({k: v for k, v in s.items() if k != "mapping"}).lower()
        assert CANARY.lower() not in rest


# ===================================================== differential fuzz

# The oracle below is deliberately a separate, flat implementation of the
# written contract.  It shares no code with protocol.py.

MSG = {
    "invalid_request": "request is not valid",
    "invalid_text": "text is not valid",
    "invalid_document_type": "document_type is not supported",
    "payload_too_large": "payload is too large",
    "verify_not_supported": "verify is not supported by the local server",
}
RPC_MSG = {-32700: "Parse error", -32600: "Invalid Request", -32601: "Method not found",
           -32602: "Invalid params"}
DOCTYPES = {"auto", "general", "resume", "transcript"}
TOOL_ARGS = {"pii_check": {"text", "document_type"},
             "pii_redact": {"text", "document_type", "return_mapping", "verify"},
             "pii_usage": set()}
MISSING = object()


def _o_err(status, code, i):
    return status, {"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": RPC_MSG[code]}}, 0


def _o_tool(name, a, n):
    """-> (structured, is_error, counted)"""
    def bad(code):
        return {"error": code, "message": MSG[code], "request_id": RID}, True, 0

    if set(a) - TOOL_ARGS[name]:
        return bad("invalid_request")
    if name == "pii_usage":
        return ({"period": "local", "requests_served": n, "shards_used": 0,
                 "shards_limit": None, "cost_cents": 0.0}, False, 0)
    if "text" not in a:
        return bad("invalid_request")
    rm = a.get("return_mapping", False)
    vf = a.get("verify", False)
    if name == "pii_redact":
        if type(rm) is not bool or type(vf) is not bool:
            return bad("invalid_request")
        if vf:
            return bad("verify_not_supported")
    t = a["text"]
    if type(t) is not str:
        return bad("invalid_text")
    if len(t) > 50_000:
        return bad("payload_too_large")
    dt = a.get("document_type", "auto")
    if type(dt) is not str:
        return bad("invalid_request")
    if dt not in DOCTYPES:
        return bad("invalid_document_type")
    f = [{"type": "EMAIL", "start_offset": 0, "end_offset": len(t), "confidence": 0.5}] \
        if "@" in t else []
    counts = {"EMAIL": 1} if f else {}
    if name == "pii_check":
        return {"findings": f, "entity_counts": counts}, False, 1
    out = {"redacted_text": "R%d" % len(t), "findings": f, "entity_counts": counts,
           "audit_additions": 1}
    if rm:
        out["mapping"] = {"<<EMAIL_1>>": t} if f else {}
    return out, False, 1


def oracle(msg, n):
    """-> (status, payload | None, counted_increments)"""
    if type(msg) is not dict:
        return _o_err(400, -32600, None)
    has_id = "id" in msg
    i = msg.get("id")
    id_ok = has_id and type(i) in (str, int)
    echo = i if id_ok else None
    if set(msg) - {"jsonrpc", "id", "method", "params"}:
        return _o_err(400, -32600, echo)
    if not (type(msg.get("jsonrpc")) is str and msg["jsonrpc"] == "2.0"):
        return _o_err(400, -32600, echo)
    if type(msg.get("method")) is not str:
        return _o_err(400, -32600, echo)
    if "params" in msg and type(msg["params"]) is not dict:
        return _o_err(400, -32600, echo)
    if has_id and not id_ok:
        return _o_err(400, -32600, None)
    if not has_id:
        return 202, None, 0
    m = msg["method"]
    p = msg.get("params")

    def ok(result, counted=0):
        return 200, {"jsonrpc": "2.0", "id": i, "result": result}, counted

    if m == "ping":
        return ok({})
    if m == "initialize":
        if p is None or type(p.get("protocolVersion")) is not str:
            return _o_err(200, -32602, i)
        pv = p["protocolVersion"]
        return ok({"protocolVersion": pv if pv in SUPPORTED else SUPPORTED[0],
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "pii-buddy", "version": VERSION}})
    if m == "tools/list":
        return ok("LIST")
    if m == "tools/call":
        if p is None or type(p.get("name")) is not str or p["name"] not in TOOL_ARGS:
            return _o_err(200, -32602, i)
        a = p.get("arguments", {}) if "arguments" in p else {}
        if type(a) is not dict:
            return _o_err(200, -32602, i)
        s, e, c = _o_tool(p["name"], a, n)
        return ok({"content": "TEXT", "structuredContent": s, "isError": e}, c)
    return _o_err(200, -32601, i)


ID_POOL = [MISSING, MISSING, 1, 0, -5, 2 ** 40, "a", "", "r_9", True, False, 1.5, None, [], {}]
JSONRPC_POOL = ["2.0"] * 12 + ["1.0", 2.0, None, "", True, MISSING]
METHOD_POOL = (["ping", "initialize", "tools/list", "tools/call"] * 6 + [
    "notifications/initialized", "resources/list", "prompts/list", "completion/complete",
    "logging/setLevel", "tools/foo", "", 5, None, MISSING, "Ping"])
TEXT_POOL = ["hello", "a@b.c", "", "x" * 50_000, "x" * 50_001, "café \U0001f600 @",
             5, None, [], {}, True, 1.5, MISSING]
DT_POOL = [MISSING] * 4 + ["auto", "general", "resume", "transcript", "bogus", "", 5, None, True]
BOOL_POOL = [MISSING] * 4 + [True, False, 1, 0, "true", None, [], 1.0]
NAME_POOL = ["pii_check"] * 4 + ["pii_redact"] * 4 + ["pii_usage"] * 2 + [
    "nope", "", 5, None, MISSING, "PII_CHECK"]
EXTRA_ARG_POOL = ["audit", "mapping", "x", "Text", "document-type"]


def _set(d, k, v):
    if v is not MISSING:
        d[k] = v


def gen_args(rnd):
    a = {}
    _set(a, "text", rnd.choice(TEXT_POOL))
    _set(a, "document_type", rnd.choice(DT_POOL))
    _set(a, "return_mapping", rnd.choice(BOOL_POOL))
    _set(a, "verify", rnd.choice(BOOL_POOL))
    if rnd.random() < 0.08:
        a[rnd.choice(EXTRA_ARG_POOL)] = rnd.choice([1, "x", True])
    return a


GOOD_ID_POOL = [1, 0, -5, 2 ** 40, "a", "", "r_9"]
GOOD_METHOD_POOL = ["ping", "initialize", "tools/list", "tools/call", "tools/call",
                    "tools/call", "resources/list", "tools/foo"]


def gen_message(rnd):
    m = {}
    if rnd.random() < 0.55:
        m["jsonrpc"] = "2.0"
        m["id"] = rnd.choice(GOOD_ID_POOL)
        m["method"] = rnd.choice(GOOD_METHOD_POOL)
        if rnd.random() < 0.05:
            del m["id"]
    else:
        _set(m, "jsonrpc", rnd.choice(JSONRPC_POOL))
        _set(m, "id", rnd.choice(ID_POOL))
        _set(m, "method", rnd.choice(METHOD_POOL))
    method = m.get("method")
    r = rnd.random()
    if method == "tools/call" and r < 0.85:
        p = {}
        _set(p, "name", rnd.choice(NAME_POOL))
        q = rnd.random()
        if q < 0.85:
            p["arguments"] = gen_args(rnd)
        elif q < 0.9:
            p["arguments"] = rnd.choice([[], "x", None, 5])
        if rnd.random() < 0.1:
            p["_meta"] = {"progressToken": 1}
        m["params"] = p
    elif method == "initialize" and r < 0.8:
        p = {}
        _set(p, "protocolVersion", rnd.choice(
            list(SUPPORTED) + ["1999-01-01", "", 5, None, MISSING]))
        if rnd.random() < 0.5:
            p["capabilities"] = {}
        m["params"] = p
    elif r < 0.12:
        m["params"] = rnd.choice([{}, {"a": 1}, [], "x", 5, None, [1]])
    if rnd.random() < 0.03:
        m["extra"] = 1
    return m


RAW_KINDS = [
    b"", b"{", b"nope", b"[", b'{"a"', b"{'a':1}", b"\xff\xfe", b"null\x00",
    b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
    b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
    b'{"jsonrpc":"2.0","id":Infinity,"method":"ping"}',
    b'{"jsonrpc":"2.0","id":1e999,"method":"ping"}',
    b'{"jsonrpc":"2.0","id":123456789012345678901,"method":"ping"}',
    b'{"jsonrpc":"2.0","id":1,"method":"ping"}x',
    b'{"jsonrpc":"2.0","id":1,"method":"ping"}{}',
    b'\xef\xbb\xbf{"jsonrpc":"2.0","id":1,"method":"ping"}',
    b'{"jsonrpc":"2.0","id":1,"method":"pi\xffng"}',
    b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":"\\ud800"}}',
    b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"\\udfff":1}}',
    b'{"jsonrpc":"2.0","id":1,"method":"ping","params":' + b'[' * 40 + b']' * 40 + b"}",
]


def gen_case(rnd):
    """-> (raw bytes, parsed object | PARSE_FAIL)"""
    r = rnd.random()
    if r < 0.06:
        return rnd.choice(RAW_KINDS), "FAIL"
    if r < 0.09:
        batch = [gen_message(rnd) for _ in range(rnd.choice([0, 1, 2, 3]))]
        return json.dumps(batch).encode(), batch
    if r < 0.11:
        v = rnd.choice([0, 1, "x", None, True, 1.5, "ping"])
        return json.dumps(v).encode(), v
    msg = gen_message(rnd)
    return json.dumps(msg, ensure_ascii=rnd.random() < 0.5).encode("utf-8"), msg


N_FUZZ = 25_000


class TestDifferentialFuzz:
    def test_matches_oracle_on_25k_seeded_cases(self):
        rnd = random.Random(20261018)
        tools_listing = jbody(call("mcp", rpc("tools/list")))["result"]
        stats = {"ok": 0, "err": 0, "note": 0, "tool_err": 0, "parse": 0}
        for case in range(N_FUZZ):
            raw_bytes, obj = gen_case(rnd)
            n = rnd.randrange(4)
            u = protocol.UsageCounter()
            for _ in range(n):
                u.increment()
            resp = protocol.handle(ROUTE["mcp"], raw_bytes, request_id=RID, usage=u)
            ctx = (case, raw_bytes[:300])
            assert resp.headers == HEADERS, ctx
            if obj == "FAIL" and isinstance(obj, str):
                status, payload, counted = _o_err(400, -32700, None)
                stats["parse"] += 1
            elif type(obj) is list:
                status, payload, counted = _o_err(400, -32600, None)
            else:
                status, payload, counted = oracle(obj, n)
            assert resp.status == status, ctx
            if payload is None:
                assert resp.body == b"", ctx
                stats["note"] += 1
            else:
                got = json.loads(resp.body)
                exp = json.loads(json.dumps(payload))
                res = exp.get("result")
                if res == "LIST":
                    exp["result"] = tools_listing
                elif isinstance(res, dict) and res.get("content") == "TEXT":
                    gres = got["result"]
                    assert len(gres["content"]) == 1, ctx
                    assert gres["content"][0]["type"] == "text", ctx
                    assert json.loads(gres["content"][0]["text"]) == res["structuredContent"], ctx
                    res["content"] = gres["content"]
                    stats["tool_err" if res["isError"] else "ok"] += 1
                else:
                    stats["err" if "error" in exp else "ok"] += 1
                assert got == exp, ctx
                assert type(got["id"]) is type(exp["id"]), ctx
            assert u.requests_served == n + counted, ctx
        # the generator must actually exercise every outcome
        assert stats["ok"] > 2000 and stats["err"] > 2000 and stats["note"] > 1000
        assert stats["tool_err"] > 1000 and stats["parse"] > 1000, stats


# ------------------------------------- client responses / notifications (202)

class TestClientResponsesAreAccepted:
    """Streamable HTTP: a POST whose input is only responses or notifications
    gets HTTP 202 with no body.  A response has an id, exactly one of
    result / error, and no method."""

    @pytest.mark.parametrize("msg", [
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": "abc", "result": {"roots": []}},
        {"jsonrpc": "2.0", "id": 0, "result": None},
        {"jsonrpc": "2.0", "id": 2 ** 40, "result": [1, 2]},
        {"jsonrpc": "2.0", "id": -1, "result": "x"},
        {"jsonrpc": "2.0", "id": 3, "error": {"code": -32601, "message": "nope"}},
        {"jsonrpc": "2.0", "id": "", "error": {"code": 1, "message": "m", "data": [1]}},
        {"jsonrpc": "2.0", "id": 4, "error": {}},
    ])
    def test_valid_response_is_202_empty(self, msg):
        u = protocol.UsageCounter()
        r = call("mcp", msg, usage=u)
        assert (r.status, r.body) == (202, b"")
        assert r.headers == HEADERS
        assert r.diag is None and r.entity_count is None
        assert u.requests_served == 0

    @pytest.mark.parametrize("msg", [
        {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}},
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "2.0", "result": {}},
        {"jsonrpc": "2.0", "error": {"code": 1, "message": "m"}},
        {"jsonrpc": "2.0", "id": None, "result": {}},
        {"jsonrpc": "2.0", "id": True, "result": {}},
        {"jsonrpc": "2.0", "id": 1.5, "result": {}},
        {"jsonrpc": "2.0", "id": [1], "result": {}},
        {"jsonrpc": "2.0", "id": {}, "error": {}},
        {"jsonrpc": "2.0", "id": 1, "error": "boom"},
        {"jsonrpc": "2.0", "id": 1, "error": None},
        {"jsonrpc": "2.0", "id": 1, "error": [1]},
        {"jsonrpc": "1.0", "id": 1, "result": {}},
        {"jsonrpc": 2, "id": 1, "result": {}},
        {"id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 1, "result": {}, "extra": 1},
        {"jsonrpc": "2.0", "id": 1, "result": {}, "params": {}},
    ])
    def test_malformed_response_stays_invalid_request(self, msg):
        err(call("mcp", msg), -32600, 400)

    def test_result_with_a_method_is_not_a_response(self):
        err(call("mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping", "result": {}}),
            -32600, 400, id=1)

    def test_valid_ids_are_echoed_on_malformed_responses(self):
        b = jbody(call("mcp", {"jsonrpc": "2.0", "id": 9, "result": {}, "error": {}}))
        assert b["id"] == 9

    def test_responses_in_a_batch_are_still_rejected(self):
        err(call("mcp", [{"jsonrpc": "2.0", "id": 1, "result": {}}]), -32600, 400, id=None)

    def test_canary_in_a_response_is_never_echoed(self):
        r = call("mcp", {"jsonrpc": "2.0", "id": 1, "result": {"x": CANARY}})
        assert r.body == b"" and CANARY not in repr(r)
