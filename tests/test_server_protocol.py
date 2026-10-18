"""pii_buddy.server.protocol: the REST half of the pure dispatcher, strict body
parsing, the error contract, the usage counter and the silence guarantee."""

import dataclasses
import itertools
import json
import logging
import os
import pathlib
import pprint
import subprocess
import sys
import threading
import time

import pytest

from pii_buddy import core
from pii_buddy.server import protocol
from tests._protocol_helpers import (
    CANARY,
    HEADERS,
    ROUTE,
    RID,
    call,
    install_fake_core,
    jbody,
)

ERROR_KEYS = {"error", "message", "request_id"}
CANARY_WINDOWS = {CANARY[i:i + 6] for i in range(len(CANARY) - 5)}


def _clean(resp):
    blob = resp.body.decode() + repr(resp.headers) + repr(resp.diag)
    return not any(w in blob for w in CANARY_WINDOWS)


@pytest.fixture
def fake(monkeypatch):
    install_fake_core(monkeypatch)


# ----------------------------------------------------------- response shape

class TestResponse:
    def test_frozen_dataclass(self):
        r = call("health")
        assert dataclasses.is_dataclass(r)
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.status = 500

    def test_fixed_headers_on_every_kind_of_response(self, fake):
        for resp in (
            call("health"),
            call("usage"),
            call("check", {"text": "a@b.c"}),
            call("check", b"{"),
            call("nope", {"a": 1}),
            call("mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            call("mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ):
            assert resp.headers == HEADERS
            assert type(resp.body) is bytes

    def test_body_is_ascii_json(self, fake):
        resp = call("check", {"text": "café \U0001f600 a@b.c"})
        resp.body.decode("ascii")
        json.loads(resp.body)


# ------------------------------------------------------------------- health

class TestHealth:
    def test_body_is_exactly_ok_true(self):
        r = call("health")
        assert r.status == 200
        assert jbody(r) == {"ok": True}
        assert r.body == b'{"ok":true}'

    def test_ignores_a_body_and_does_not_count(self):
        u = protocol.UsageCounter()
        r = call("health", {"x": 1}, usage=u)
        assert jbody(r) == {"ok": True}
        assert u.requests_served == 0

    def test_nothing_else_in_headers_or_body(self):
        r = call("health")
        blob = (r.body.decode() + repr(r.headers)).lower()
        for word in ("version", "model", "pid", "spacy", "python"):
            assert word not in blob


# -------------------------------------------------------------------- usage

class TestUsage:
    def test_shape(self):
        r = call("usage")
        assert r.status == 200
        assert jbody(r) == {
            "period": "local",
            "requests_served": 0,
            "shards_used": 0,
            "shards_limit": None,
            "cost_cents": 0.0,
        }

    def test_float_cost_serialises_as_float(self):
        assert b'"cost_cents":0.0' in call("usage").body

    def test_counts_completed_core_requests_only(self, fake):
        u = protocol.UsageCounter()
        call("check", {"text": "a@b.c"}, usage=u)
        call("redact", {"text": "a@b.c"}, usage=u)
        call("restore", {"redacted_text": "x", "mapping": {}}, usage=u)
        assert u.requests_served == 3
        call("check", {"text": 5}, usage=u)            # core rejects
        call("check", b"{", usage=u)                   # never reached core
        call("check", {"text": "x", "bogus": 1}, usage=u)
        call("usage", usage=u)
        call("health", usage=u)
        assert u.requests_served == 3
        assert jbody(call("usage", usage=u))["requests_served"] == 3


class TestUsageCounter:
    def test_thread_safe(self):
        u = protocol.UsageCounter()

        def work():
            for _ in range(2000):
                u.increment()

        ts = [threading.Thread(target=work) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert u.requests_served == 16000

    def test_holds_no_per_request_data(self):
        u = protocol.UsageCounter()
        before = len(vars(u))
        for _ in range(100):
            u.increment()
        assert len(vars(u)) == before
        assert all(type(v) in (int, type(threading.Lock())) for v in vars(u).values())


# ------------------------------------------------------------- REST success

class TestCheck:
    def test_real_core_email(self):
        r = call("check", {"text": "Mail zq7f3a9cxk@example.test now"})
        assert r.status == 200
        b = jbody(r)
        assert set(b) == {"findings", "entity_counts"}
        assert b["entity_counts"] == {"EMAIL": 1}
        assert set(b["findings"][0]) == {
            "type", "start_offset", "end_offset", "confidence"
        }

    def test_document_type_is_forwarded(self, monkeypatch):
        seen = []

        def spy(text, *, document_type="auto"):
            seen.append(document_type)
            return core.CheckResult((), {})

        monkeypatch.setattr(protocol.core, "check_text", spy)
        call("check", {"text": "x", "document_type": "resume"})
        call("check", {"text": "x"})
        assert seen == ["resume", "auto"]

    def test_bad_document_type_is_core_400(self, fake):
        r = call("check", {"text": "x", "document_type": "zzz"})
        assert (r.status, jbody(r)["error"]) == (400, "invalid_document_type")
        r = call("check", {"text": "x", "document_type": 7})
        assert (r.status, jbody(r)["error"]) == (400, "invalid_request")


class TestRedact:
    def test_defaults_return_mapping_and_audit(self):
        r = call("redact", {"text": "Mail zq7f3a9cxk@example.test now"})
        b = jbody(r)
        assert r.status == 200
        assert set(b) == {
            "redacted_text", "mapping", "findings", "entity_counts", "audit_additions",
        }
        assert b["mapping"] == {"<<EMAIL_1>>": "zq7f3a9cxk@example.test"}
        assert b["redacted_text"] == "Mail <<EMAIL_1>> now"

    def test_return_mapping_false_omits_mapping(self, fake):
        b = jbody(call("redact", {"text": "a@b.c", "return_mapping": False}))
        assert "mapping" not in b
        assert set(b) == {"redacted_text", "findings", "entity_counts", "audit_additions"}

    def test_audit_flag_reaches_core(self, fake):
        assert jbody(call("redact", {"text": "a@b.c", "audit": False}))["audit_additions"] == 0
        assert jbody(call("redact", {"text": "a@b.c", "audit": True}))["audit_additions"] == 1
        assert jbody(call("redact", {"text": "a@b.c"}))["audit_additions"] == 1

    @pytest.mark.parametrize("key", ["return_mapping", "audit"])
    @pytest.mark.parametrize("bad", [0, 1, "true", "", None, [], {}, 1.0])
    def test_flags_must_be_exact_bools(self, fake, key, bad):
        r = call("redact", {"text": "a@b.c", key: bad})
        assert (r.status, jbody(r)["error"]) == (400, "invalid_request")


class TestRestore:
    def test_round_trip_with_real_core(self):
        red = jbody(call("redact", {"text": "Mail zq7f3a9cxk@example.test now"}))
        r = call("restore", {"redacted_text": red["redacted_text"], "mapping": red["mapping"]})
        assert r.status == 200
        assert jbody(r) == {"text": "Mail zq7f3a9cxk@example.test now"}

    def test_bad_mapping_is_400(self):
        for m in ([], "x", 3, None, {"not a tag": "x"}, {"<<A_1>>": 1}):
            r = call("restore", {"redacted_text": "x", "mapping": m})
            assert r.status == 400
            assert jbody(r)["error"] in {"invalid_mapping", "invalid_request"}

    def test_bad_text_is_400(self):
        r = call("restore", {"redacted_text": 5, "mapping": {}})
        assert (r.status, jbody(r)["error"]) == (400, "invalid_text")


# ------------------------------------------------------------ strict schema

ALLOWED = {
    "check": {"text", "document_type"},
    "redact": {"text", "document_type", "return_mapping", "audit"},
    "restore": {"redacted_text", "mapping"},
}
REQUIRED = {"check": {"text"}, "redact": {"text"}, "restore": {"redacted_text", "mapping"}}
VALID = {
    "check": {"text": "x"},
    "redact": {"text": "x"},
    "restore": {"redacted_text": "x", "mapping": {}},
}


class TestSchema:
    @pytest.mark.parametrize("route", sorted(ALLOWED))
    def test_allowed_keys_are_exactly_these(self, fake, route):
        for key in ALLOWED[route]:
            ok = dict(VALID[route])
            ok.setdefault(key, {"document_type": "auto", "return_mapping": True,
                                "audit": True}.get(key))
            r = call(route, ok)
            assert r.status == 200, (route, key, jbody(r))

    @pytest.mark.parametrize("route", sorted(ALLOWED))
    @pytest.mark.parametrize("extra", ["verify", "TEXT", "Text", "", "mapping2", "__proto__", "x"])
    def test_unknown_keys_rejected(self, fake, route, extra):
        if extra in ALLOWED[route]:
            pytest.skip("allowed")
        body = dict(VALID[route], **{extra: 1})
        r = call(route, body)
        assert (r.status, jbody(r)["error"]) == (400, "invalid_request")

    @pytest.mark.parametrize("route", sorted(REQUIRED))
    def test_missing_required_rejected(self, fake, route):
        for key in REQUIRED[route]:
            body = {k: v for k, v in VALID[route].items() if k != key}
            r = call(route, body)
            assert (r.status, jbody(r)["error"]) == (400, "invalid_request")

    @pytest.mark.parametrize("route", sorted(ALLOWED))
    @pytest.mark.parametrize("top", [[], [{"text": "x"}], "x", 5, 1.5, True, None])
    def test_top_level_must_be_object(self, fake, route, top):
        r = protocol.handle(ROUTE[route], json.dumps(top).encode(), request_id=RID,
                            usage=protocol.UsageCounter())
        assert r.status == 400
        assert jbody(r)["error"] == "invalid_request"

    @pytest.mark.parametrize("route", sorted(ALLOWED))
    def test_missing_or_empty_body_is_invalid_json(self, fake, route):
        for body in (None, b"", b"   "):
            r = protocol.handle(ROUTE[route], body, request_id=RID, usage=protocol.UsageCounter())
            assert (r.status, jbody(r)["error"]) == (400, "invalid_json")

    def test_text_wrong_type_goes_through_core(self, fake):
        for v in (5, None, [], {}, True):
            r = call("check", {"text": v})
            assert (r.status, jbody(r)["error"]) == (400, "invalid_text")

    def test_unknown_route(self):
        r = call("zzz", {"a": 1})
        assert r.status == 404
        assert jbody(r)["error"] == "not_found"
        assert set(jbody(r)) == ERROR_KEYS


# ------------------------------------------------------------ JSON strictness

def _deep(n, kind):
    if kind == "arr":
        return b"[" * n + b"1" + b"]" * n
    return b'{"a":' * n + b"1" + b"}" * n


BAD_BODIES = {
    "bom": b"\xef\xbb\xbf{}",
    "bad_utf8": b'{"a":"\xff"}',
    "overlong": b'{"a":"\xc0\x80"}',
    "encoded_surrogate": b'{"a":"\xed\xa0\x80"}',
    "lone_high": b'{"a":"\\ud800"}',
    "lone_low": b'{"a":"\\udc00"}',
    "lone_in_key": b'{"\\ud800":1}',
    "lone_in_list": b'{"a":["\\udbff"]}',
    "reversed_pair": b'{"a":"\\ude00\\ud83d"}',
    "trailing_garbage": b'{"a":1}x',
    "two_docs": b'{"a":1}{"b":2}',
    "trailing_comma": b'{"a":1,}',
    "dup": b'{"a":1,"a":2}',
    "dup_same_value": b'{"a":1,"a":1}',
    "dup_nested": b'{"a":{"b":1,"b":2}}',
    "dup_in_list": b'{"a":[{"k":1,"k":1}]}',
    "nan": b'{"a":NaN}',
    "inf": b'{"a":Infinity}',
    "ninf": b'{"a":-Infinity}',
    "float_overflow": b'{"a":1e999}',
    "big_int": b'{"a":' + b"9" * 21 + b"}",
    "big_neg_int": b'{"a":-' + b"9" * 21 + b"}",
    "single_quotes": b"{'a':1}",
    "comment": b'{"a":1}//x',
    "ctrl_in_string": b'{"a":"\x01"}',
    "nul": b'{"a":"\x00"}',
    "empty": b"",
    "ws_only": b"  \n",
    "truncated": b'{"a":',
    "depth_17": _deep(17, "obj"),
    "depth_17_arr": b'{"a":' + _deep(16, "arr") + b"}",
    "unbalanced": b'{"a":[1,2}',
    "vt_whitespace": b'\x0b{"a":1}',
    "nbsp_whitespace": ' {"a":1}'.encode(),
}

GOOD_BODIES = {
    "plain": (b'{"a":1}', {"a": 1}),
    "astral_pair": (b'{"a":"\\ud83d\\ude00"}', {"a": "\U0001f600"}),
    "raw_astral": ('{"a":"\U0001f600"}'.encode(), {"a": "\U0001f600"}),
    "int_20_digits": (b'{"a":' + b"9" * 20 + b"}", {"a": int("9" * 20)}),
    "neg_int_20_digits": (b'{"a":-' + b"9" * 20 + b"}", {"a": -int("9" * 20)}),
    "depth_16": (_deep(16, "obj"), None),
    "float": (b'{"a":1.5e3}', {"a": 1500.0}),
    "ws": (b' \t\r\n{"a" : 1}\n ', {"a": 1}),
    "escaped_backslash_u": (b'{"a":"\\\\ud800"}', {"a": "\\ud800"}),
    "same_key_different_objects": (b'{"a":{"k":1},"b":{"k":1}}', {"a": {"k": 1}, "b": {"k": 1}}),
    "empty_key": (b'{"":1}', {"": 1}),
}


class TestParseJsonBody:
    @pytest.mark.parametrize("name", sorted(BAD_BODIES))
    def test_rejects_with_fixed_invalid_json(self, name):
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(BAD_BODIES[name])
        assert e.value.code == "invalid_json"
        assert e.value.__cause__ is None
        assert e.value.__suppress_context__ or e.value.__context__ is None

    def test_all_bad_bodies_share_one_message(self):
        msgs = set()
        for body in BAD_BODIES.values():
            with pytest.raises(protocol.ProtocolError) as e:
                protocol.parse_json_body(body)
            msgs.add(str(e.value))
        assert len(msgs) == 1

    @pytest.mark.parametrize("name", sorted(GOOD_BODIES))
    def test_accepts(self, name):
        body, expected = GOOD_BODIES[name]
        out = protocol.parse_json_body(body)
        if expected is not None:
            assert out == expected

    def test_depth_16_keeps_structure(self):
        out = protocol.parse_json_body(_deep(16, "obj"))
        for _ in range(16):
            out = out["a"]
        assert out == 1

    def test_top_level_scalars_and_arrays_parse(self):
        assert protocol.parse_json_body(b"[1,2]") == [1, 2]
        assert protocol.parse_json_body(b"5") == 5
        assert protocol.parse_json_body(b'"x"') == "x"
        assert protocol.parse_json_body(b"null") is None

    def test_size_cap_is_512_kib(self):
        pad = b" " * (512 * 1024 - 2)
        assert protocol.parse_json_body(b"{}" + pad) == {}
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(b"{}" + pad + b" ")
        assert e.value.code == "payload_too_large"

    @pytest.mark.parametrize("bad", [None, "{}", bytearray(b"{}"), memoryview(b"{}"), 5, []])
    def test_non_bytes_input(self, bad):
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(bad)
        assert e.value.code == "invalid_json"

    def test_error_text_never_echoes_input(self):
        body = ('{"' + CANARY + '":1,"' + CANARY + '":2}').encode()
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(body)
        assert CANARY not in str(e.value) and CANARY not in repr(e.value)
        assert CANARY not in repr(e.value.args)

    def test_rest_route_reports_400_invalid_json(self, fake):
        for name, body in BAD_BODIES.items():
            if name == "empty" or name == "ws_only":
                pass
            r = protocol.handle(ROUTE["check"], body, request_id=RID, usage=protocol.UsageCounter())
            assert r.status == 400, name
            assert jbody(r) == {
                "error": "invalid_json",
                "message": jbody(r)["message"],
                "request_id": RID,
            }

    def test_rest_oversize_is_413(self, fake):
        r = protocol.handle(ROUTE["check"], b" " * (512 * 1024 + 1), request_id=RID,
                            usage=protocol.UsageCounter())
        assert (r.status, jbody(r)["error"]) == (413, "payload_too_large")


PATHOLOGICAL = r'''
import json
from pii_buddy.server import protocol

cases = {
    "arr": b"[" * 10000 + b"1" + b"]" * 10000,
    "obj": b'{"a":' * 10000 + b"1" + b"}" * 10000,
    "open_only": b"[" * 400000,
    "huge_int": b'{"a":' + b"9" * 500000 + b"}",
    "huge_frac": b'{"a":0.' + b"9" * 500000 + b"}",
    "string_of_quotes": b'{"a":"' + b'\\"' * 200000 + b'"}',
    "brackets_in_string": b'{"a":"' + b"[" * 400000 + b'"}',
    "many_keys": b"{" + b",".join(b'"k%d":1' % i for i in range(40000)) + b"}",
}
out = {}
for name, body in cases.items():
    try:
        protocol.parse_json_body(body)
        out[name] = "ok"
    except protocol.ProtocolError as e:
        out[name] = e.code
    r = protocol.handle("POST /mcp", body, request_id="r_1", usage=protocol.UsageCounter())
    out[name + ":mcp"] = r.status
print(json.dumps(out))
'''


class TestPathologicalInSubprocess:
    def test_hostile_bodies_fail_fast_and_fixed(self, tmp_path):
        env = dict(os.environ, PII_BUDDY_DIR=str(tmp_path / "PII_Buddy"))
        p = subprocess.run(
            [sys.executable, "-c", PATHOLOGICAL],
            capture_output=True, text=True, timeout=120, env=env,
            cwd=str(pathlib.Path(__file__).resolve().parent.parent),
        )
        assert p.returncode == 0, p.stderr[-2000:]
        assert p.stderr == ""
        out = json.loads(p.stdout)
        assert out["arr"] == out["obj"] == out["open_only"] == out["huge_int"] == "invalid_json"
        assert out["huge_frac"] == "invalid_json"
        assert out["brackets_in_string"] == "ok"
        assert out["string_of_quotes"] == "ok"
        assert out["many_keys"] == "ok"
        for k, v in out.items():
            if k.endswith(":mcp"):
                assert v in (400, 200), (k, v)


# ------------------------------------------------------------ error contract

def _boom(exc):
    def f(*a, **k):
        raise exc
    return f


EXCEPTIONS = {
    "value": lambda: ValueError(CANARY),
    "unicode": lambda: UnicodeEncodeError("utf-8", CANARY, 0, 1, CANARY),
    "memory": lambda: MemoryError(CANARY),
    "recursion": lambda: RecursionError(CANARY),
    "key": lambda: KeyError(CANARY),
    "os": lambda: OSError(2, CANARY),
    "assert": lambda: AssertionError(CANARY),
    "core_unknown_code": lambda: core.CoreError(CANARY, CANARY, "SomeError", "x.py:f:1"),
}

CORE_CODE_STATUS = {
    "invalid_request": 400,
    "invalid_text": 400,
    "invalid_mapping": 400,
    "invalid_json": 400,
    "invalid_document_type": 400,
    "payload_too_large": 413,
    "model_unavailable": 503,
    "internal_error": 500,
}


class TestErrorContract:
    @pytest.mark.parametrize("route,fn,body", [
        ("check", "check_text", {"text": "x"}),
        ("redact", "redact_text", {"text": "x"}),
        ("restore", "restore_text", {"redacted_text": "x", "mapping": {}}),
    ])
    @pytest.mark.parametrize("name", sorted(EXCEPTIONS))
    def test_any_exception_is_fixed_500(self, monkeypatch, route, fn, body, name):
        monkeypatch.setattr(protocol.core, fn, _boom(EXCEPTIONS[name]()))
        u = protocol.UsageCounter()
        r = call(route, body, usage=u)
        assert _clean(r), (route, name, r)
        assert u.requests_served == 0
        b = jbody(r)
        assert set(b) == ERROR_KEYS
        assert b["request_id"] == RID
        assert (r.status, b["error"]) == (500, "internal_error")

    def test_all_internal_failures_share_one_message(self, monkeypatch):
        msgs = set()
        for name in EXCEPTIONS:
            monkeypatch.setattr(protocol.core, "check_text", _boom(EXCEPTIONS[name]()))
            msgs.add(jbody(call("check", {"text": "x"}))["message"])
        assert len(msgs) == 1

    @pytest.mark.parametrize("code,status", sorted(CORE_CODE_STATUS.items()))
    def test_core_error_codes_map_to_status(self, monkeypatch, code, status):
        monkeypatch.setattr(
            protocol.core, "check_text",
            _boom(core.CoreError(code, "msg " + CANARY, "SomeError", "mod.py:fn:12")),
        )
        r = call("check", {"text": "x"})
        b = jbody(r)
        assert (r.status, b["error"]) == (status, code)
        assert set(b) == ERROR_KEYS
        assert _clean(r)
        assert r.diag is not None and r.diag.code == code

    def test_messages_are_fixed_per_code(self, monkeypatch):
        seen = {}
        for code in CORE_CODE_STATUS:
            for text in ("one", "two"):
                monkeypatch.setattr(
                    protocol.core, "check_text", _boom(core.CoreError(code, text)))
                m = jbody(call("check", {"text": "x"}))["message"]
                assert seen.setdefault(code, m) == m
        assert len(set(seen.values())) == len(seen)

    def test_diag_carries_only_class_name_and_where(self, monkeypatch):
        monkeypatch.setattr(
            protocol.core, "check_text",
            _boom(core.CoreError("internal_error", "internal error", "KeyError",
                                 "detector.py:detect_pii:77")),
        )
        r = call("check", {"text": "x"})
        assert r.diag == protocol.Diag("internal_error", "KeyError", "detector.py:detect_pii:77")
        assert r.status == 500 and "detector" not in r.body.decode()

    @pytest.mark.parametrize("exc_type,where", [
        (CANARY + " with spaces", "/etc/passwd"),
        ("a" * 500, "x.py:f:1\nfake log line"),
        ("<script>", "../../x.py:f:1"),
        (5, 5),
        (None, None),
    ])
    def test_diag_fields_are_sanitised(self, monkeypatch, exc_type, where):
        monkeypatch.setattr(
            protocol.core, "check_text",
            _boom(core.CoreError("internal_error", "m", exc_type, where)))
        r = call("check", {"text": "x"})
        assert r.diag.exc_type is None
        assert r.diag.where is None

    def test_foreign_exception_diag_is_class_name_only(self, monkeypatch):
        class Weird(Exception):
            def __str__(self):
                raise RuntimeError(CANARY)

            __repr__ = __str__

        monkeypatch.setattr(protocol.core, "check_text", _boom(Weird(CANARY)))
        r = call("check", {"text": "x"})
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")
        assert r.diag.exc_type == "Weird"
        assert r.diag.where is None
        assert _clean(r)

    def test_exception_with_hostile_class_name(self, monkeypatch):
        Evil = type(CANARY + "\n spoof", (Exception,), {})
        monkeypatch.setattr(protocol.core, "check_text", _boom(Evil(CANARY)))
        r = call("check", {"text": "x"})
        assert r.diag.exc_type is None
        assert _clean(r)

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit, GeneratorExit])
    def test_base_exceptions_propagate(self, monkeypatch, exc):
        monkeypatch.setattr(protocol.core, "check_text", _boom(exc()))
        with pytest.raises(exc):
            call("check", {"text": "x"})

    def test_success_has_no_diag(self, fake):
        assert call("check", {"text": "x"}).diag is None

    def test_unserialisable_core_result_is_500(self, monkeypatch):
        class R:
            def to_dict(self):
                return {"findings": [], "entity_counts": float("nan")}

        monkeypatch.setattr(protocol.core, "check_text", lambda *a, **k: R())
        u = protocol.UsageCounter()
        r = call("check", {"text": "x"}, usage=u)
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")
        assert u.requests_served == 0

    def test_to_dict_raising_is_500(self, monkeypatch):
        class R:
            def to_dict(self):
                raise ValueError(CANARY)

        monkeypatch.setattr(protocol.core, "check_text", lambda *a, **k: R())
        r = call("check", {"text": "x"})
        assert r.status == 500 and _clean(r)

    @pytest.mark.parametrize("rid", [CANARY, "", "../x", "r_", "R_AB", "r_" + "a" * 200,
                                     "r_zz", None, 5, "r_ab\n"])
    def test_bad_request_ids_are_replaced_not_echoed(self, fake, rid):
        r = call("check", b"{", rid=rid)
        got = jbody(r)["request_id"]
        assert got == "r_0"
        assert _clean(r)

    def test_good_request_ids_are_echoed(self, fake):
        for rid in ("r_0", "r_deadbeef", "r_" + "a" * 32):
            assert jbody(call("check", b"{", rid=rid))["request_id"] == rid


# ------------------------------------------------- canary: no matched text

class TestFindingsNeverContainMatchedText:
    TEXT = f"Please write to {CANARY.lower()}@example.test about it, ssn 078-05-1120."

    def test_check_response_has_no_canary(self):
        r = call("check", {"text": self.TEXT})
        assert r.status == 200
        blob = r.body.decode()
        assert CANARY.lower() not in blob
        assert not any(w.lower() in blob.lower() for w in CANARY_WINDOWS)
        assert "078-05-1120" not in blob

    def test_redact_findings_part_has_no_canary(self):
        b = jbody(call("redact", {"text": self.TEXT, "return_mapping": False}))
        blob = json.dumps(b)
        assert CANARY.lower() not in blob.lower()
        assert "078-05-1120" not in blob

    def test_redact_with_mapping_only_in_mapping(self):
        b = jbody(call("redact", {"text": self.TEXT}))
        side = json.dumps({k: v for k, v in b.items() if k != "mapping"})
        assert CANARY.lower() not in side.lower()
        assert CANARY.lower() in json.dumps(b["mapping"]).lower()

    def test_findings_shape_has_no_extra_fields(self):
        for f in jbody(call("check", {"text": self.TEXT}))["findings"]:
            assert set(f) == {"type", "start_offset", "end_offset", "confidence"}


# ----------------------------------------------------------------- silence

SILENCE_SCRIPT = r'''
import io, logging, sys, warnings
warnings.simplefilter("error")
logging.basicConfig(level=0, stream=sys.stderr)
import pii_buddy.server.protocol
'''


class TestSilence:
    def test_import_is_silent(self, tmp_path):
        env = dict(os.environ, PII_BUDDY_DIR=str(tmp_path / "PII_Buddy"))
        p = subprocess.run(
            [sys.executable, "-c", SILENCE_SCRIPT], capture_output=True, text=True,
            timeout=120, env=env, cwd=str(pathlib.Path(__file__).resolve().parent.parent),
        )
        assert p.returncode == 0, p.stderr[-2000:]
        assert p.stdout == ""
        assert p.stderr == ""

    def test_all_routes_are_silent(self, monkeypatch, capsys, caplog):
        install_fake_core(monkeypatch)
        root = logging.getLogger()
        old = root.level
        root.setLevel(0)
        caplog.set_level(0)
        try:
            rpc = {"jsonrpc": "2.0", "id": 1}
            bodies = [
                ("health", None), ("usage", None),
                ("check", {"text": "a@b.c"}), ("check", b"{"), ("check", [1]),
                ("redact", {"text": "a@b.c"}), ("redact", {"text": 5}),
                ("restore", {"redacted_text": "x", "mapping": {}}),
                ("restore", {"redacted_text": "x", "mapping": []}),
                ("nope", {}),
                ("mcp", dict(rpc, method="initialize", params={"protocolVersion": "2025-06-18"})),
                ("mcp", dict(rpc, method="tools/list")),
                ("mcp", dict(rpc, method="tools/call",
                             params={"name": "pii_check", "arguments": {"text": "a@b.c"}})),
                ("mcp", dict(rpc, method="tools/call",
                             params={"name": "pii_check", "arguments": {"text": 5}})),
                ("mcp", dict(rpc, method="tools/call",
                             params={"name": "pii_redact", "arguments": {"text": "x", "verify": True}})),
                ("mcp", dict(rpc, method="bogus")),
                ("mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}),
                ("mcp", b"{"), ("mcp", [1]),
            ]
            for route, obj in bodies:
                call(route, obj)
            monkeypatch.setattr(protocol.core, "check_text", _boom(ValueError(CANARY)))
            call("check", {"text": "x"})
            call("mcp", dict(rpc, method="tools/call",
                             params={"name": "pii_check", "arguments": {"text": "x"}}))
        finally:
            root.setLevel(old)
        out = capsys.readouterr()
        assert out.out == "" and out.err == ""
        assert caplog.records == []

    def test_source_has_no_io_primitives(self):
        src = pathlib.Path(protocol.__file__).read_text()
        for needle in ("print(", "import logging", "logging.", "sys.stdout", "sys.stderr",
                       "open(", "import socket", "import os", "import subprocess",
                       "Thread(", "_restore_unchecked", "pathlib", "import sys"):
            assert needle not in src, needle

    def test_baseexception_is_never_named_or_caught(self):
        import ast
        src = pathlib.Path(protocol.__file__).read_text()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ExceptHandler):
                assert node.type is not None, "bare except"
                names = [n.id for n in ast.walk(node.type) if isinstance(n, ast.Name)]
                assert names == ["Exception"], names
            if isinstance(node, ast.Name):
                assert node.id != "BaseException"
            if isinstance(node, ast.Attribute):
                assert node.attr != "BaseException"


# ----------------------------------------------- review round: PR #25 findings

BARE = ("health", "usage", "check", "redact", "restore", "mcp")


class TestRouteTable:
    def test_dispatch_keys_are_the_guards_strings(self):
        assert protocol.ROUTES == frozenset(ROUTE.values())

    @pytest.mark.parametrize("name", BARE)
    def test_bare_names_are_not_routes(self, name):
        r = protocol.handle(name, b"{}", request_id=RID, usage=protocol.UsageCounter())
        assert (r.status, jbody(r)["error"]) == (404, "not_found")

    def test_unhashable_route_is_404_not_a_crash(self):
        r = protocol.handle([1], b"{}", request_id=RID, usage=protocol.UsageCounter())
        assert (r.status, jbody(r)["error"]) == (404, "not_found")


class TestResponseReprIsBodyFree:
    def _resp(self, fake_installed=True):
        return protocol.Response(
            200, b'{"mapping":{"<<NAME_1>>":"%s"}}' % CANARY.encode(),
            diag=protocol.Diag("internal_error", "ValueError", "x.py:f:1"),
            entity_count=3,
        )

    def _all_renderings(self, resp):
        yield repr(resp)
        yield str(resp)
        yield f"{resp}"
        yield "%s" % (resp,)
        yield "%r" % (resp,)
        yield format(resp)
        yield format(resp, "")
        yield "{}".format(resp)
        yield pprint.pformat(resp)
        yield pprint.pformat([resp, {"k": resp}], width=20)
        yield repr([resp])

    def test_canary_never_rendered(self):
        for text in self._all_renderings(self._resp()):
            assert CANARY not in text
            assert not any(w in text for w in CANARY_WINDOWS), text

    def test_real_route_response_never_rendered(self, fake):
        resp = call("redact", {"text": "Mail %s@example.test now" % CANARY.lower()})
        assert CANARY.lower() in resp.body.decode()
        for text in self._all_renderings(resp):
            assert CANARY.lower() not in text

    def test_metadata_fields_stay_visible(self):
        text = repr(self._resp())
        assert "status=200" in text
        assert "entity_count=3" in text
        assert "internal_error" in text and "ValueError" in text
        assert "body" not in text

    def test_body_field_is_still_a_normal_field(self):
        r = self._resp()
        assert r.body.startswith(b'{"mapping"')
        assert dataclasses.replace(r, status=500).body == r.body

    def test_diag_repr_has_only_metadata(self):
        d = protocol.Diag("internal_error", "ValueError", "x.py:f:1")
        assert repr(d) == "Diag(code='internal_error', exc_type='ValueError', where='x.py:f:1')"


# ------------------------------------------------ hostile exception objects

class _Meta(type):
    @property
    def __name__(cls):
        raise RuntimeError(CANARY)


def _hostile_core_errors():
    class BadCode(core.CoreError):
        code = property(lambda s: (_ for _ in ()).throw(RuntimeError(CANARY)),
                        lambda s, v: None)

    class IntCode(core.CoreError):
        code = property(lambda s: 5, lambda s, v: None)

    class ListCode(core.CoreError):
        code = property(lambda s: [CANARY], lambda s, v: None)

    class HugeCode(core.CoreError):
        code = property(lambda s: "x" * 10_000, lambda s, v: None)

    class StrSub(str):
        def __hash__(self):
            raise RuntimeError(CANARY)

        def __eq__(self, other):
            raise RuntimeError(CANARY)

    class SubclassCode(core.CoreError):
        code = property(lambda s: StrSub("invalid_text"), lambda s, v: None)

    class BadWhere(core.CoreError):
        where = property(lambda s: (_ for _ in ()).throw(RuntimeError(CANARY)),
                         lambda s, v: None)

    class BadExcType(core.CoreError):
        exc_type = property(lambda s: (_ for _ in ()).throw(RuntimeError(CANARY)),
                            lambda s, v: None)

    class BadClass(core.CoreError):
        __class__ = property(lambda s: (_ for _ in ()).throw(RuntimeError(CANARY)))

    class BadMeta(core.CoreError, metaclass=_Meta):
        pass

    class BadGetattr(core.CoreError):
        def __getattribute__(self, name):
            if name in ("code", "where", "exc_type"):
                raise RuntimeError(CANARY)
            return super().__getattribute__(name)

    out = {}
    for cls in (BadCode, IntCode, ListCode, HugeCode, SubclassCode, BadWhere,
                BadExcType, BadClass, BadMeta, BadGetattr):
        out[cls.__name__ if cls is not BadMeta else "BadMeta"] = cls
    return out


HOSTILE = _hostile_core_errors()


def _mcp_check_call():
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "pii_check", "arguments": {"text": "x"}}}


def _safe_call(*args, **kwargs):
    """call() that turns any escape into a plain failure; a hostile exception
    must not get as far as pytest's own traceback rendering."""
    resp = None
    escaped = False
    try:
        resp = call(*args, **kwargs)
    except BaseException:
        escaped = True
    if escaped:
        pytest.fail("handle() raised")
    return resp


class TestHandleNeverRaises:
    @pytest.mark.parametrize("name", sorted(HOSTILE))
    @pytest.mark.parametrize("via", ["rest", "mcp_tool"])
    def test_hostile_core_error(self, monkeypatch, name, via):
        cls = HOSTILE[name]
        monkeypatch.setattr(
            protocol.core, "check_text",
            _boom(cls("invalid_text", CANARY, "SomeError", "x.py:f:1")))
        u = protocol.UsageCounter()
        if via == "rest":
            r = _safe_call("check", {"text": "x"}, usage=u)
            assert type(r.body) is bytes
            assert jbody(r)["request_id"] == RID
        else:
            r = _safe_call("mcp", _mcp_check_call(), usage=u)
            assert r.status == 200
            assert jbody(r)["result"]["isError"] is True
        assert _clean(r)
        assert CANARY not in repr(r)
        assert u.requests_served == 0
        assert r.diag is not None and r.diag.code in {
            "internal_error", "invalid_text"}
        assert r.diag.where in (None, "x.py:f:1")

    @pytest.mark.parametrize("name", ["BadCode", "IntCode", "ListCode", "HugeCode",
                                      "SubclassCode", "BadGetattr"])
    def test_unreadable_code_falls_back_to_internal_error(self, monkeypatch, name):
        monkeypatch.setattr(
            protocol.core, "check_text",
            _boom(HOSTILE[name]("invalid_text", CANARY, "SomeError", "x.py:f:1")))
        r = _safe_call("check", {"text": "x"})
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")
        assert r.diag.code == "internal_error"

    @pytest.mark.parametrize("name", ["BadWhere", "BadExcType"])
    def test_unreadable_metadata_keeps_the_code(self, monkeypatch, name):
        monkeypatch.setattr(
            protocol.core, "check_text",
            _boom(HOSTILE[name]("invalid_text", CANARY, "SomeError", "x.py:f:1")))
        r = _safe_call("check", {"text": "x"})
        assert (r.status, jbody(r)["error"]) == (400, "invalid_text")
        if name == "BadWhere":
            assert r.diag.where is None and r.diag.exc_type == "SomeError"
        else:
            assert r.diag.exc_type is None and r.diag.where == "x.py:f:1"

    def test_exception_with_hostile_metaclass_name(self, monkeypatch):
        class Boom(Exception, metaclass=_Meta):
            pass

        monkeypatch.setattr(protocol.core, "check_text", _boom(Boom(CANARY)))
        r = _safe_call("check", {"text": "x"})
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")
        assert r.diag == protocol.Diag("internal_error", None, None)

    def test_hostile_protocol_error_subclass(self, monkeypatch):
        class Evil(protocol.ProtocolError):
            code = property(lambda s: (_ for _ in ()).throw(RuntimeError(CANARY)),
                            lambda s, v: None)

        monkeypatch.setattr(protocol.core, "check_text", _boom(Evil("invalid_text")))
        r = _safe_call("check", {"text": "x"})
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")

    def test_broken_usage_counter_cannot_raise(self, fake):
        class Broken:
            @property
            def requests_served(self):
                raise RuntimeError(CANARY)

            def increment(self):
                raise RuntimeError(CANARY)

        r = protocol.handle(ROUTE["usage"], None, request_id=RID, usage=Broken())
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")
        r = protocol.handle(ROUTE["check"], b'{"text":"a@b.c"}', request_id=RID,
                            usage=Broken())
        assert r.status == 200


# ----------------------------------------------- iterative nesting pre-scan

def _nest(n, kind="["):
    if kind == "[":
        return b"[" * n + b"1" + b"]" * n
    if kind == "{":
        return b'{"a":' * n + b"1" + b"}" * n
    out = b"1"
    for i in range(n):
        out = (b"[" + out + b"]") if i % 2 == 0 else (b'{"a":' + out + b"}")
    return out


class TestNestingPrescan:
    @pytest.mark.parametrize("kind", ["[", "{", "mix"])
    def test_boundary_16_ok_17_rejected(self, kind):
        protocol.parse_json_body(_nest(16, kind))
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(_nest(17, kind))
        assert e.value.code == "invalid_json"

    @pytest.mark.parametrize("kind", ["[", "{", "mix"])
    def test_prescan_flags_exactly_depth_17(self, kind):
        assert protocol._too_deep(_nest(16, kind)) is False
        assert protocol._too_deep(_nest(17, kind)) is True

    def test_deep_input_never_reaches_the_c_parser(self, monkeypatch):
        calls = []
        real = protocol.json.loads

        def spy(*a, **k):
            calls.append(1)
            return real(*a, **k)

        monkeypatch.setattr(protocol.json, "loads", spy)
        for n in (17, 100, 10_000):
            for kind in ("[", "{", "mix"):
                with pytest.raises(protocol.ProtocolError):
                    protocol.parse_json_body(_nest(n, kind))
        assert calls == []
        protocol.parse_json_body(_nest(16))
        assert calls == [1]

    def test_brackets_inside_strings_do_not_count(self):
        body = b'{"a":"' + b"[" * 1000 + b'"}'
        assert protocol._too_deep(body) is False
        assert protocol.parse_json_body(body) == {"a": "[" * 1000}
        body = b'["' + b"{[" * 500 + b'",' + b"[" * 15 + b"1" + b"]" * 15 + b"]"
        assert protocol._too_deep(body) is False
        protocol.parse_json_body(body)

    def test_escaped_quote_does_not_end_the_string(self):
        body = b'["\\"' + b"[" * 100 + b'"]'
        assert protocol._too_deep(body) is False
        assert protocol.parse_json_body(body) == ['"' + "[" * 100]

    def test_escaped_backslash_then_quote_does_end_the_string(self):
        body = b'["\\\\"' + b",[" * 17 + b"]" * 17 + b"]"
        assert protocol._too_deep(body) is True
        short = b'["\\\\"' + b",[" * 3 + b"]" * 3 + b"]"
        assert protocol._too_deep(short) is False

    def test_long_backslash_runs(self):
        for k in (1, 2, 3, 4, 7, 100, 1001):
            odd = b'["' + b"\\" * k + b'",' + b"[" * 17
            even_close = b'["' + b"\\" * k + b'"' + b",[" * 17 + b"]" * 17 + b"]"
            assert protocol._too_deep(even_close) is (k % 2 == 0), k
            assert protocol._too_deep(odd) is (k % 2 == 0), k

    def test_unterminated_string_and_bad_escapes_are_left_to_the_parser(self):
        for body in (b'["abc', b'["\\', b'["\\x[[[[[[[[[[[[[[[[[[[[[[["]', b'"', b"\\", b""):
            assert protocol._too_deep(body) is False
            with pytest.raises(protocol.ProtocolError) as e:
                protocol.parse_json_body(body)
            assert e.value.code == "invalid_json"

    def test_unbalanced_closers_do_not_go_negative(self):
        body = b"]" * 100 + b"[" * 16
        assert protocol._too_deep(body) is False
        body = b"]" * 100 + b"[" * 17
        assert protocol._too_deep(body) is True

    def test_non_ascii_bytes_do_not_confuse_the_scan(self):
        body = '["é\U0001f600[[[[[[[[[[[[[[[[[[[[[["]'.encode()
        assert protocol._too_deep(body) is False
        assert protocol.parse_json_body(body)[0].startswith("é")

    def test_walk_is_still_a_second_layer(self, monkeypatch):
        monkeypatch.setattr(protocol, "_too_deep", lambda b: False)
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(_nest(17))
        assert e.value.code == "invalid_json"


PRESCAN_SCRIPT = r'''
import json, sys
sys.setrecursionlimit(1_000_000)
from pii_buddy.server import protocol

N = 512 * 1024
cases = {
    "open_arr": b"[" * N,
    "open_obj": b"{" * N,
    "quotes": b'"' * N,
    "backslashes": b"\\" * N,
    "obj_keys": b'{"a":' * (N // 5),
    "arr_in_string": b'["' + b"[" * (N - 4) + b'"]',
    "str_then_deep": b'["' + b"\\\\" * 1000 + b'"' + b",[" * 100000,
    "mix": (b'["[{\\"' + b"[{" * 1000 + b'"' + b",{" * 20000)[:N],
    "alternating": (b'"[' * (N // 2)),
    "deep_10000": b"[" * 10000 + b"1" + b"]" * 10000,
    "deep_obj_10000": b'{"a":' * 10000 + b"1" + b"}" * 10000,
    "deep_100000": b"[" * 100000 + b"1" + b"]" * 100000,
}
out = {}
for name, body in cases.items():
    assert len(body) <= N, name
    try:
        protocol.parse_json_body(body)
        out[name] = "ok"
    except protocol.ProtocolError as e:
        out[name] = e.code
    r = protocol.handle("POST /mcp", body, request_id="r_1", usage=protocol.UsageCounter())
    out[name + ":mcp"] = r.status
print(json.dumps(out))
'''


class TestPrescanInSubprocess:
    def test_pathological_bodies_under_a_raised_recursion_limit(self, tmp_path):
        env = dict(os.environ, PII_BUDDY_DIR=str(tmp_path / "PII_Buddy"))
        p = subprocess.run(
            [sys.executable, "-c", PRESCAN_SCRIPT],
            capture_output=True, text=True, timeout=30, env=env,
            cwd=str(pathlib.Path(__file__).resolve().parent.parent),
        )
        assert p.returncode == 0, (p.returncode, p.stderr[-2000:])
        assert p.stderr == ""
        out = json.loads(p.stdout)
        for name in ("open_arr", "open_obj", "quotes", "backslashes", "obj_keys",
                     "str_then_deep", "deep_10000", "deep_obj_10000", "deep_100000"):
            assert out[name] == "invalid_json", (name, out[name])
        assert out["arr_in_string"] == "ok"  # brackets inside a string are not nesting
        assert out["alternating"] == "invalid_json"
        assert out["mix"] == "invalid_json"
        for k, v in out.items():
            if k.endswith(":mcp"):
                assert v in (400, 413), (k, v)


# ---------------------------------------------------------- surviving mutants

class TestFloatLengthEdge:
    def test_64_chars_ok_65_rejected(self):
        ok = b"0." + b"1" * 62
        assert len(ok) == 64
        assert protocol.parse_json_body(ok) == float(ok)
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(b"0." + b"1" * 63)
        assert e.value.code == "invalid_json"
        assert protocol.parse_json_body(b'{"a":' + ok + b"}") == {"a": float(ok)}
        with pytest.raises(protocol.ProtocolError):
            protocol.parse_json_body(b'{"a":0.' + b"1" * 63 + b"}")

    def test_int_digit_edge(self):
        assert protocol.parse_json_body(b"9" * 20) == int("9" * 20)
        assert protocol.parse_json_body(b"-" + b"9" * 20) == -int("9" * 20)
        with pytest.raises(protocol.ProtocolError):
            protocol.parse_json_body(b"9" * 21)
        with pytest.raises(protocol.ProtocolError):
            protocol.parse_json_body(b"-" + b"9" * 21)


class _YieldingCounter(protocol.UsageCounter):
    """Reads of the count stall now and then between read and write, so an
    unlocked read-modify-write loses updates even when the GIL would hide it.
    Under the lock the stall is serialised and costs nothing but time."""

    _ticks = itertools.count()

    @property
    def _n(self):
        value = self.__dict__["_value"]
        if next(self._ticks) % 50 == 0:
            time.sleep(1e-4)
        return value

    @_n.setter
    def _n(self, v):
        self.__dict__["_value"] = v


def _hammer(counter, threads=16, per=5000):
    start = threading.Barrier(threads)

    def work():
        start.wait()
        for _ in range(per):
            counter.increment()

    ts = [threading.Thread(target=work) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


class TestUsageCounterIsLocked:
    def test_16_threads_x_5000_with_forced_interleaving(self):
        c = _YieldingCounter()
        _hammer(c)
        assert c.requests_served == 80_000

    def test_16_threads_x_5000_with_tiny_switch_interval(self):
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            c = protocol.UsageCounter()
            _hammer(c)
        finally:
            sys.setswitchinterval(old)
        assert c.requests_served == 80_000

    def test_new_counter_is_zero_and_instances_are_independent(self):
        a, b = protocol.UsageCounter(), protocol.UsageCounter()
        a.increment()
        assert (a.requests_served, b.requests_served) == (1, 0)


class TestEntityCountField:
    @pytest.fixture
    def three(self, monkeypatch):
        f = (core.Finding("EMAIL", 0, 3, 0.5), core.Finding("EMAIL", 4, 7, 0.5),
             core.Finding("PHONE", 8, 12, 0.5))
        counts = {"EMAIL": 2, "PHONE": 1}
        monkeypatch.setattr(protocol.core, "check_text",
                            lambda t, document_type="auto": core.CheckResult(f, counts))
        monkeypatch.setattr(
            protocol.core, "redact_text",
            lambda t, document_type="auto", audit=True: core.RedactResult(
                "R", {"<<EMAIL_1>>": "x"}, f, counts, 1))

    def test_rest_check_and_redact_count_findings(self, three):
        for route in ("check", "redact"):
            r = call(route, {"text": "x"})
            assert type(r.entity_count) is int
            assert r.entity_count == len(jbody(r)["findings"]) == 3

    def test_mcp_check_and_redact_count_findings(self, three):
        for name in ("pii_check", "pii_redact"):
            r = call("mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": name, "arguments": {"text": "x"}}})
            res = jbody(r)["result"]
            assert res["isError"] is False
            assert type(r.entity_count) is int
            assert r.entity_count == len(res["structuredContent"]["findings"]) == 3

    def test_zero_findings_is_zero_not_none(self, fake):
        r = call("check", {"text": "nothing here"})
        assert r.entity_count == 0 and type(r.entity_count) is int

    def test_none_where_documented(self, fake):
        assert call("restore", {"redacted_text": "x", "mapping": {}}).entity_count is None
        assert call("health").entity_count is None
        assert call("usage").entity_count is None
        assert call("check", b"{").entity_count is None
        assert call("check", {"text": 5}).entity_count is None
        assert call("nope", {}).entity_count is None
        for obj in ({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "pii_usage"}},
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "pii_check", "arguments": {"text": 5}}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"}):
            assert call("mcp", obj).entity_count is None, obj

    def test_restore_count_is_none_even_with_a_mapping(self, fake):
        r = call("restore", {"redacted_text": "<<EMAIL_1>> <<EMAIL_1>>",
                             "mapping": {"<<EMAIL_1>>": "a@b.c"}})
        assert r.status == 200 and r.entity_count is None


class TestMcpInternalFailureContract:
    """Contract (local_api_design.md, MCP): tool errors are results with
    isError:true, not JSON-RPC errors, and still HTTP 200.  Only a failure
    outside any tool (here: the result cannot be encoded) is HTTP 500 with a
    JSON-RPC -32603 error and a null id."""

    CALL = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "pii_check", "arguments": {"text": "x"}}}

    def test_plain_exception_in_a_tool_is_http_200_is_error(self, monkeypatch):
        monkeypatch.setattr(protocol.core, "check_text", _boom(Exception(CANARY)))
        u = protocol.UsageCounter()
        r = call("mcp", self.CALL, usage=u)
        assert r.status == 200
        b = jbody(r)
        assert set(b) == {"jsonrpc", "id", "result"} and b["id"] == 7
        assert b["result"]["isError"] is True
        assert b["result"]["structuredContent"] == {
            "error": "internal_error", "message": "internal error", "request_id": RID}
        assert r.diag == protocol.Diag("internal_error", "Exception", None)
        assert r.entity_count is None and u.requests_served == 0
        assert _clean(r)

    def test_unencodable_result_is_http_500_jsonrpc_internal_error(self, monkeypatch):
        class Bad:
            def to_dict(self):
                return {"entity_counts": {}, "findings": [], "x": float("nan")}

        monkeypatch.setattr(protocol.core, "check_text", lambda *a, **k: Bad())
        u = protocol.UsageCounter()
        r = call("mcp", self.CALL, usage=u)
        assert r.status == 500
        assert jbody(r) == {"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32603, "message": "Internal error"}}
        assert r.diag is not None and r.diag.code == "internal_error"
        assert r.headers == HEADERS and u.requests_served == 0

    def test_same_failure_on_rest_is_the_fixed_500(self, monkeypatch):
        class Bad:
            def to_dict(self):
                return {"x": float("nan")}

        monkeypatch.setattr(protocol.core, "check_text", lambda *a, **k: Bad())
        r = call("check", {"text": "x"})
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")


# ------------------------------------------- review round 2: PR #25 findings

import asyncio

_PY311 = sys.version_info >= (3, 11)


class _CustomInterrupt(BaseException):
    pass


def _interrupts():
    out = {
        "KeyboardInterrupt": KeyboardInterrupt,
        "SystemExit": lambda: SystemExit(3),
        "GeneratorExit": GeneratorExit,
        "CancelledError": asyncio.CancelledError,
        "Custom": lambda: _CustomInterrupt(CANARY),
    }
    if _PY311:
        out["GroupOfKeyboardInterrupt"] = lambda: BaseExceptionGroup(
            "g", [KeyboardInterrupt()])
        out["GroupOfSystemExit"] = lambda: BaseExceptionGroup("g", [SystemExit(3)])
    return out


INTERRUPTS = _interrupts()

CORE_FNS = {
    "check": ("check_text", "pii_check"),
    "redact": ("redact_text", "pii_redact"),
}


def _mcp_tool_call(tool, text="x"):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": {"text": text}}}


class TestInterruptsPropagate:
    """Anything that is not an ``Exception`` is an interrupt or a cancellation
    and leaves handle() untouched."""

    @pytest.mark.parametrize("name", sorted(INTERRUPTS))
    @pytest.mark.parametrize("route", ["check", "redact", "restore"])
    def test_rest(self, monkeypatch, name, route):
        fn = {"check": "check_text", "redact": "redact_text", "restore": "restore_text"}[route]
        body = {"redacted_text": "x", "mapping": {}} if route == "restore" else {"text": "x"}
        exc = INTERRUPTS[name]()
        monkeypatch.setattr(protocol.core, fn, _boom(exc))
        u = protocol.UsageCounter()
        with pytest.raises(type(exc)):
            call(route, body, usage=u)
        assert u.requests_served == 0

    @pytest.mark.parametrize("name", sorted(INTERRUPTS))
    @pytest.mark.parametrize("route", ["check", "redact"])
    def test_mcp_tools(self, monkeypatch, name, route):
        fn, tool = CORE_FNS[route]
        exc = INTERRUPTS[name]()
        monkeypatch.setattr(protocol.core, fn, _boom(exc))
        u = protocol.UsageCounter()
        with pytest.raises(type(exc)):
            call("mcp", _mcp_tool_call(tool), usage=u)
        assert u.requests_served == 0

    @pytest.mark.parametrize("route", ["check", "mcp"])
    def test_interrupt_from_a_hostile_attribute_still_propagates(self, monkeypatch, route):
        class Bad(core.CoreError):
            code = property(lambda s: (_ for _ in ()).throw(KeyboardInterrupt()),
                            lambda s, v: None)

        monkeypatch.setattr(protocol.core, "check_text",
                            _boom(Bad("invalid_text", CANARY, "E", "x.py:f:1")))
        obj = {"text": "x"} if route == "check" else _mcp_tool_call("pii_check")
        with pytest.raises(KeyboardInterrupt):
            call(route, obj)

    def test_interrupt_from_the_usage_counter_propagates(self, fake):
        class U:
            requests_served = 0

            def increment(self):
                raise KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            protocol.handle(ROUTE["check"], b'{"text":"a@b.c"}', request_id=RID, usage=U())


def _ordinary():
    out = {
        "ValueError": lambda: ValueError(CANARY),
        "UnicodeEncodeError": lambda: UnicodeEncodeError("utf-8", CANARY, 0, 1, CANARY),
        "MemoryError": lambda: MemoryError(CANARY),
        "RecursionError": lambda: RecursionError(CANARY),
        "KeyError": lambda: KeyError(CANARY),
        "Exception": lambda: Exception(CANARY),
    }
    for code in sorted(CORE_CODE_STATUS) + ["not_found", "verify_not_supported", CANARY]:
        out["CoreError:" + code] = (
            lambda code=code: core.CoreError(code, CANARY, "SomeError", "x.py:f:1"))
    if _PY311:
        out["ExceptionGroup"] = lambda: ExceptionGroup(
            CANARY, [ValueError(CANARY), KeyError(CANARY)])
    return out


ORDINARY = _ordinary()


def _expected(name):
    if name.startswith("CoreError:"):
        code = name.split(":", 1)[1]
        if code in CORE_CODE_STATUS:
            return CORE_CODE_STATUS[code], code
    return 500, "internal_error"


class TestOrdinaryExceptionsAreFixedResponses:
    @pytest.mark.parametrize("name", sorted(ORDINARY))
    @pytest.mark.parametrize("fn,body", [
        ("check_text", {"text": "x"}),
        ("redact_text", {"text": "x"}),
        ("restore_text", {"redacted_text": "x", "mapping": {}}),
    ])
    def test_rest(self, monkeypatch, name, fn, body):
        monkeypatch.setattr(protocol.core, fn, _boom(ORDINARY[name]()))
        u = protocol.UsageCounter()
        route = {"check_text": "check", "redact_text": "redact", "restore_text": "restore"}[fn]
        r = call(route, body, usage=u)
        status, code = _expected(name)
        assert (r.status, jbody(r)["error"]) == (status, code)
        assert set(jbody(r)) == ERROR_KEYS and _clean(r)
        assert r.diag is not None and r.diag.code == code
        assert u.requests_served == 0

    @pytest.mark.parametrize("name", sorted(ORDINARY))
    @pytest.mark.parametrize("fn,tool", [("check_text", "pii_check"),
                                         ("redact_text", "pii_redact")])
    def test_mcp_tool(self, monkeypatch, name, fn, tool):
        monkeypatch.setattr(protocol.core, fn, _boom(ORDINARY[name]()))
        u = protocol.UsageCounter()
        r = call("mcp", _mcp_tool_call(tool), usage=u)
        _, code = _expected(name)
        assert r.status == 200
        res = jbody(r)["result"]
        assert res["isError"] is True and res["structuredContent"]["error"] == code
        assert _clean(r) and r.diag.code == code
        assert u.requests_served == 0


def _raising(exc_factory):
    return property(lambda s: (_ for _ in ()).throw(exc_factory()), lambda s, v: None)


ATTR_EXCEPTIONS = {
    "ValueError": lambda: ValueError(CANARY),
    "RuntimeError": lambda: RuntimeError(CANARY),
    "KeyError": lambda: KeyError(CANARY),
    "AttributeError": lambda: AttributeError(CANARY),
    "TypeError": lambda: TypeError(CANARY),
    "RecursionError": lambda: RecursionError(CANARY),
    "MemoryError": lambda: MemoryError(CANARY),
}


class TestHostileAttributesRaisingOrdinaryExceptions:
    @pytest.mark.parametrize("exc", sorted(ATTR_EXCEPTIONS))
    @pytest.mark.parametrize("attr", ["code", "where", "exc_type"])
    @pytest.mark.parametrize("route", ["check", "mcp"])
    def test_property(self, monkeypatch, exc, attr, route):
        cls = type("Hostile", (core.CoreError,), {attr: _raising(ATTR_EXCEPTIONS[exc])})
        monkeypatch.setattr(protocol.core, "check_text",
                            _boom(cls("invalid_text", CANARY, "SomeError", "x.py:f:1")))
        obj = {"text": "x"} if route == "check" else _mcp_tool_call("pii_check")
        u = protocol.UsageCounter()
        r = _safe_call(route, obj, usage=u)
        want = "internal_error" if attr == "code" else "invalid_text"
        assert r.diag.code == want
        if route == "check":
            assert jbody(r)["error"] == want
        else:
            assert jbody(r)["result"]["isError"] is True
        assert _clean(r) and u.requests_served == 0

    @pytest.mark.parametrize("exc", sorted(ATTR_EXCEPTIONS))
    def test_metaclass_name(self, monkeypatch, exc):
        class Meta(type):
            __name__ = _raising(ATTR_EXCEPTIONS[exc])

        class Boom(Exception, metaclass=Meta):
            pass

        monkeypatch.setattr(protocol.core, "check_text", _boom(Boom(CANARY)))
        for route, obj in (("check", {"text": "x"}), ("mcp", _mcp_check_call())):
            r = _safe_call(route, obj)
            assert r.diag == protocol.Diag("internal_error", None, None)
            assert _clean(r)


class _NoIncrement:
    requests_served = 0


class _IncrementNotCallable:
    requests_served = 0
    increment = 5


class _IncrementRaisesOnLookup:
    requests_served = 0
    increment = _raising(lambda: ValueError(CANARY))


class _HostileGetattr:
    def __getattribute__(self, name):
        raise RuntimeError(CANARY)


class _IncrementVanishes:
    """A fine counter until core has run: the lookup then starts raising."""

    requests_served = 0

    def __init__(self):
        self.lookups = 0

    @property
    def increment(self):
        self.lookups += 1
        if self.lookups > 1:
            raise ValueError(CANARY)
        return lambda: None


class _IncrementRaises:
    requests_served = 0

    def increment(self):
        raise ValueError(CANARY)


BAD_USAGE = {
    "None": lambda: None,
    "NoIncrement": _NoIncrement,
    "NotCallable": _IncrementNotCallable,
    "LookupRaises": _IncrementRaisesOnLookup,
    "HostileGetattr": _HostileGetattr,
    "int": lambda: 5,
}


class TestUsageValidatedUpFront:
    @pytest.mark.parametrize("name", sorted(BAD_USAGE))
    @pytest.mark.parametrize("route", ["health", "usage", "check", "redact", "restore"])
    def test_rest_is_a_fixed_500_and_core_never_runs(self, monkeypatch, name, route):
        calls = []
        for fn in ("check_text", "redact_text", "restore_text"):
            monkeypatch.setattr(protocol.core, fn, lambda *a, **k: calls.append(1))
        body = b'{"text":"x"}' if route in ("check", "redact") else (
            b'{"redacted_text":"x","mapping":{}}' if route == "restore" else None)
        r = protocol.handle(ROUTE[route], body, request_id=RID, usage=BAD_USAGE[name]())
        assert (r.status, jbody(r)) == (500, {
            "error": "internal_error", "message": "internal error", "request_id": RID})
        assert r.diag is not None and r.diag.code == "internal_error"
        assert r.headers == HEADERS and _clean(r) and calls == []

    @pytest.mark.parametrize("name", sorted(BAD_USAGE))
    def test_mcp_is_a_jsonrpc_500_and_core_never_runs(self, monkeypatch, name):
        calls = []
        monkeypatch.setattr(protocol.core, "check_text", lambda *a, **k: calls.append(1))
        body = json.dumps(_mcp_tool_call("pii_check")).encode()
        r = protocol.handle(ROUTE["mcp"], body, request_id=RID, usage=BAD_USAGE[name]())
        assert r.status == 500
        assert jbody(r) == {"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32603, "message": "Internal error"}}
        assert r.diag.code == "internal_error" and calls == [] and _clean(r)

    @pytest.mark.parametrize("name", sorted(BAD_USAGE))
    def test_a_bad_usage_never_raises_for_unknown_routes_either(self, name):
        r = protocol.handle("GET /nope", b"", request_id=RID, usage=BAD_USAGE[name]())
        assert r.status in (404, 500) and _clean(r)

    @pytest.mark.parametrize("make", [_IncrementVanishes, _IncrementRaises])
    @pytest.mark.parametrize("route", ["check", "redact", "mcp"])
    def test_usage_failure_after_core_does_not_lose_the_response(self, fake, make, route):
        if route == "mcp":
            body = json.dumps(_mcp_tool_call("pii_check", "a@b.c")).encode()
        else:
            body = b'{"text":"a@b.c"}'
        r = protocol.handle(ROUTE[route], body, request_id=RID, usage=make())
        assert r.status == 200 and r.diag is None and r.entity_count == 1
        assert _clean(r)


class _HostileStr(str):
    def __eq__(self, other):
        raise RuntimeError(CANARY)

    def __hash__(self):
        raise RuntimeError(CANARY)


class _HostileObj:
    def __eq__(self, other):
        raise RuntimeError(CANARY)

    def __hash__(self):
        raise RuntimeError(CANARY)


class _Unhashable(list):
    pass


class TestRouteMustBeAnExactStr:
    @pytest.mark.parametrize("make", [
        lambda: _HostileStr("POST /mcp"), lambda: _HostileStr("POST /v1/check"),
        _HostileObj, _Unhashable, lambda: 5, lambda: None, lambda: b"POST /mcp",
    ])
    def test_is_404_and_never_compared(self, make):
        r = protocol.handle(make(), b"{}", request_id=RID, usage=protocol.UsageCounter())
        assert (r.status, jbody(r)["error"]) == (404, "not_found")
        assert _clean(r)

    def test_http_methods_the_guard_never_admits_are_404(self):
        for route in ("HEAD /v1/health", "HEAD /mcp", "OPTIONS /v1/check",
                      "PUT /v1/usage", "DELETE /mcp"):
            r = protocol.handle(route, b"", request_id=RID, usage=protocol.UsageCounter())
            assert (r.status, jbody(r)["error"]) == (404, "not_found"), route


class TestCoreCodesAreAllowListed:
    @pytest.mark.parametrize("code", ["not_found", "verify_not_supported", "bogus", ""])
    def test_codes_core_never_emits_are_internal(self, monkeypatch, code):
        monkeypatch.setattr(protocol.core, "check_text",
                            _boom(core.CoreError(code, CANARY, "E", "x.py:f:1")))
        r = call("check", {"text": "x"})
        assert (r.status, jbody(r)["error"]) == (500, "internal_error")
        assert r.diag.code == "internal_error"

    def test_the_allow_list_is_exactly_what_core_emits(self):
        assert protocol._CORE_CODES == frozenset(CORE_CODE_STATUS)


# ---------------------------------------------- guard routes without handlers

ROUTE_SCRIPT = r'''
import sys
from pii_buddy.server import guard
for spec in sys.argv[1:]:
    path, methods = spec.split("=")
    guard._ROUTES[path] = frozenset(methods.split(","))
try:
    import pii_buddy.server.protocol
except Exception as e:
    print(type(e).__name__ + "|" + str(e))
else:
    print("imported")
'''


def _import_with_routes(tmp_path, *specs):
    env = dict(os.environ, PII_BUDDY_DIR=str(tmp_path / "PII_Buddy"))
    p = subprocess.run(
        [sys.executable, "-c", ROUTE_SCRIPT, *specs],
        capture_output=True, text=True, timeout=60, env=env,
        cwd=str(pathlib.Path(__file__).resolve().parent.parent),
    )
    assert p.returncode == 0, p.stderr[-2000:]
    return p.stdout.strip()


class TestGuardRouteWithoutHandler:
    def test_a_seventh_path_fails_at_import_with_a_clear_message(self, tmp_path):
        out = _import_with_routes(tmp_path, "/v1/new=GET")
        kind, _, msg = out.partition("|")
        assert kind == "RuntimeError", out
        assert msg.startswith("protocol has no handler for guard route")
        assert "GET /v1/new" in msg

    def test_a_new_method_on_an_existing_path_is_not_silently_dispatched(self, tmp_path):
        out = _import_with_routes(tmp_path, "/v1/health=GET,HEAD")
        kind, _, msg = out.partition("|")
        assert kind == "RuntimeError", out
        assert "HEAD /v1/health" in msg

    def test_the_real_tables_import_cleanly(self, tmp_path):
        assert _import_with_routes(tmp_path) == "imported"


# ------------------------------ pre-scan: sibling containers (depth must drop)

def _arr(items):
    return b"[" + b",".join(items) + b"]"


class TestPrescanSiblings:
    def test_1000_empty_array_siblings_at_depth_2(self):
        body = _arr([b"[]"] * 1000)
        assert protocol._too_deep(body) is False
        assert protocol.parse_json_body(body) == [[]] * 1000

    def test_1000_empty_object_siblings_at_depth_2(self):
        body = _arr([b"{}"] * 1000)
        assert protocol._too_deep(body) is False
        assert protocol.parse_json_body(body) == [{}] * 1000

    def test_1000_keys_with_empty_array_values(self):
        body = b"{" + b",".join(b'"k%d":[]' % i for i in range(1000)) + b"}"
        assert protocol._too_deep(body) is False
        assert len(protocol.parse_json_body(body)) == 1000

    def test_1000_keys_with_empty_object_values(self):
        body = b"{" + b",".join(b'"k%d":{}' % i for i in range(1000)) + b"}"
        assert protocol._too_deep(body) is False
        assert len(protocol.parse_json_body(body)) == 1000

    def test_seventeen_sequential_one_element_siblings(self):
        body = _arr([b"[1]"] * 17)
        assert protocol._too_deep(body) is False
        assert protocol.parse_json_body(body) == [[1]] * 17

    @pytest.mark.parametrize("n", [15, 16, 17, 18, 33, 100])
    def test_sibling_counts_around_the_depth_limit(self, n):
        assert protocol._too_deep(_arr([b"[1]"] * n)) is False

    @pytest.mark.parametrize("pairs", [1, 16, 17, 100, 1000, 5000])
    def test_alternating_open_close_pairs(self, pairs):
        body = _arr([b"[]", b"{}"] * pairs)
        assert protocol._too_deep(body) is False
        assert len(protocol.parse_json_body(body)) == 2 * pairs
        mixed = b"[" + b",".join(b'{"a":[]}' for _ in range(pairs)) + b"]"
        assert protocol._too_deep(mixed) is False
        protocol.parse_json_body(mixed)

    def test_concatenated_values_are_not_too_deep_just_invalid(self):
        body = b"[]" * 5000
        assert protocol._too_deep(body) is False
        with pytest.raises(protocol.ProtocolError) as e:
            protocol.parse_json_body(body)
        assert e.value.code == "invalid_json"

    @pytest.mark.parametrize("wrap", [0, 1, 13, 14])
    def test_sibling_groups_up_to_depth_16_are_accepted(self, wrap):
        body = b"[" * wrap + _arr([b"[]"] * 1000) + b"]" * wrap
        assert protocol._too_deep(body) is False
        protocol.parse_json_body(body)

    @pytest.mark.parametrize("wrap", [15, 16, 17, 20])
    def test_sibling_groups_at_depth_17_are_rejected(self, wrap):
        body = b"[" * wrap + _arr([b"[]"] * 1000) + b"]" * wrap
        assert protocol._too_deep(body) is True
        with pytest.raises(protocol.ProtocolError):
            protocol.parse_json_body(body)

    def test_many_chains_that_each_reach_exactly_depth_16(self):
        chain = b"[" * 15 + b"1" + b"]" * 15
        body = _arr([chain] * 1000)
        assert protocol._too_deep(body) is False
        protocol.parse_json_body(body)

    def test_one_chain_among_many_reaching_depth_17_is_rejected(self):
        ok = b"[" * 15 + b"1" + b"]" * 15
        bad = b"[" * 16 + b"1" + b"]" * 16
        body = _arr([ok] * 500 + [bad] + [ok] * 500)
        assert protocol._too_deep(body) is True

    def test_object_chains_among_siblings(self):
        chain = b'{"a":' * 15 + b"1" + b"}" * 15
        body = b"{" + b",".join(b'"k%d":%s' % (i, chain) for i in range(300)) + b"}"
        assert protocol._too_deep(body) is False
        protocol.parse_json_body(body)


WIDE_SCRIPT = r'''
import json, sys
from pii_buddy.server import protocol

N = protocol.MAX_BODY_BYTES
out = {}
for name, unit in (("arrays", b"[1]"), ("objects", b'{"a":1}'), ("empty", b"[]")):
    count = (N - 2) // (len(unit) + 1)
    body = b"[" + b",".join([unit] * count) + b"]"
    assert len(body) <= N, name
    value = protocol.parse_json_body(body)
    out[name] = [len(body), len(value)]
    r = protocol.handle("POST /mcp", body, request_id="r_1", usage=protocol.UsageCounter())
    out[name + ":mcp"] = r.status
print(json.dumps(out))
'''


class TestWideButShallowDocument:
    def test_a_512_kib_document_is_accepted(self, tmp_path):
        env = dict(os.environ, PII_BUDDY_DIR=str(tmp_path / "PII_Buddy"))
        p = subprocess.run(
            [sys.executable, "-c", WIDE_SCRIPT],
            capture_output=True, text=True, timeout=60, env=env,
            cwd=str(pathlib.Path(__file__).resolve().parent.parent),
        )
        assert p.returncode == 0, (p.returncode, p.stderr[-2000:])
        out = json.loads(p.stdout)
        for name in ("arrays", "objects", "empty"):
            size, n = out[name]
            assert size > 500 * 1024 and n > 50_000, (name, out[name])
            assert out[name + ":mcp"] == 400  # valid JSON, but not a JSON-RPC message
