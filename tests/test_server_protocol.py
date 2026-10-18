"""pii_buddy.server.protocol: the REST half of the pure dispatcher, strict body
parsing, the error contract, the usage counter and the silence guarantee."""

import dataclasses
import json
import logging
import os
import pathlib
import subprocess
import sys
import threading

import pytest

from pii_buddy import core
from pii_buddy.server import protocol
from tests._protocol_helpers import (
    CANARY,
    HEADERS,
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
        r = protocol.handle(route, json.dumps(top).encode(), request_id=RID,
                            usage=protocol.UsageCounter())
        assert r.status == 400
        assert jbody(r)["error"] == "invalid_request"

    @pytest.mark.parametrize("route", sorted(ALLOWED))
    def test_missing_or_empty_body_is_invalid_json(self, fake, route):
        for body in (None, b"", b"   "):
            r = protocol.handle(route, body, request_id=RID, usage=protocol.UsageCounter())
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
            r = protocol.handle("check", body, request_id=RID, usage=protocol.UsageCounter())
            assert r.status == 400, name
            assert jbody(r) == {
                "error": "invalid_json",
                "message": jbody(r)["message"],
                "request_id": RID,
            }

    def test_rest_oversize_is_413(self, fake):
        r = protocol.handle("check", b" " * (512 * 1024 + 1), request_id=RID,
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
    r = protocol.handle("mcp", body, request_id="r_1", usage=protocol.UsageCounter())
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
                       "Thread(", "_restore_unchecked", "pathlib", "import sys",
                       "BaseException"):
            assert needle not in src, needle
