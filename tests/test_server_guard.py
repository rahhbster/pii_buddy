"""Tests for pii_buddy.server.guard: pure request admission control.

No sockets, threads or files.  All tokens and hosts here are fake.
"""

import random

import pytest

from pii_buddy.server import guard
from pii_buddy.server.guard import (
    BODY_CAP,
    MAX_INFLIGHT,
    READ_TIMEOUT,
    TEXT_CAP,
    Decision,
    check_request,
    check_text_length,
    compare_token,
    host_allowed,
    parse_bearer,
    target_allowed,
)

TOKEN = "fake-token_AbCdEf0123456789-ZyXwVu_9876543210"
PORT = 8123
PORTS = (PORT,)
HOST_OK = f"127.0.0.1:{PORT}"


def base(extra=(), drop=(), cl="12"):
    hdrs = [
        ("Host", HOST_OK),
        ("Authorization", f"Bearer {TOKEN}"),
        ("Content-Type", "application/json"),
        ("Content-Length", cl),
    ]
    dropl = {d.lower() for d in drop}
    hdrs = [(n, v) for n, v in hdrs if n.lower() not in dropl]
    return hdrs + list(extra)


def get_base(drop=()):
    return base(drop=("Content-Type", "Content-Length") + tuple(drop))


def run(method="POST", target="/v1/redact", headers=None, ports=PORTS, token=TOKEN):
    if headers is None:
        headers = base()
    return check_request(method, target, headers, expected_ports=ports, token=token)


def denied(d, status, code):
    assert d.allowed is False
    assert (d.status, d.code) == (status, code)


class TestConstants:
    def test_caps(self):
        assert BODY_CAP == 512 * 1024
        assert TEXT_CAP == 50_000
        assert READ_TIMEOUT == 10
        assert MAX_INFLIGHT == 4

    def test_decision_frozen(self):
        d = Decision(True, 200, "ok")
        with pytest.raises(Exception):
            d.allowed = False


class TestCompareToken:
    def test_match(self):
        assert compare_token(TOKEN, TOKEN) is True

    @pytest.mark.parametrize("bad", [
        None, "", " ", TOKEN + "x", TOKEN[:-1], TOKEN.upper(), TOKEN + " ",
        "x" * 1_000_000, "tok" * 50, "\ud800", "\x00", b"\xff\xfe", 12345,
    ])
    def test_mismatch_never_raises(self, bad):
        assert compare_token(bad, TOKEN) is False

    @pytest.mark.parametrize("exp", [None, "", b"", 0])
    def test_empty_expected_fails_closed(self, exp):
        assert compare_token("", exp) is False
        assert compare_token(None, exp) is False
        assert compare_token("anything", exp) is False

    def test_non_ascii_expected(self):
        assert compare_token("pässword", "pässword") is True
        assert compare_token("password", "pässword") is False
        assert compare_token("pässword\ud800", "pässword") is False

    def test_bytes_ok(self):
        assert compare_token(TOKEN.encode(), TOKEN) is True

    def test_uses_hmac_compare_digest_on_bytes(self, monkeypatch):
        calls = []
        real = guard.hmac.compare_digest

        def spy(a, b):
            calls.append((type(a), type(b)))
            return real(a, b)

        monkeypatch.setattr(guard.hmac, "compare_digest", spy)
        assert compare_token(TOKEN, TOKEN) is True
        assert calls and all(t == (bytes, bytes) for t in calls)


class TestParseBearer:
    @pytest.mark.parametrize("value", [
        f"Bearer {TOKEN}", f"bearer {TOKEN}", f"BEARER {TOKEN}",
    ])
    def test_ok(self, value):
        assert parse_bearer(value) == TOKEN

    @pytest.mark.parametrize("value", [
        None, "", "Bearer", "Bearer ", "Bearer  tok", " Bearer tok", "Bearer tok ",
        "Bearer tok extra", "Basic dGVzdDp0ZXN0", "Bearertok", "Bearer\ttok",
        "Bearer tok\n", "Bearer \x00", "Bearer tök", 5, b"Bearer tok",
        "Bearer " + "a" * 5000,
    ])
    def test_rejects(self, value):
        assert parse_bearer(value) is None


class TestHostAllowed:
    @pytest.mark.parametrize("host", [
        f"127.0.0.1:{PORT}", f"localhost:{PORT}", f"LOCALHOST:{PORT}",
        f"LocalHost:{PORT}",
    ])
    def test_ok(self, host):
        assert host_allowed(host, PORTS) is True

    @pytest.mark.parametrize("host", [
        None, "", "127.0.0.1", "localhost", f"127.0.0.1:{PORT + 1}",
        f"127.0.0.1.:{PORT}", f"localhost.:{PORT}", f"[::1]:{PORT}", "[::1]",
        f"127.0.0.1.evil.com:{PORT}", f"evil.com:{PORT}",
        f"user@127.0.0.1:{PORT}", f"user:pw@127.0.0.1:{PORT}",
        f"127.0.0.1:{PORT}@evil.com", f" 127.0.0.1:{PORT}", f"127.0.0.1:{PORT} ",
        f"127.0.0.1 :{PORT}", f"127.0.0.1: {PORT}", f"127.0.0.1:{PORT}\n",
        f"127.0.0.1:{PORT}\x00", f"127.0.0.1\x00.evil.com:{PORT}",
        f"127.0.0.1:{PORT}\t", f"127.0.0.1:0{PORT}", f"127.0.0.1:+{PORT}",
        f"127.0.0.1:{PORT},evil.com", f"127.0.0.1:{PORT}/x", f"127.0.0.1:{PORT}:1",
        f"127.0.0.1:{PORT}.0", "127.0.0.1:", f":{PORT}", f"0.0.0.0:{PORT}",
        f"127.1:{PORT}", f"2130706433:{PORT}", f"0x7f.0.0.1:{PORT}",
        f"127.0.0.1:{PORT}\r\nX: y",
        f"lоcalhost:{PORT}",
        f"ⅼⅼⅼ:{PORT}",
        f"127.0.0.１:{PORT}",
        "localhost:٨١٢٣",
        f"١٢٧.0.0.1:{PORT}",
        f"Klocalhost:{PORT}",
        "x" * 100_000, 7, b"127.0.0.1:8123",
    ])
    def test_rejects(self, host):
        assert host_allowed(host, PORTS) is False

    def test_port_set_and_single(self):
        assert host_allowed("127.0.0.1:9", (8, 9)) is True
        assert host_allowed("127.0.0.1:9", 9) is True
        assert host_allowed("127.0.0.1:10", (8, 9)) is False

    @pytest.mark.parametrize("ports", [(), None, (0,), (70000,), ("8123",), True])
    def test_bad_expected_ports_fail_closed(self, ports):
        assert host_allowed(f"127.0.0.1:{PORT}", ports) is False
        assert host_allowed("127.0.0.1:0", ports) is False


class TestTargetAllowed:
    @pytest.mark.parametrize("t", [
        "/", "/v1/health", "/v1/redact", "/mcp", "/v1/usage?x=1", "/v1/health?",
    ])
    def test_ok(self, t):
        assert target_allowed(t) is True

    @pytest.mark.parametrize("t", [
        None, "", "v1/health", "*", "http://127.0.0.1:8123/v1/health",
        "HTTP://x/", "https://evil.com/", "//evil.com/v1/health", "//",
        "/../etc/passwd", "/v1/../v1/health", "/v1/..", "/..", "/./v1",
        "/v1/./health", "/%2e%2e/x", "/%2E%2E/x", "/v1/%2e%2e/health",
        "/.%2e/x", "/%2e./x", "/v1%2fhealth", "/v1%5chealth", "/v1/%00",
        "/v1/health%25", "/%252e%252e/x", "/v1/health\x00", "/v1\\health",
        "/v1/health#frag", "/v1/health#", "/v1/health ", "/v1/ health",
        "/v1/health\n", "/v1/health\r\nHost: x", "/v1/health\t",
        "/v1/héalth", "/v1/health?q=\x00", "/v1/health?q=a b",
        "/v1/health?q=#", "/" + "a" * 5000, 5, b"/v1/health",
    ])
    def test_rejects(self, t):
        assert target_allowed(t) is False


class TestHappyPath:
    @pytest.mark.parametrize("target", ["/v1/check", "/v1/redact", "/v1/restore", "/mcp"])
    def test_post_routes(self, target):
        d = run("POST", target)
        assert d.allowed is True and d.status == 200 and d.code == "ok"
        assert d.route == f"POST {target}"

    def test_get_usage(self):
        d = run("GET", "/v1/usage", get_base())
        assert d.allowed is True and d.route == "GET /v1/usage"

    def test_query_string_ignored_for_routing(self):
        assert run("POST", "/v1/check?x=1").allowed is True

    def test_health_without_token(self):
        d = run("GET", "/v1/health", get_base(drop=("Authorization",)))
        assert d.allowed is True and d.route == "GET /v1/health"

    def test_localhost_host_and_charset(self):
        h = base(drop=("Host", "Content-Type"))
        h += [("host", f"LOCALHOST:{PORT}"),
              ("content-type", "Application/JSON; charset=UTF-8")]
        assert run("POST", "/v1/check", h).allowed is True

    def test_zero_length_post_passes_guard(self):
        assert run(headers=base(cl="0")).allowed is True

    def test_exactly_cap_ok(self):
        assert run(headers=base(cl=str(BODY_CAP))).allowed is True


class TestToken:
    @pytest.mark.parametrize("auth", [
        None, "", "Bearer", "Bearer wrong", f"Bearer {TOKEN}x", f"Bearer {TOKEN} ",
        f"Basic {TOKEN}", TOKEN, f"Token {TOKEN}",
    ])
    def test_bad_token_401(self, auth):
        h = base(drop=("Authorization",))
        if auth is not None:
            h.append(("Authorization", auth))
        denied(run(headers=h), 401, "invalid_api_key")

    def test_missing_401_for_every_protected_route(self):
        for m, t in [("POST", "/v1/check"), ("POST", "/v1/redact"),
                     ("POST", "/v1/restore"), ("GET", "/v1/usage"),
                     ("POST", "/mcp"), ("GET", "/mcp")]:
            h = (get_base if m == "GET" else base)(drop=("Authorization",))
            denied(run(m, t, h), 401, "invalid_api_key")

    def test_duplicate_authorization_401(self):
        h = base() + [("Authorization", "Bearer other")]
        denied(run(headers=h), 401, "invalid_api_key")
        h = base(drop=("Authorization",)) + [
            ("Authorization", "Bearer other"), ("Authorization", f"Bearer {TOKEN}")]
        denied(run(headers=h), 401, "invalid_api_key")

    def test_empty_server_token_denies_everything_but_health(self):
        denied(run(token=""), 401, "invalid_api_key")
        denied(run(token=None), 401, "invalid_api_key")
        assert run("GET", "/v1/health", get_base(), token="").allowed is True

    def test_unknown_route_without_token_is_401_not_404(self):
        denied(run("POST", "/v1/nope", base(drop=("Authorization",))), 401, "invalid_api_key")
        denied(run("GET", "/v1/redact", get_base(drop=("Authorization",))), 401,
               "invalid_api_key")

    def test_only_health_is_exempt(self):
        g = get_base(drop=("Authorization",))
        assert run("GET", "/v1/health", g).allowed is True
        p = base(drop=("Authorization",))
        denied(run("POST", "/v1/health", p), 401, "invalid_api_key")
        denied(run("GET", "/v1/health/", g), 401, "invalid_api_key")
        denied(run("GET", "/v1/Health", g), 401, "invalid_api_key")
        denied(run("GET", "/v1/health/x", g), 401, "invalid_api_key")

    def test_token_not_in_decision(self):
        h = base(drop=("Authorization",)) + [("Authorization", "Bearer SECRETSENTINEL")]
        d = run(headers=h)
        assert "SECRETSENTINEL" not in repr(d) and TOKEN not in repr(d)


class TestRouting:
    def test_unknown_route_with_token_404(self):
        denied(run("POST", "/v1/nope"), 404, "not_found")
        denied(run("GET", "/", get_base()), 404, "not_found")
        denied(run("POST", "/v1/redact/"), 404, "not_found")

    @pytest.mark.parametrize("m,t", [
        ("GET", "/v1/check"), ("GET", "/v1/redact"), ("GET", "/v1/restore"),
        ("POST", "/v1/usage"), ("GET", "/mcp"), ("POST", "/v1/health"),
    ])
    def test_wrong_method_405_with_token(self, m, t):
        h = get_base() if m == "GET" else base()
        denied(run(m, t, h), 405, "method_not_allowed")


class TestMethods:
    @pytest.mark.parametrize("m", [
        "OPTIONS", "PUT", "DELETE", "PATCH", "HEAD", "TRACE", "CONNECT", "get",
        "Post", "", None, "GET ", "GET\x00", "FOO", 5, b"GET",
    ])
    def test_405(self, m):
        denied(run(m, "/v1/health", base()), 405, "method_not_allowed")

    def test_options_preflight_never_allowed_even_with_cors_headers(self):
        h = [("Host", HOST_OK), ("Origin", "https://evil.example"),
             ("Access-Control-Request-Method", "POST")]
        denied(run("OPTIONS", "/v1/redact", h), 405, "method_not_allowed")

    def test_method_checked_before_auth(self):
        denied(run("OPTIONS", "/v1/redact", base(drop=("Authorization",))),
               405, "method_not_allowed")


class TestTarget:
    @pytest.mark.parametrize("t", [
        "http://127.0.0.1:8123/v1/health", "//evil.com/v1/health", "/../x",
        "/%2e%2e/x", "/v1\\health", "/v1/health\x00", "/v1/health#f", "x",
    ])
    def test_bad_target_400(self, t):
        denied(run("GET", t, get_base()), 400, "bad_request")

    def test_bad_target_before_token(self):
        denied(run("GET", "/../x", get_base(drop=("Authorization",))), 400, "bad_request")


class TestHost:
    @pytest.mark.parametrize("host", [
        "evil.example", f"evil.example:{PORT}", f"127.0.0.1.evil.com:{PORT}",
        f"127.0.0.1.:{PORT}", f"localhost.:{PORT}", f"[::1]:{PORT}",
        "127.0.0.1", f"127.0.0.1:{PORT + 1}", f"user@127.0.0.1:{PORT}", "",
        f"127.0.0.1:{PORT} ", f"lоcalhost:{PORT}",
    ])
    def test_bad_host_421(self, host):
        h = base(drop=("Host",)) + [("Host", host)]
        denied(run(headers=h), 421, "bad_host")

    def test_missing_host_421(self):
        denied(run(headers=base(drop=("Host",))), 421, "bad_host")

    def test_duplicate_host_400(self):
        h = base() + [("Host", HOST_OK)]
        denied(run(headers=h), 400, "bad_request")
        h = base() + [("hOsT", "evil.example")]
        denied(run(headers=h), 400, "bad_request")

    def test_bad_host_even_for_health(self):
        h = [("Host", f"evil.example:{PORT}")]
        denied(run("GET", "/v1/health", h), 421, "bad_host")

    def test_bad_host_before_token(self):
        h = base(drop=("Host", "Authorization")) + [("Host", "evil.example")]
        denied(run(headers=h), 421, "bad_host")

    def test_expected_ports_multiple(self):
        h = base(drop=("Host",)) + [("Host", "localhost:9")]
        assert run(headers=h, ports=(8, 9)).allowed is True


class TestOrigin:
    @pytest.mark.parametrize("name", ["Origin", "origin", "ORIGIN", "oRiGiN"])
    @pytest.mark.parametrize("value", [
        "https://evil.example", "null", "", "http://127.0.0.1:8123",
        f"http://localhost:{PORT}", "x",
    ])
    def test_any_origin_403(self, name, value):
        denied(run(headers=base() + [(name, value)]), 403, "forbidden_origin")

    def test_origin_on_health_403(self):
        h = [("Host", HOST_OK), ("Origin", "null")]
        denied(run("GET", "/v1/health", h), 403, "forbidden_origin")

    def test_origin_without_token_is_403_not_401(self):
        h = base(drop=("Authorization",)) + [("Origin", "https://evil.example")]
        denied(run(headers=h), 403, "forbidden_origin")

    def test_origin_value_not_echoed(self):
        d = run(headers=base() + [("Origin", "https://evil-sentinel.example")])
        assert "sentinel" not in repr(d)


class TestFetchMetadata:
    @pytest.mark.parametrize("v", [
        "cross-site", "same-site", "same-origin", "", "bogus", "Cross-Site",
    ])
    def test_site_403(self, v):
        denied(run(headers=base() + [("Sec-Fetch-Site", v)]), 403, "forbidden_fetch_site")

    @pytest.mark.parametrize("v", ["none", "None", "NONE", " none "])
    def test_site_none_ok(self, v):
        assert run(headers=base() + [("Sec-Fetch-Site", v)]).allowed is True

    def test_duplicate_site_with_one_bad(self):
        h = base() + [("Sec-Fetch-Site", "none"), ("sec-fetch-site", "cross-site")]
        denied(run(headers=h), 403, "forbidden_fetch_site")

    @pytest.mark.parametrize("v", ["no-cors", "No-Cors", "navigate", "same-origin", "websocket"])
    def test_mode_without_site_403_unless_cors(self, v):
        denied(run(headers=base() + [("Sec-Fetch-Mode", v)]), 403, "forbidden_fetch_site")

    @pytest.mark.parametrize("v", ["cors", "CORS", " cors\t"])
    def test_mode_cors_without_site_is_a_non_browser_client(self, v):
        assert run(headers=base() + [("Sec-Fetch-Mode", v)]).allowed is True

    def test_fetch_checks_apply_to_health(self):
        h = [("Host", HOST_OK), ("Sec-Fetch-Site", "cross-site")]
        denied(run("GET", "/v1/health", h), 403, "forbidden_fetch_site")
        h = [("Host", HOST_OK), ("Sec-Fetch-Mode", "no-cors")]
        denied(run("GET", "/v1/health", h), 403, "forbidden_fetch_site")


class TestFraming:
    @pytest.mark.parametrize("v", ["chunked", "gzip", "", "identity"])
    def test_transfer_encoding_501(self, v):
        denied(run(headers=base() + [("Transfer-Encoding", v)]), 501, "not_implemented")
        denied(run(headers=base() + [("transfer-encoding", v)]), 501, "not_implemented")

    def test_te_on_health(self):
        h = [("Host", HOST_OK), ("Transfer-Encoding", "chunked")]
        denied(run("GET", "/v1/health", h), 501, "not_implemented")

    def test_duplicate_content_length_400(self):
        denied(run(headers=base() + [("Content-Length", "12")]), 400, "bad_request")
        denied(run(headers=base() + [("content-length", "13")]), 400, "bad_request")

    @pytest.mark.parametrize("hdr", [
        (" Host", "x"), ("\tX-A", "y"), (" ", "folded continuation"),
        ("", "empty"), ("Bad Name", "v"), ("Bad:Name", "v"), ("X\x00", "v"),
        ("X-A\r\nX-B", "v"), ("X-é", "v"),
    ])
    def test_malformed_or_folded_name_400(self, hdr):
        denied(run(headers=base() + [hdr]), 400, "bad_request")

    @pytest.mark.parametrize("val", [
        "a\r\nX-Evil: 1", "a\nb", "a\rb", "a\x00b", "a\x01b", "a\x7fb",
        "x" * 9000,
    ])
    def test_bad_header_value_400(self, val):
        denied(run(headers=base() + [("X-A", val)]), 400, "bad_request")

    def test_tab_in_value_ok(self):
        assert run(headers=base() + [("X-A", "a\tb")]).allowed is True

    def test_too_many_headers_400(self):
        h = base() + [(f"X-{i}", "v") for i in range(200)]
        denied(run(headers=h), 400, "bad_request")

    @pytest.mark.parametrize("h", [
        None, "x", 5, [("Host",)], [("Host", 5)], [5], [(b"Host", b"x")],
        [["Host", "a", "b"]],
    ])
    def test_garbage_headers_fail_closed(self, h):
        d = check_request("GET", "/v1/health", h, expected_ports=PORTS, token=TOKEN)
        denied(d, 400, "bad_request")

    def test_structure_checked_before_host(self):
        h = base(drop=("Host",)) + [("Host", "evil.example"), ("Host", "x")]
        denied(run(headers=h), 400, "bad_request")


class TestBody:
    @pytest.mark.parametrize("cl", [
        "+5", "5 ", " 5", "0x10", "-1", "1e3", "5.0", "", "abc", "٥",
        "５", "5\n", "5,5", "99999999999999999999999999",
    ])
    def test_bad_content_length_400(self, cl):
        denied(run(headers=base(cl=cl)), 400, "bad_request")

    def test_missing_content_length_post_411(self):
        denied(run(headers=base(drop=("Content-Length",))), 411, "length_required")

    def test_over_cap_413(self):
        denied(run(headers=base(cl=str(BODY_CAP + 1))), 413, "payload_too_large")
        denied(run(headers=base(cl="9999999999")), 413, "payload_too_large")

    def test_leading_zeros_ok(self):
        assert run(headers=base(cl="0012")).allowed is True

    @pytest.mark.parametrize("ct", [
        "text/plain", "application/x-www-form-urlencoded", "multipart/form-data",
        "application/json5", "application/jsonx", "application/json; charset=latin-1",
        "application/json; charset=utf-8; x=y", "application/json;boundary=1",
        "application/json, text/plain", "text/plain; application/json", "",
        " application/json", "application/json ;",
        "application/json; charset=utf-8x", "application/ json",
        "application/json;charset=\"utf-8\"",
    ])
    def test_bad_content_type_415(self, ct):
        h = base(drop=("Content-Type",)) + [("Content-Type", ct)]
        denied(run(headers=h), 415, "unsupported_media_type")

    def test_missing_content_type_415(self):
        denied(run(headers=base(drop=("Content-Type",))), 415, "unsupported_media_type")

    def test_duplicate_content_type_400(self):
        denied(run(headers=base() + [("Content-Type", "application/json")]),
               400, "bad_request")

    @pytest.mark.parametrize("ct", [
        "application/json", "application/json; charset=utf-8",
        "application/json;charset=utf-8", "APPLICATION/JSON; CHARSET=UTF-8",
        "application/json ; charset=utf-8",
    ])
    def test_good_content_types(self, ct):
        h = base(drop=("Content-Type",)) + [("Content-Type", ct)]
        assert run(headers=h).allowed is True

    @pytest.mark.parametrize("cl", ["5", "1"])
    def test_get_with_body_400(self, cl):
        h = get_base() + [("Content-Length", cl)]
        denied(run("GET", "/v1/usage", h), 400, "bad_request")

    def test_get_with_zero_cl_ok(self):
        h = get_base() + [("Content-Length", "0")]
        assert run("GET", "/v1/usage", h).allowed is True

    def test_health_get_with_body_400(self):
        h = [("Host", HOST_OK), ("Content-Length", "3")]
        denied(run("GET", "/v1/health", h), 400, "bad_request")


class TestTextLength:
    def test_ok(self):
        assert check_text_length(0).allowed is True
        assert check_text_length(TEXT_CAP).allowed is True

    def test_over(self):
        denied(check_text_length(TEXT_CAP + 1), 413, "payload_too_large")

    @pytest.mark.parametrize("n", [-1, None, "5", 1.5, True])
    def test_garbage_denied(self, n):
        assert check_text_length(n).allowed is False


class TestDecisionOrder:
    """Cheap rejects first; the token check comes before any body check."""

    def test_order_is_stable(self):
        auth = ("Authorization", f"Bearer {TOKEN}")
        host = ("Host", HOST_OK)
        fold = (" bad", "v")
        evil = ("Host", "evil.example")
        cases = [
            ("OPTIONS", "/../x", [fold, evil, ("Origin", "x")], 405, "method_not_allowed"),
            ("POST", "/../x", [fold, evil], 400, "bad_request"),
            ("POST", "/v1/redact", [fold, evil, ("Origin", "x")], 400, "bad_request"),
            ("POST", "/v1/redact", [evil, ("Origin", "x"), ("Transfer-Encoding", "chunked")],
             501, "not_implemented"),
            ("POST", "/v1/redact", [evil, ("Origin", "x")], 421, "bad_host"),
            ("POST", "/v1/redact", [host, ("Origin", "x"), ("Sec-Fetch-Site", "cross-site")],
             403, "forbidden_origin"),
            ("POST", "/v1/redact", [host, ("Sec-Fetch-Site", "cross-site")],
             403, "forbidden_fetch_site"),
            ("POST", "/v1/redact",
             [host, ("Content-Type", "text/plain"), ("Content-Length", "999999999")],
             401, "invalid_api_key"),
            ("POST", "/v1/nope", [host, auth], 404, "not_found"),
            ("GET", "/v1/redact", [host, auth], 405, "method_not_allowed"),
            ("POST", "/v1/redact",
             [host, auth, ("Content-Type", "text/plain"), ("Content-Length", "999999999")],
             413, "payload_too_large"),
            ("POST", "/v1/redact",
             [host, auth, ("Content-Type", "text/plain"), ("Content-Length", "5")],
             415, "unsupported_media_type"),
        ]
        for m, t, h, status, code in cases:
            denied(run(m, t, h), status, code)

    def test_body_problems_hidden_from_unauthenticated(self):
        for extra in ([("Content-Length", "99999999")], [("Content-Length", "x")],
                      [("Content-Type", "text/plain"), ("Content-Length", "1")], []):
            h = [("Host", HOST_OK)] + extra
            denied(run("POST", "/v1/redact", h), 401, "invalid_api_key")

    def test_decision_has_no_message_field(self):
        d = run(headers=base(drop=("Authorization",)))
        assert set(vars(d)) == {"allowed", "status", "code", "route"}


NAMES = ["Host", "host", "HOST", "Origin", "origin", "Authorization", "authorization",
         "Content-Type", "Content-Length", "content-length", "Transfer-Encoding",
         "Sec-Fetch-Site", "Sec-Fetch-Mode", "X-Other", " Folded", "Accept", "", "Bad Name"]
HOSTS = [HOST_OK, f"localhost:{PORT}", "evil.example", "127.0.0.1",
         f"[::1]:{PORT}", f"127.0.0.1.:{PORT}", "", "\x00", f"LOCALHOST:{PORT}",
         "x" * 300]
AUTHS = [f"Bearer {TOKEN}", f"bearer {TOKEN}", "Bearer wrong", "Bearer ", "", "Basic x",
         TOKEN, f"Bearer {TOKEN} ", "\x00", f"Bearer {TOKEN}\n"]
CTS = ["application/json", "application/json; charset=utf-8", "text/plain", "",
       "application/json5", "APPLICATION/JSON"]
CLS = ["0", "12", "5", "-1", "+5", "x", "", str(BODY_CAP), str(BODY_CAP + 1),
       "9" * 40, "٥"]
SITES = ["none", "cross-site", "same-origin", "", "same-site"]
MODES = ["navigate", "cors", "no-cors", "same-origin", ""]
TES = ["chunked", "", "gzip"]
ORIGINS = ["null", "https://evil.example", "", "http://127.0.0.1:8123"]
METHODS = ["GET", "POST", "OPTIONS", "PUT", "get", "", "HEAD"]
TARGETS = ["/v1/health", "/v1/check", "/v1/redact", "/v1/restore", "/v1/usage",
           "/mcp", "/", "/v1/nope", "/../x", "http://127.0.0.1:8123/v1/health",
           "//x/y", "/v1/health?x=1", "/v1/health\x00", "/%2e%2e/x", "/V1/health"]


def _value_for(rng, name):
    n = name.lower()
    pools = {
        "host": HOSTS, "authorization": AUTHS, "content-type": CTS,
        "content-length": CLS, "sec-fetch-site": SITES, "sec-fetch-mode": MODES,
        "transfer-encoding": TES, "origin": ORIGINS,
    }
    return rng.choice(pools.get(n, ["v", "", "a\tb", "x\ny", "\x00", "z" * 50]))


def _pick(rng, pool, good):
    return rng.choice(pool[:good] if rng.random() < 0.7 else pool)


def _random_case(rng):
    method = rng.choice(METHODS)
    target = rng.choice(TARGETS)
    headers = []
    valid_start = rng.random() < 0.4
    if valid_start:
        headers = get_base() if method == "GET" else base()
    else:
        if rng.random() < 0.9:
            headers.append(("Host", _pick(rng, HOSTS, 2)))
        if rng.random() < 0.8:
            headers.append(("Authorization", _pick(rng, AUTHS, 1)))
        if rng.random() < 0.6:
            headers.append(("Content-Type", _pick(rng, CTS, 2)))
        if rng.random() < 0.6:
            headers.append(("Content-Length", _pick(rng, CLS, 2)))
    for _ in range(0 if valid_start and rng.random() < 0.6 else rng.randint(0, 4)):
        name = rng.choice(NAMES)
        if rng.random() < 0.5 and name.lower() in ("origin", "transfer-encoding"):
            continue
        headers.append((name, _value_for(rng, name)))
    rng.shuffle(headers)
    return method, target, headers


def _authorized(headers):
    auth = [v for n, v in headers if n.lower() == "authorization"]
    return len(auth) == 1 and auth[0].lower() in (f"bearer {TOKEN}".lower(),) \
        and auth[0][7:] == TOKEN


KNOWN_STATUS = {200, 400, 401, 403, 404, 405, 411, 413, 415, 421, 501}


class TestFuzz:
    N = 4000

    def test_invariants(self):
        rng = random.Random(20261015)
        allowed_count = 0
        health_allowed = 0
        origin_cases = 0
        for _ in range(self.N):
            method, target, headers = _random_case(rng)
            d = check_request(method, target, headers, expected_ports=PORTS, token=TOKEN)
            assert isinstance(d, Decision)
            assert d.status in KNOWN_STATUS, (method, target, headers, d)
            assert (d.status == 200) == d.allowed
            if any(n.lower() == "origin" for n, _ in headers):
                origin_cases += 1
                assert not d.allowed, (method, target, headers)
            if d.allowed:
                allowed_count += 1
                is_health = (method, target.split("?", 1)[0]) == ("GET", "/v1/health")
                if is_health:
                    health_allowed += 1
                else:
                    assert _authorized(headers), (method, target, headers)
                hosts = [v for n, v in headers if n.lower() == "host"]
                assert len(hosts) == 1 and host_allowed(hosts[0], PORTS)
                assert method in ("GET", "POST")
                assert target_allowed(target)
                assert not any(n.lower() in ("transfer-encoding", "origin")
                               for n, _ in headers)
                assert not any(n.lower() == "sec-fetch-site" and v.strip().lower() != "none"
                               for n, v in headers)
        assert allowed_count >= 50, allowed_count
        assert health_allowed >= 5, health_allowed
        assert origin_cases >= 200, origin_cases

    def test_never_raises_on_hostile_types(self):
        rng = random.Random(7)
        atoms = [None, 0, -1, 1.5, True, b"x", "", "GET", "/v1/health", ("Host", "x"),
                 [("Host", HOST_OK)], [], "\ud800", object(), {"a": 1}]
        for _ in range(2000):
            args = [rng.choice(atoms) for _ in range(3)]
            ports = rng.choice([PORTS, None, (), "8123", 8123, [object()]])
            token = rng.choice([TOKEN, None, "", b"x", 5, "\ud800"])
            d = check_request(*args, expected_ports=ports, token=token)
            assert isinstance(d, Decision)

    def test_helpers_never_raise(self):
        rng = random.Random(11)
        atoms = [None, 0, 1.5, b"\xff", "", "\ud800", "\x00", "é" * 10, "a" * 100_000,
                 "Bearer x", [], object(), True]
        for _ in range(1000):
            a, b = rng.choice(atoms), rng.choice(atoms)
            assert compare_token(a, b) in (True, False)
            assert parse_bearer(a) is None or isinstance(parse_bearer(a), str)
            assert host_allowed(a, b) in (True, False)
            assert target_allowed(a) in (True, False)
