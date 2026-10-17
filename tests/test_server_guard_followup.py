"""Follow-up hardening pins for guard.py (post-merge red team of #20).

Covers: ASCII-only header normalisation, single-use iterators as
expected_ports, five surviving mutants, and a seeded differential fuzz against
an independent oracle written from the spec.  Fake data only; no I/O.
"""

import itertools
import random

import pytest

from pii_buddy.server.guard import check_request, host_allowed

TOKEN = "fake-token_AbCdEf0123456789-ZyXwVu_9876543210"
PORT = 8123
HOST_OK = f"127.0.0.1:{PORT}"
PADS = ["\xa0", " ", "\x85", "​"]


def get_health(extra=(), host=HOST_OK, ports=(PORT,)):
    headers = [("Host", host)] + list(extra)
    return check_request("GET", "/v1/health", headers, expected_ports=ports, token=TOKEN)


def post(ctype="application/json", host=HOST_OK, ports=(PORT,), auth=None):
    headers = [
        ("Host", host),
        ("Authorization", auth or f"Bearer {TOKEN}"),
        ("Content-Type", ctype),
        ("Content-Length", "12"),
    ]
    return check_request("POST", "/v1/check", headers, expected_ports=ports, token=TOKEN)


class TestAsciiOnlyFetchMetadata:
    @pytest.mark.parametrize("pad", PADS)
    @pytest.mark.parametrize("fmt", ["{p}none", "none{p}", "{p}none{p}", "{p}NONE"])
    def test_site_with_unicode_padding_is_denied(self, pad, fmt):
        d = get_health([("Sec-Fetch-Site", fmt.format(p=pad))])
        assert (d.allowed, d.status, d.code) == (False, 403, "forbidden_fetch_site")

    @pytest.mark.parametrize("value", [" NONE", "none ", "\tNone\t", "NoNe", "none"])
    def test_site_with_http_whitespace_and_any_ascii_case_is_allowed(self, value):
        assert get_health([("Sec-Fetch-Site", value)]).allowed

    @pytest.mark.parametrize("value", ["same-origin", "cross-site", "same-site", "", "nonee"])
    def test_other_site_values_denied(self, value):
        assert get_health([("Sec-Fetch-Site", value)]).code == "forbidden_fetch_site"

    @pytest.mark.parametrize("value", [" cors", "CORS ", "\tNo-Cors", "no-cors"])
    def test_mode_ascii_trim_and_case(self, value):
        assert get_health([("Sec-Fetch-Mode", value)]).code == "forbidden_fetch_site"

    @pytest.mark.parametrize("pad", PADS)
    def test_mode_is_not_unicode_trimmed(self, pad):
        # Only exactly cors/no-cors (after ASCII trim) is rejected; the padded
        # value is a different, unknown token.
        assert get_health([("Sec-Fetch-Mode", pad + "cors")]).allowed


class TestAsciiOnlyOtherHeaderNormalisation:
    @pytest.mark.parametrize("pad", PADS)
    def test_host_with_unicode_padding_denied(self, pad):
        for h in (pad + HOST_OK, HOST_OK + pad):
            assert get_health(host=h).code == "bad_host"
        assert not host_allowed(pad + HOST_OK, (PORT,))

    @pytest.mark.parametrize("host", ["LOCALHOST:8123", "LocalHost:8123", "127.0.0.1:8123"])
    def test_host_ascii_case_allowed(self, host):
        assert get_health(host=host).allowed

    def test_host_fullwidth_digits_denied(self):
        assert get_health(host="127.0.0.1:８１２３").code == "bad_host"

    @pytest.mark.parametrize("scheme", ["Bearer", "BEARER", "bEaReR"])
    def test_bearer_ascii_case_allowed(self, scheme):
        assert post(auth=f"{scheme} {TOKEN}").allowed

    @pytest.mark.parametrize("pad", PADS)
    def test_bearer_unicode_padding_denied(self, pad):
        for v in (pad + "Bearer " + TOKEN, "Bearer " + TOKEN + pad, "Bearer" + pad + TOKEN):
            assert post(auth=v).code == "invalid_api_key"

    @pytest.mark.parametrize("pad", PADS)
    def test_content_type_unicode_padding_denied(self, pad):
        for ct in (pad + "application/json", "application/json" + pad,
                   "application/json" + pad + "; charset=utf-8",
                   "application/json;" + pad + "charset=utf-8"):
            assert post(ctype=ct).code == "unsupported_media_type"

    def test_content_type_long_s_does_not_fold_to_s(self):
        assert post(ctype="application/json; charſet=utf-8").code == "unsupported_media_type"
        assert post(ctype="APPLICATION/JSON; CHARSET=UTF-8").allowed

    @pytest.mark.parametrize("pad", PADS)
    def test_header_names_with_unicode_are_bad_request(self, pad):
        d = get_health([("Sec-Fetch-Site" + pad, "none")])
        assert (d.status, d.code) == (400, "bad_request")


class TestExpectedPortsIterators:
    def test_generator_ports_fail_closed_deny_all_on_every_call(self):
        ports = (p for p in [PORT])
        for _ in range(3):
            assert get_health(ports=ports).code == "bad_host"

    def test_iterator_objects_fail_closed(self):
        for it in (iter([PORT]), iter((PORT,)), map(int, [PORT]), itertools.repeat(PORT),
                   itertools.cycle([PORT])):
            assert not host_allowed(HOST_OK, it)

    def test_large_generator_cannot_leak_ports_on_later_calls(self):
        ports = (p for p in range(1, 21))
        results = [host_allowed(f"127.0.0.1:{p}", ports) for p in (1, 19, 20, 19, 20)]
        assert results == [False] * 5

    def test_rejecting_an_iterator_does_not_consume_it(self):
        it = iter([PORT, 9])
        host_allowed(HOST_OK, it)
        assert list(it) == [PORT, 9]

    def test_reiterable_containers_work_repeatedly(self):
        for ports in ([PORT], (PORT,), {PORT}, frozenset({PORT}), range(PORT, PORT + 1),
                      {PORT: "x"}, PORT):
            assert [host_allowed(HOST_OK, ports) for _ in range(3)] == [True] * 3

    def test_duplicates_count_once(self):
        assert host_allowed("127.0.0.1:80", [80] * 9)
        assert host_allowed("127.0.0.1:80", [80] * 1000)

    def test_cap_is_on_distinct_ports(self):
        assert host_allowed("127.0.0.1:1", list(range(1, 9)))
        assert not host_allowed("127.0.0.1:1", list(range(1, 10)))
        assert not host_allowed("127.0.0.1:1", list(range(1, 9)) + [1] * 5 + [9])

    def test_reiterable_that_never_ends_is_denied_not_hung(self):
        class Endless:
            def __iter__(self):
                return itertools.repeat(PORT)

        assert not host_allowed(HOST_OK, Endless())


class TestSurvivingMutants:
    # (a) Host regex dot unescaped
    @pytest.mark.parametrize("host", ["127x0x0x1:8123", "127a0b0c1:8123", "1270001:8123",
                                      "127-0-0-1:8123"])
    def test_host_dots_must_be_literal(self, host):
        assert not host_allowed(host, (8123,))

    # (b) Content-Type suffix types
    @pytest.mark.parametrize("ct", ["application/vnd.x+json", "application/ld+json",
                                    "text/json", "application/jsonx", "application/json5",
                                    "xapplication/json", "application/json;charset=utf-16"])
    def test_only_application_json_content_type(self, ct):
        assert post(ctype=ct).code == "unsupported_media_type"

    # (c) bytes / bytearray / str as expected_ports
    @pytest.mark.parametrize("ports", [b"P", bytearray(b"P"), "P", "80", b"\x50\x00",
                                       memoryview(b"P")])
    def test_stringlike_ports_deny_all(self, ports):
        assert not host_allowed("127.0.0.1:80", ports)
        assert not host_allowed("127.0.0.1:1", ports)

    # (d) bool is not a port number
    def test_bool_is_not_a_port(self):
        assert not host_allowed("127.0.0.1:1", [True])
        assert not host_allowed("127.0.0.1:1", True)
        assert not host_allowed("127.0.0.1:1", [True, 1])
        assert not host_allowed("127.0.0.1:0", [False])

    # (e) any invalid entry poisons the whole argument
    @pytest.mark.parametrize("bad", ["x", None, 0, -1, 65536, 1.5, True, b"8", [8080], (1,)])
    def test_one_invalid_entry_denies_everything(self, bad):
        assert not host_allowed("127.0.0.1:8080", [8080, bad])
        assert not host_allowed("127.0.0.1:8080", [bad, 8080])


# ---------------------------------------------------------------------------
# Independent oracle, written from the spec (no regexes, no guard internals).
# ---------------------------------------------------------------------------

_TCHAR = set("!#$%&'*+.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-")
_DIGITS = set("0123456789")
_ROUTES = {
    "/v1/health": {"GET"}, "/v1/usage": {"GET"}, "/v1/check": {"POST"},
    "/v1/redact": {"POST"}, "/v1/restore": {"POST"}, "/mcp": {"POST"},
}


def _alower(s):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def _atrim(s):
    i, j = 0, len(s)
    while i < j and s[i] in " \t":
        i += 1
    while j > i and s[j - 1] in " \t":
        j -= 1
    return s[i:j]


def _o_ports(ports):
    if isinstance(ports, int) and not isinstance(ports, bool):
        ports = [ports]
    if not isinstance(ports, (list, tuple, set, frozenset)):
        return set()
    for p in ports:
        if type(p) is not int or not 1 <= p <= 65535:
            return set()
    return set(ports) if len(set(ports)) <= 8 else set()


def _o_host(v, ports):
    if not isinstance(v, str) or len(v) > 64 or any(ord(c) > 127 for c in v):
        return False
    v = _alower(v)
    for prefix in ("127.0.0.1:", "localhost:"):
        if v.startswith(prefix):
            rest = v[len(prefix):]
            if not 1 <= len(rest) <= 5 or rest[0] == "0" or any(c not in _DIGITS for c in rest):
                return False
            return int(rest) <= 65535 and int(rest) in _o_ports(ports)
    return False


def _o_target(t):
    if not isinstance(t, str) or not 1 <= len(t) <= 2048:
        return False
    if t[0] != "/" or t[:2] == "//":
        return False
    if any(not 33 <= ord(c) <= 126 for c in t) or "\\" in t or "#" in t:
        return False
    path = t.partition("?")[0]
    return "%" not in path and not {".", ".."} & set(path.split("/"))


def _o_ctype(v):
    s = _alower(v)
    if not s.startswith("application/json"):
        return False
    rest = s[len("application/json"):]
    if rest == "":
        return True
    rest = rest.lstrip(" \t")
    if not rest.startswith(";"):
        return False
    return rest[1:].lstrip(" \t") == "charset=utf-8"


def oracle(method, target, headers, ports, token):
    if method not in ("GET", "POST"):
        return (False, 405, "method_not_allowed")
    bad = (False, 400, "bad_request")
    if not _o_target(target):
        return bad
    if not isinstance(headers, (list, tuple)) or len(headers) > 100:
        return bad
    h = {}
    for pair in headers:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            return bad
        n, v = pair
        if not isinstance(n, str) or not isinstance(v, str):
            return bad
        if not n or any(c not in _TCHAR for c in n) or len(v) > 8192:
            return bad
        if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in v):
            return bad
        h.setdefault(_alower(n), []).append(v)
    for k in ("host", "content-length", "content-type"):
        if len(h.get(k, [])) > 1:
            return bad
    if "transfer-encoding" in h:
        return (False, 501, "not_implemented")
    if len(h.get("host", [])) != 1 or not _o_host(h["host"][0], ports):
        return (False, 421, "bad_host")
    if "origin" in h:
        return (False, 403, "forbidden_origin")
    if any(_alower(_atrim(v)) != "none" for v in h.get("sec-fetch-site", [])):
        return (False, 403, "forbidden_fetch_site")
    if any(_alower(_atrim(v)) in ("cors", "no-cors") for v in h.get("sec-fetch-mode", [])):
        return (False, 403, "forbidden_fetch_site")
    if method == "GET" and any(v != "0" for v in h.get("content-length", [])):
        return bad
    path = target.partition("?")[0]
    if method == "GET" and path == "/v1/health":
        return (True, 200, "ok")
    auth = h.get("authorization", [])
    ok_auth = False
    if len(auth) == 1:
        a = auth[0]
        if len(a) > 7 and _alower(a[:6]) == "bearer" and a[6] == " ":
            tok = a[7:]
            ok_auth = (len(tok) <= 512 and all(33 <= ord(c) <= 126 for c in tok)
                       and bool(token) and tok == token)
    if not ok_auth:
        return (False, 401, "invalid_api_key")
    if path not in _ROUTES:
        return (False, 404, "not_found")
    if method not in _ROUTES[path]:
        return (False, 405, "method_not_allowed")
    if method == "POST":
        cl = h.get("content-length")
        if not cl:
            return (False, 411, "length_required")
        if not 1 <= len(cl[0]) <= 10 or any(c not in _DIGITS for c in cl[0]):
            return bad
        if int(cl[0]) > 512 * 1024:
            return (False, 413, "payload_too_large")
        ct = h.get("content-type")
        if not ct or not _o_ctype(ct[0]):
            return (False, 415, "unsupported_media_type")
    return (True, 200, "ok")


_METHODS = ["GET", "POST", "GET", "POST", "PUT", "OPTIONS", "get", "", None]
_TARGETS = ["/v1/health", "/v1/usage", "/v1/check", "/v1/redact", "/v1/restore", "/mcp",
            "/v1/health?x=1", "/v1/nope", "/v1/health/", "//v1/health", "/v1/%68ealth",
            "/v1/../v1/health", "/./mcp", "v1/health", "", "/v1/check#f", "/v1\\check",
            "/v1/check?q=%41", "/ v1", "/v1/chéck", "/" + "a" * 2100]
_HOSTS = [HOST_OK, "localhost:8123", "LOCALHOST:8123", "127.0.0.1:9", "127.0.0.1:08123",
          "127.0.0.1:65536", "127.0.0.1:", "127x0x0x1:8123", "127.0.0.1.evil.com:8123",
          "[::1]:8123", "evil.example", "\xa0127.0.0.1:8123", "127.0.0.1:8123 ",
          "127.0.0.1:８１２３", "localhost:80", "127.0.0.1:7", "",
          "127.0.0.1:123456"]
_SITE = [None, "none", "NONE", " none", "none\t", "\xa0none", "none ", "\x85none",
         "​none", "same-origin", "cross-site", "", "nonee", "None "]
_MODE = [None, "navigate", "cors", " CORS", "no-cors\t", "\xa0cors", "same-origin",
         "​no-cors"]
_CT = ["application/json", "Application/JSON", "application/json; charset=utf-8",
       "application/json;charset=UTF-8", "application/json ;\tcharset=utf-8",
       "application/json; charset=utf-8 ", "application/vnd.x+json", "text/plain",
       "application/json\xa0", "application/json; charſet=utf-8", "", "application/json;",
       "application/json; charset=utf-16", "application/json  ;  charset=utf-8"]
_CL = ["0", "12", "524288", "524289", "", "-1", "1 ", "+5", "99999999999", "٣", "007",
       "1,2", "12\t"]
_NAMES = ["Host", "host", "HOST", "Origin", "Transfer-Encoding", "X-Other", "Bad Name",
          "Naïve", "", "Content_Type"]
_CTRL = ["a\x00b", "a\x7fb", "a\nb", "a\rb", "a\tb", "a\x0bb"]


def _near_valid_request(rng):
    """A request that is valid, then perturbed in at most one place."""
    if rng.random() < 0.5:
        method, target = "GET", rng.choice(["/v1/health", "/v1/usage", "/v1/health?x=1"])
        headers = [("Host", HOST_OK), ("Authorization", f"Bearer {TOKEN}")]
    else:
        method, target = "POST", rng.choice(["/v1/check", "/v1/redact", "/v1/restore", "/mcp"])
        headers = [("Host", HOST_OK), ("Authorization", f"Bearer {TOKEN}"),
                   ("Content-Type", "application/json"), ("Content-Length", "12")]
    ports = (PORT,)
    pick = rng.randrange(9)
    if pick == 1:
        headers.append(("Sec-Fetch-Site", rng.choice(_SITE[1:])))
    elif pick == 2:
        headers.append(("Sec-Fetch-Mode", rng.choice(_MODE[1:])))
    elif pick == 3:
        headers[0] = ("Host", rng.choice(_HOSTS))
    elif pick == 4 and method == "POST":
        headers[2] = ("Content-Type", rng.choice(_CT))
    elif pick == 5 and method == "POST":
        headers[3] = ("Content-Length", rng.choice(_CL))
    elif pick == 6:
        target = rng.choice(_TARGETS)
    elif pick == 7:
        ports = rng.choice([[PORT], {PORT}, PORT, (PORT, 9), [PORT] * 9, (PORT, "x"),
                            [PORT, True], list(range(PORT, PORT + 9))])
    elif pick == 8:
        headers.append((rng.choice(_NAMES), rng.choice(["v", "", "12"])))
    rng.shuffle(headers)
    return method, target, headers, ports, TOKEN


def _rand_request(rng):
    if rng.random() < 0.5:
        return _near_valid_request(rng)
    method = rng.choice(_METHODS)
    target = rng.choice(_TARGETS)
    headers = []
    if rng.random() < 0.95:
        headers.append(("Host", rng.choice(_HOSTS) if rng.random() < 0.4 else HOST_OK))
    if rng.random() < 0.06:
        headers.append(("host", rng.choice(_HOSTS)))
    if rng.random() < 0.85:
        scheme = rng.choice(["Bearer", "bearer", "BEARER", "Basic", "Bearer", "Bearer"])
        tok = TOKEN if rng.random() < 0.85 else rng.choice(
            [TOKEN[:-1], TOKEN + "x", "", " ", "a" * 600, TOKEN.upper(), "t\xa0k"])
        pad = rng.choice(["", "", "", " ", "\xa0", "x"])
        sep = rng.choice([" ", " ", " ", "  ", "", "\t", "\xa0"])
        headers.append(("Authorization", pad + scheme + sep + tok))
    if rng.random() < 0.05:
        headers.append(("Authorization", f"Bearer {TOKEN}"))
    if rng.random() < 0.7:
        headers.append(("Content-Type", rng.choice(_CT)))
    if rng.random() < 0.03:
        headers.append(("Content-Type", "application/json"))
    if rng.random() < 0.75:
        headers.append(("Content-Length", rng.choice(_CL)))
    if rng.random() < 0.03:
        headers.append(("Content-Length", "12"))
    if rng.random() < 0.3:
        v = rng.choice(_SITE)
        if v is not None:
            headers.append((rng.choice(["Sec-Fetch-Site", "sec-fetch-site", "SEC-FETCH-SITE"]), v))
    if rng.random() < 0.2:
        v = rng.choice(_MODE)
        if v is not None:
            headers.append(("Sec-Fetch-Mode", v))
    if rng.random() < 0.06:
        headers.append(("Origin", rng.choice(["http://evil.example", "null", ""])))
    if rng.random() < 0.04:
        headers.append(("Transfer-Encoding", "chunked"))
    for _ in range(rng.choice([0, 0, 0, 1, 2])):
        headers.append((rng.choice(_NAMES), rng.choice(["v", "", "12", HOST_OK, "a" * 9000])))
    if rng.random() < 0.04:
        headers.append(("X-Ctl", rng.choice(_CTRL)))
    if rng.random() < 0.02:
        headers.append(("X-Pair",))
    if rng.random() < 0.02:
        headers.append((b"X", "v"))
    if rng.random() < 0.01:
        headers = headers + [("X-%d" % i, "v") for i in range(101)]
    rng.shuffle(headers)
    if rng.random() < 0.02:
        headers = tuple(headers)
    ports = rng.choice([(PORT,), [PORT], {PORT}, PORT, (PORT, 9), [], (), (PORT, "x"),
                        [PORT, True], [PORT] * 9, list(range(PORT, PORT + 9)), None])
    token = TOKEN if rng.random() < 0.97 else rng.choice(["", None, "other"])
    return method, target, headers, ports, token


def test_differential_fuzz_against_independent_oracle():
    rng = random.Random(0x6B1D5EED)
    mismatches = []
    allowed = 0
    for _ in range(25_000):
        method, target, headers, ports, token = _rand_request(rng)
        got = check_request(method, target, headers, expected_ports=ports, token=token)
        want = oracle(method, target, headers, ports, token)
        allowed += want[0]
        if (got.allowed, got.status, got.code) != want:
            mismatches.append((method, target, headers, ports, token, got, want))
            if len(mismatches) >= 5:
                break
    assert not mismatches, mismatches
    assert allowed > 500
