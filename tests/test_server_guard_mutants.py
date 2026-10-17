"""Tests that pin guard.py behaviour found by mutation review of PR #20.

Each class names the mutant it kills.  No sockets, threads or files; all
tokens and hosts are fake.
"""

import re

import pytest

from pii_buddy.server import guard
from pii_buddy.server.guard import check_request, host_allowed

TOKEN = "fake-token_AbCdEf0123456789-ZyXwVu_9876543210"
PORT = 8123
PORTS = (PORT,)
HOST_OK = f"127.0.0.1:{PORT}"


def post_headers(host=HOST_OK, auth=True, ctype="application/json", extra=()):
    h = [("Host", host)]
    if auth:
        h.append(("Authorization", f"Bearer {TOKEN}"))
    h += [("Content-Type", ctype), ("Content-Length", "12")]
    return h + list(extra)


def get_headers(host=HOST_OK, auth=True, extra=()):
    h = [("Host", host)]
    if auth:
        h.append(("Authorization", f"Bearer {TOKEN}"))
    return h + list(extra)


def run(method="POST", target="/v1/redact", headers=None, ports=PORTS, token=TOKEN):
    if headers is None:
        headers = post_headers()
    return check_request(method, target, headers, expected_ports=ports, token=token)


def denied(d, status, code):
    assert d.allowed is False
    assert (d.status, d.code) == (status, code)


class TestContentTypeIsAsciiOnly:
    # U+212A (Kelvin) folds to 'k', which never occurs in the allowed value, so
    # those cases pass either way; they pin that no fold-in can appear later.
    @pytest.mark.parametrize("ctype", [
        "application/jſon",
        "application/json;charſet=utf-8",
        "application/json; charſet=utf-8",
        "applicatıon/json",
        "applicatİon/json",
        "application/json;charset=utf-8K",
        "application/json;cKarset=utf-8",
        "Kapplication/json",
        "application/json;charset=utf‐ 8",
    ])
    def test_non_ascii_lookalikes_are_415(self, ctype):
        denied(run(headers=post_headers(ctype=ctype)), 415, "unsupported_media_type")

    @pytest.mark.parametrize("ctype", [
        "application/json", "APPLICATION/JSON", "Application/Json;Charset=UTF-8",
        "application/json ; charset=utf-8", "application/json;\tCHARSET=UTF-8",
    ])
    def test_ascii_case_variants_still_allowed(self, ctype):
        assert run(headers=post_headers(ctype=ctype)).allowed is True

    def test_pattern_is_ascii_mode(self):
        assert guard._CONTENT_TYPE.flags & re.ASCII


class TestHostHeaderOnly:
    """Kills: trusting X-Forwarded-Host / Forwarded instead of Host."""

    @pytest.mark.parametrize("name", ["X-Forwarded-Host", "Forwarded", "X-Host",
                                      "X-Original-Host", "X-Forwarded-Server"])
    def test_bad_host_not_rescued_by_forwarded_good_value(self, name):
        value = f"host={HOST_OK}" if name == "Forwarded" else HOST_OK
        h = post_headers(host="evil.example", extra=[(name, value)])
        denied(run(headers=h), 421, "bad_host")

    @pytest.mark.parametrize("name", ["X-Forwarded-Host", "Forwarded"])
    def test_missing_host_not_rescued(self, name):
        value = f"host={HOST_OK}" if name == "Forwarded" else HOST_OK
        h = [x for x in post_headers(extra=[(name, value)]) if x[0] != "Host"]
        denied(run(headers=h), 421, "bad_host")

    @pytest.mark.parametrize("name,value", [
        ("X-Forwarded-Host", "evil.example"),
        ("Forwarded", "host=evil.example;proto=https"),
    ])
    def test_good_host_not_broken_by_forwarded_evil_value(self, name, value):
        assert run(headers=post_headers(extra=[(name, value)])).allowed is True


class TestLocalhostSubdomains:
    """Kills: accepting foo.localhost:PORT."""

    @pytest.mark.parametrize("host", [
        f"foo.localhost:{PORT}", f"a.b.localhost:{PORT}", f"evil-localhost:{PORT}",
        f"xlocalhost:{PORT}", f".localhost:{PORT}", f"localhost.:{PORT}",
        f"foo.127.0.0.1:{PORT}", f"x127.0.0.1:{PORT}",
    ])
    def test_rejected(self, host):
        assert host_allowed(host, PORTS) is False
        denied(run(headers=post_headers(host=host)), 421, "bad_host")

    def test_exact_names_still_accepted(self):
        assert host_allowed(f"localhost:{PORT}", PORTS) is True
        assert host_allowed(f"LOCALHOST:{PORT}", PORTS) is True


class TestTokenOnlyInAuthorizationHeader:
    """Kills: a ?token= query value or a cookie authenticating."""

    @pytest.mark.parametrize("target", [
        f"/v1/usage?token={TOKEN}", f"/v1/usage?api_key={TOKEN}",
        f"/v1/usage?access_token={TOKEN}", f"/v1/usage?authorization=Bearer%20{TOKEN}",
        f"/v1/usage?a=1&token={TOKEN}",
    ])
    def test_query_token_is_401(self, target):
        denied(run("GET", target, get_headers(auth=False)), 401, "invalid_api_key")

    @pytest.mark.parametrize("cookie", [
        f"token={TOKEN}", f"Authorization=Bearer {TOKEN}", f"api_key={TOKEN}",
        f"session={TOKEN}; token={TOKEN}",
    ])
    def test_cookie_token_is_401(self, cookie):
        h = get_headers(auth=False, extra=[("Cookie", cookie)])
        denied(run("GET", "/v1/usage", h), 401, "invalid_api_key")

    @pytest.mark.parametrize("name", ["X-Api-Key", "X-Auth-Token", "Proxy-Authorization",
                                      "X-Forwarded-Authorization"])
    def test_other_headers_are_not_credentials(self, name):
        h = get_headers(auth=False, extra=[(name, f"Bearer {TOKEN}"), (name, TOKEN)])
        denied(run("GET", "/v1/usage", h), 401, "invalid_api_key")

    def test_wrong_bearer_not_rescued_by_query_or_cookie(self):
        h = get_headers(auth=False, extra=[("Authorization", "Bearer wrong"),
                                           ("Cookie", f"token={TOKEN}")])
        denied(run("GET", f"/v1/usage?token={TOKEN}", h), 401, "invalid_api_key")

    def test_query_does_not_change_route(self):
        assert run("GET", "/v1/usage?x=1", get_headers()).allowed is True


class _HostileStr(str):
    def lower(self):
        raise RuntimeError("boom")

    def split(self, *a, **k):
        raise RuntimeError("boom")

    def startswith(self, *a, **k):
        raise RuntimeError("boom")

    def __iter__(self):
        raise RuntimeError("boom")

    def __getitem__(self, i):
        raise RuntimeError("boom")

    def encode(self, *a, **k):
        raise RuntimeError("boom")

    def isascii(self):
        raise RuntimeError("boom")


class _HostileSeq:
    def __iter__(self):
        raise RuntimeError("boom")

    def __len__(self):
        raise RuntimeError("boom")


def _boom(*a, **k):
    raise RuntimeError("injected")


class TestFailClosed:
    """Kills: the except branch of check_request returning allow."""

    @pytest.mark.parametrize("helper,method,target,mk", [
        (h, m, t, mk)
        for h in ("host_allowed", "target_allowed", "_clean_headers",
                  "_fetch_metadata_bad")
        for m, t, mk in (("POST", "/v1/redact", post_headers),
                         ("GET", "/v1/usage", get_headers),
                         ("GET", "/v1/health", get_headers))
    ] + [
        (h, m, t, mk)
        for h in ("compare_token", "parse_bearer")
        for m, t, mk in (("POST", "/v1/redact", post_headers),
                         ("GET", "/v1/usage", get_headers))
    ] + [("_check_body_headers", "POST", "/v1/redact", post_headers)])
    def test_internal_exception_is_a_deny_not_a_raise(
            self, monkeypatch, helper, method, target, mk):
        monkeypatch.setattr(guard, helper, _boom)
        d = run(method, target, mk())
        assert isinstance(d, guard.Decision)
        assert d.allowed is False
        assert d.status >= 400 and d.code

    def test_control_without_injection_is_allowed(self):
        assert run().allowed is True

    def test_evaluator_exception_is_a_deny(self, monkeypatch):
        monkeypatch.setattr(guard, "_evaluate", _boom)
        denied(run(), 400, "bad_request")

    def test_deny_decision_carries_no_route(self, monkeypatch):
        monkeypatch.setattr(guard, "host_allowed", _boom)
        d = run()
        assert (d.allowed, d.route) == (False, "")

    @pytest.mark.parametrize("make", [
        lambda: [(_HostileStr("Host"), HOST_OK)],
        lambda: [("Host", _HostileStr(HOST_OK))],
        lambda: [("Host", HOST_OK), ("Authorization", _HostileStr(f"Bearer {TOKEN}"))],
        lambda: [("Host", HOST_OK), ("Authorization", f"Bearer {TOKEN}"),
                 ("Content-Type", _HostileStr("application/json")),
                 ("Content-Length", "1")],
        lambda: _HostileSeq(),
        lambda: [_HostileSeq()],
        lambda: [("Host", HOST_OK, "extra")],
        lambda: [object()],
        lambda: {"Host": HOST_OK},
        lambda: None,
        lambda: [(None, None)],
        lambda: [("Host", b"127.0.0.1:8123")],
    ], ids=range(12))
    @pytest.mark.parametrize("method,target", [("POST", "/v1/redact"), ("GET", "/v1/usage")])
    def test_hostile_typed_headers_deny(self, make, method, target):
        d = check_request(method, target, make(), expected_ports=PORTS, token=TOKEN)
        assert d.allowed is False

    @pytest.mark.parametrize("make", [lambda: _HostileStr("/v1/health"), _HostileSeq,
                                      lambda: 5, lambda: b"/v1/health"], ids=range(4))
    def test_hostile_target_denies(self, make):
        assert run("GET", make(), get_headers()).allowed is False

    @pytest.mark.parametrize("make", [lambda: _HostileStr(TOKEN), _HostileSeq, object],
                             ids=range(3))
    def test_hostile_token_denies(self, make):
        assert run("GET", "/v1/usage", get_headers(), token=make()).allowed is False

    @pytest.mark.parametrize("make", [_HostileSeq, object, lambda: [_HostileStr("1")]],
                             ids=range(3))
    def test_hostile_ports_deny(self, make):
        assert run(ports=make()).allowed is False


class TestMethodPrecedence:
    """Decision: the method check precedes auth for methods outside GET/POST,
    so unauthenticated HEAD / lowercase get / OPTIONS are 405, never 401.
    GET/POST on an unknown route or the wrong method are authenticated first.
    """

    @pytest.mark.parametrize("m", ["HEAD", "get", "post", "OPTIONS", "PUT", "DELETE"])
    def test_unauthenticated_unknown_method_is_405_before_auth(self, m):
        denied(run(m, "/v1/health", get_headers(auth=False)), 405, "method_not_allowed")
        denied(run(m, "/v1/usage", get_headers(auth=False)), 405, "method_not_allowed")

    def test_unauthenticated_known_method_is_401_not_405(self):
        denied(run("POST", "/v1/usage", post_headers(auth=False)), 401, "invalid_api_key")
        denied(run("GET", "/v1/redact", get_headers(auth=False)), 401, "invalid_api_key")


class TestExpectedPortsBound:
    def test_eight_ports_accepted(self):
        ports = tuple(range(9000, 9008))
        assert host_allowed("127.0.0.1:9007", ports) is True
        assert run(headers=post_headers(host="127.0.0.1:9007"), ports=ports).allowed is True

    @pytest.mark.parametrize("make", [tuple, frozenset, list, set])
    def test_nine_ports_deny_everything(self, make):
        ports = make(range(9000, 9009))
        assert host_allowed("127.0.0.1:9000", ports) is False
        denied(run(headers=post_headers(host="127.0.0.1:9000"), ports=ports),
               421, "bad_host")

    def test_huge_iterable_is_not_expanded(self):
        pulled = []

        def gen():
            for i in range(1, 10_000_000):
                pulled.append(i)
                yield 8000 + (i % 1000)

        assert host_allowed("127.0.0.1:8001", gen()) is False
        assert len(pulled) <= 16

    def test_frozenset_and_tuple_of_ints_ok(self):
        assert host_allowed(HOST_OK, frozenset({PORT})) is True
        assert host_allowed(HOST_OK, (PORT,)) is True
