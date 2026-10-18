"""Sec-Fetch-* allow-list and boundary pins for guard.py (red team of #22).

Fake data only; no I/O.
"""

import enum

import pytest

from pii_buddy.server.guard import check_request, host_allowed

TOKEN = "fake-token_AbCdEf0123456789-ZyXwVu_9876543210"
PORT = 8123
HOST_OK = f"127.0.0.1:{PORT}"
PADS = ["\xa0", "\x85", "​", "　", " "]
FETCH = ["Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User"]


def mcp(extra=(), token=TOKEN, ports=(PORT,)):
    headers = [
        ("Host", HOST_OK),
        ("Authorization", f"Bearer {token}"),
        ("Content-Type", "application/json"),
        ("Content-Length", "12"),
    ] + list(extra)
    return check_request("POST", "/mcp", headers, expected_ports=ports, token=token)


def health(extra=()):
    return check_request("GET", "/v1/health", [("Host", HOST_OK)] + list(extra),
                         expected_ports=(PORT,), token=TOKEN)


def verdict(d):
    return (d.allowed, d.status, d.code)


DENY = (False, 403, "forbidden_fetch_site")
OK = (True, 200, "ok")


class TestClientsWeAdmit:
    def test_curl_style_no_fetch_headers(self):
        assert verdict(mcp()) == OK

    def test_node_fetch_style_mode_cors_only(self):
        assert verdict(mcp([("sec-fetch-mode", "cors")])) == OK

    def test_address_bar_navigation_to_health(self):
        h = [("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate"),
             ("Sec-Fetch-Dest", "document"), ("Sec-Fetch-User", "?1")]
        assert verdict(health(h)) == OK

    def test_navigation_still_needs_auth_elsewhere(self):
        h = [("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate"),
             ("Sec-Fetch-Dest", "document"), ("Sec-Fetch-User", "?1")]
        d = check_request("GET", "/v1/usage", [("Host", HOST_OK)] + h,
                          expected_ports=(PORT,), token=TOKEN)
        assert (d.status, d.code) == (401, "invalid_api_key")

    @pytest.mark.parametrize("subset", [
        [], ["Sec-Fetch-Site"], ["Sec-Fetch-Mode"], ["Sec-Fetch-Dest"], ["Sec-Fetch-User"],
        ["Sec-Fetch-Mode", "Sec-Fetch-User"], ["Sec-Fetch-Site", "Sec-Fetch-Dest"],
    ])
    def test_site_none_with_any_subset_of_navigation_headers(self, subset):
        vals = {"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}
        pairs = [("Sec-Fetch-Site", "none")] + [(k, vals[k]) for k in subset if k != FETCH[0]]
        assert verdict(health(pairs)) == OK

    @pytest.mark.parametrize("v", [" NONE ", "\tNone", "none\t"])
    def test_ascii_trim_and_case_on_every_header(self, v):
        h = [("Sec-Fetch-Site", v), ("Sec-Fetch-Mode", " NAVIGATE\t"),
             ("Sec-Fetch-Dest", "\tDocument "), ("Sec-Fetch-User", " ?1\t")]
        assert verdict(health(h)) == OK
        assert verdict(mcp([("SEC-FETCH-MODE", " CORS ")])) == OK


class TestBrowsersAreDenied:
    def test_cross_site_browser_request(self):
        h = [("Origin", "https://evil.example"), ("Sec-Fetch-Site", "cross-site"),
             ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty")]
        assert verdict(mcp(h)) == (False, 403, "forbidden_origin")

    def test_cross_site_without_origin(self):
        h = [("Sec-Fetch-Site", "cross-site"), ("Sec-Fetch-Mode", "cors")]
        assert verdict(mcp(h)) == DENY

    def test_same_origin_browser_request(self):
        h = [("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"),
             ("Sec-Fetch-Dest", "empty")]
        assert verdict(mcp(h)) == DENY

    @pytest.mark.parametrize("site", ["same-origin", "same-site", "cross-site", "x", "",
                                      "nonee", "none,none", "none;x"])
    @pytest.mark.parametrize("mode", [None, "cors", "navigate", "no-cors"])
    def test_any_site_but_none_is_denied(self, site, mode):
        h = [("Sec-Fetch-Site", site)] + ([("Sec-Fetch-Mode", mode)] if mode else [])
        assert verdict(health(h)) == DENY

    def test_cors_mode_with_site_none_is_denied(self):
        assert verdict(health([("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "cors")])) == DENY

    @pytest.mark.parametrize("mode", ["no-cors", "websocket", "same-origin", "navigate", "",
                                      "x", "cors,cors"])
    def test_mode_without_site_must_be_cors(self, mode):
        assert verdict(health([("Sec-Fetch-Mode", mode)])) == DENY

    @pytest.mark.parametrize("mode", ["no-cors", "websocket", "nested-navigate", "", "x",
                                      "cors", "same-origin"])
    def test_mode_with_site_none_must_be_navigate(self, mode):
        assert verdict(health([("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", mode)])) == DENY


class TestDestAndUser:
    @pytest.mark.parametrize("v", ["document", "script", "empty", "x", "", "iframe", "image",
                                   "Document"])
    def test_dest_without_site_is_denied(self, v):
        assert verdict(health([("Sec-Fetch-Dest", v)])) == DENY
        assert verdict(mcp([("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", v)])) == DENY

    @pytest.mark.parametrize("v", ["?1", "?0", "", "1", "true"])
    def test_user_without_site_is_denied(self, v):
        assert verdict(health([("Sec-Fetch-User", v)])) == DENY

    @pytest.mark.parametrize("v", ["script", "x", "empty", "", "iframe", "documents",
                                   "document,document"])
    def test_dest_outside_set_with_site_none(self, v):
        assert verdict(health([("Sec-Fetch-Site", "none"), ("Sec-Fetch-Dest", v)])) == DENY

    @pytest.mark.parametrize("v", ["?0", "", "1", "?2", "true", "?1?1"])
    def test_user_outside_set_with_site_none(self, v):
        assert verdict(health([("Sec-Fetch-Site", "none"), ("Sec-Fetch-User", v)])) == DENY


class TestDuplicatesAndPadding:
    @pytest.mark.parametrize("name,good,bad", [
        ("Sec-Fetch-Site", "none", "cross-site"),
        ("Sec-Fetch-Mode", "navigate", "cors"),
        ("Sec-Fetch-Dest", "document", "script"),
        ("Sec-Fetch-User", "?1", "?0"),
    ])
    @pytest.mark.parametrize("order", ["good-first", "bad-first", "empty-second"])
    def test_any_bad_duplicate_denies(self, name, good, bad, order):
        base = [("Sec-Fetch-Site", "none")] if name != "Sec-Fetch-Site" else []
        second = {"good-first": bad, "bad-first": good, "empty-second": ""}[order]
        first = {"good-first": good, "bad-first": bad, "empty-second": good}[order]
        assert verdict(health(base + [(name, first), (name.lower(), second)])) == DENY

    def test_duplicate_mode_without_site_checks_every_value(self):
        for pair in (["cors", "no-cors"], ["no-cors", "cors"], ["cors", "navigate"],
                     ["cors", ""]):
            h = [("Sec-Fetch-Mode", v) for v in pair]
            assert verdict(mcp(h)) == DENY, pair
        assert verdict(mcp([("Sec-Fetch-Mode", "cors"), ("sec-fetch-mode", "CORS")])) == OK

    def test_duplicate_mode_with_site_none_checks_every_value(self):
        for pair in (["navigate", "cors"], ["cors", "navigate"]):
            h = [("Sec-Fetch-Site", "none")] + [("Sec-Fetch-Mode", v) for v in pair]
            assert verdict(health(h)) == DENY, pair

    @pytest.mark.parametrize("pad", PADS)
    @pytest.mark.parametrize("name,value", [
        ("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Dest", "document"), ("Sec-Fetch-User", "?1"),
    ])
    def test_unicode_padding_of_every_header_is_denied(self, pad, name, value):
        for v in (pad + value, value + pad, pad + value + pad):
            h = [("Sec-Fetch-Site", "none"), ("Sec-Fetch-Mode", "navigate"),
                 ("Sec-Fetch-Dest", "document"), ("Sec-Fetch-User", "?1")]
            h = [(n, v if n == name else x) for n, x in h]
            assert verdict(health(h)) == DENY, (name, v)

    @pytest.mark.parametrize("pad", PADS)
    def test_unicode_padded_cors_without_site_is_denied(self, pad):
        assert verdict(mcp([("Sec-Fetch-Mode", pad + "cors")])) == DENY
        assert verdict(mcp([("Sec-Fetch-Mode", "cors" + pad)])) == DENY

    def test_origin_still_wins_and_is_always_403_origin(self):
        for extra in ([], [("Sec-Fetch-Site", "none")], [("Sec-Fetch-Mode", "cors")]):
            assert verdict(mcp([("Origin", "null")] + extra)) == (False, 403, "forbidden_origin")


class TestSurvivingMutantsRound2:
    # (a) only the FIRST Sec-Fetch-Mode header consulted
    def test_second_mode_header_is_consulted(self):
        assert verdict(mcp([("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Mode", "no-cors")])) == DENY

    # (b) port 65535 is valid, 65536 is not
    def test_port_65535_accepted(self):
        assert host_allowed("127.0.0.1:65535", [65535])
        assert host_allowed("localhost:65535", 65535)
        d = check_request("GET", "/v1/health", [("Host", "127.0.0.1:65535")],
                          expected_ports=(65535,), token=TOKEN)
        assert d.allowed

    def test_port_65536_and_0_rejected(self):
        assert not host_allowed("127.0.0.1:65536", [65536])
        assert not host_allowed("127.0.0.1:65535", [65536])
        assert not host_allowed("127.0.0.1:65535", [65535, 65536])
        assert not host_allowed("127.0.0.1:1", [0, 1])

    # (c) the 10,000-item cut sits exactly between 10,000 and 10,001
    def test_item_cut_boundary(self):
        assert host_allowed(HOST_OK, [PORT] * 10_000)
        assert not host_allowed(HOST_OK, [PORT] * 10_001)
        assert not host_allowed(HOST_OK, [PORT] * 100_000)
        assert not host_allowed(HOST_OK, [PORT] * 10_000 + [PORT + 1])

    # (d) int subclasses: accepted (isinstance); bool stays rejected
    def test_int_subclass_ports_are_accepted_bool_is_not(self):
        class Port(enum.IntEnum):
            A = PORT

        class Plain(int):
            pass

        assert host_allowed(HOST_OK, [Port.A])
        assert host_allowed(HOST_OK, Port.A)
        assert host_allowed(HOST_OK, [Plain(PORT)])
        assert not host_allowed("127.0.0.1:1", [True])
        assert not host_allowed("127.0.0.1:1", [PORT, True])

    # (e) bearer token length boundary
    def test_bearer_token_512_ok_513_denied(self):
        t512 = "a" * 512
        t513 = "a" * 513
        assert verdict(mcp(token=t512)) == OK
        d = mcp(token=t513)
        assert (d.allowed, d.status, d.code) == (False, 401, "invalid_api_key")
        t511 = "a" * 511
        assert verdict(mcp(token=t511)) == OK


class _Boom:
    def __init__(self, exc):
        self.exc = exc

    def __iter__(self):
        yield PORT
        raise self.exc


class TestHostAllowedNeverRaises:
    @pytest.mark.parametrize("exc", [RuntimeError("Set changed size during iteration"),
                                     ValueError("x"), OSError("x"), KeyError("x"),
                                     OverflowError("x"), ZeroDivisionError()])
    def test_hostile_iterable(self, exc):
        assert host_allowed(HOST_OK, _Boom(exc)) is False

    def test_hostile_len_and_eq(self):
        class Evil(int):
            def __eq__(self, o):
                raise RuntimeError

            def __hash__(self):
                raise ValueError

        assert host_allowed(HOST_OK, [Evil(PORT)]) is False

    def test_hostile_iter_itself(self):
        class Evil:
            def __iter__(self):
                raise RuntimeError("boom")

        assert host_allowed(HOST_OK, Evil()) is False
