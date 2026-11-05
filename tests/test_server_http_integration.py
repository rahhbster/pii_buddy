"""Real-socket tests for ``pii_buddy.server.http`` on 127.0.0.1 port 0.

Raw bytes go straight to the socket so the stdlib http.client cannot tidy a
malformed request.  The core is the deterministic stand-in from
``tests._protocol_helpers``; token, port and canary strings are fake.
"""

import json
import logging
import socket
import struct
import threading
import time

import pytest

from pii_buddy.server import guard, http, protocol
from tests._protocol_helpers import CANARY, install_fake_core

TOKEN = "fake-token_AbCdEf0123456789-ZyXwVu_9876543210"


class Client:
    def __init__(self, port):
        self.port = port

    def send(self, data, *, read_timeout=5.0, shutdown_write=False):
        """Send raw bytes, return (status, headers, body) or (None, {}, raw)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=read_timeout) as s:
            if data:
                s.sendall(data)
            if shutdown_write:
                s.shutdown(socket.SHUT_WR)
            chunks = []
            try:
                while True:
                    c = s.recv(65536)
                    if not c:
                        break
                    chunks.append(c)
            except (socket.timeout, ConnectionResetError):
                pass
        return parse_response(b"".join(chunks))

    def req(self, method, path, obj=None, *, headers=None, body=None, host=True, auth=True):
        raw = body if body is not None else (b"" if obj is None else json.dumps(obj).encode())
        lines = [f"{method} {path} HTTP/1.1"]
        if host:
            lines.append(f"Host: 127.0.0.1:{self.port}")
        if auth:
            lines.append(f"Authorization: Bearer {TOKEN}")
        if method == "POST":
            lines.append("Content-Type: application/json")
            lines.append(f"Content-Length: {len(raw)}")
        for k, v in (headers or []):
            lines.append(f"{k}: {v}")
        return self.send(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + raw)


def parse_response(raw):
    if not raw.startswith(b"HTTP/"):
        return None, {}, raw
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers, body


def error_of(body):
    return json.loads(body)["error"]


def connect(port, timeout=5):
    return socket.create_connection(("127.0.0.1", port), timeout=timeout)


def read_all(s):
    chunks = []
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            chunks.append(c)
    except (socket.timeout, ConnectionResetError):
        pass
    return parse_response(b"".join(chunks))


def reset(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def post_head(port, length, *, auth=True):
    lines = [f"POST /v1/check HTTP/1.1", f"Host: 127.0.0.1:{port}"]
    if auth:
        lines.append(f"Authorization: Bearer {TOKEN}")
    lines += ["Content-Type: application/json", f"Content-Length: {length}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def health_req(port):
    return f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()


def fields_of(record):
    """The record's fields with ``ms`` checked and removed; ``fields`` is required."""
    f = dict(record.fields)
    ms = f.pop("ms")
    assert type(ms) is int and 0 <= ms < 60_000
    return f


class Harness:
    def __init__(self, dispatch=None, **kw):
        self.usage = protocol.UsageCounter()
        self.records = []
        logger = kw.pop("logger", None)

        class _H(logging.Handler):
            def emit(_self, record):
                self.records.append(record)

        self.logger = logging.getLogger("pii_buddy.test.%d" % id(self))
        self.logger.handlers[:] = [_H()]
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)

        def default(route, body, request_id):
            return protocol.handle(route, body, request_id=request_id, usage=self.usage)

        self.server = http.make_server(
            dispatch or default, TOKEN, logger=logger or self.logger, **kw)
        self.port = self.server.port
        self.client = Client(self.port)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def wait_records(self, n, timeout=5.0):
        deadline = time.monotonic() + timeout
        while len(self.records) < n and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(self.records) >= n, self.records
        return self.records

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        assert not self.thread.is_alive()


@pytest.fixture
def harness(monkeypatch):
    install_fake_core(monkeypatch)
    h = Harness()
    yield h
    h.close()


@pytest.fixture
def make(monkeypatch):
    install_fake_core(monkeypatch)
    made = []

    def _make(dispatch=None, **kw):
        h = Harness(dispatch, **kw)
        made.append(h)
        return h

    yield _make
    for h in made:
        h.close()


class TestHappyPath:
    def test_health_is_unauthenticated_and_minimal(self, harness):
        s, h, b = harness.client.req("GET", "/v1/health", auth=False)
        assert (s, json.loads(b)) == (200, {"ok": True})
        assert h["content-type"] == "application/json"
        assert h["connection"] == "close"
        assert h["content-length"] == str(len(b))
        assert "server" not in h and "date" not in h

    def test_check_redact_restore_usage_mcp(self, harness):
        c = harness.client
        s, _, b = c.req("POST", "/v1/check", {"text": "mail a@b.c now"})
        assert s == 200 and json.loads(b)["entity_counts"] == {"EMAIL": 1}
        s, _, b = c.req("POST", "/v1/redact", {"text": "mail a@b.c now"})
        assert s == 200 and "mapping" in json.loads(b)
        s, _, b = c.req("POST", "/v1/restore",
                        {"redacted_text": "hi <<EMAIL_1>>", "mapping": {"<<EMAIL_1>>": "a@b.c"}})
        assert (s, json.loads(b)) == (200, {"text": "hi a@b.c"})
        s, _, b = c.req("GET", "/v1/usage")
        assert s == 200 and json.loads(b)["requests_served"] == 3
        s, _, b = c.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert (s, json.loads(b)) == (200, {"jsonrpc": "2.0", "id": 1, "result": {}})

    def test_mcp_notification_is_202_with_empty_body(self, harness):
        s, h, b = harness.client.req(
            "POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert (s, b) == (202, b"") and h["content-length"] == "0"

    def test_localhost_host_header_any_case(self, harness):
        for host in (f"localhost:{harness.port}", f"LOCALHOST:{harness.port}"):
            s, _, _ = harness.client.send(
                f"GET /v1/health HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            assert s == 200, host

    def test_response_is_http10_and_closes_even_for_keepalive(self, harness):
        raw = harness.client.send(
            f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
            "Connection: keep-alive\r\n\r\n".encode())
        assert raw[0] == 200 and raw[1]["connection"] == "close"

    def test_http10_request_works(self, harness):
        s, _, _ = harness.client.send(
            f"GET /v1/health HTTP/1.0\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n".encode())
        assert s == 200

    def test_expect_100_continue_never_gets_a_100(self, harness):
        body = json.dumps({"text": "x"}).encode()
        data = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nExpect: 100-continue\r\n\r\n").encode() + body
        with socket.create_connection(("127.0.0.1", harness.port), timeout=5) as s:
            s.sendall(data)
            first = s.recv(64)
        assert first.startswith(b"HTTP/1.0 200")


class TestAuth:
    def test_missing_and_wrong_token_are_401(self, harness):
        s, _, b = harness.client.req("POST", "/v1/check", {"text": "x"}, auth=False)
        assert (s, error_of(b)) == (401, "invalid_api_key")
        s, _, b = harness.client.req(
            "POST", "/v1/check", {"text": "x"}, auth=False,
            headers=[("Authorization", "Bearer wrong")])
        assert (s, error_of(b)) == (401, "invalid_api_key")

    def test_token_in_query_string_is_not_accepted(self, harness):
        s, _, _ = harness.client.req(
            "GET", f"/v1/usage?token={TOKEN}", auth=False)
        assert s == 401


class TestHostOriginFetch:
    @pytest.mark.parametrize("host", [
        "evil.example", "127.0.0.1.evil.com:{p}", "127.0.0.1:1", "127.0.0.1",
        "[::1]:{p}", "localhost.:{p}", "0.0.0.0:{p}",
    ])
    def test_bad_host_is_421(self, harness, host):
        host = host.format(p=harness.port)
        s, _, b = harness.client.send(
            f"GET /v1/health HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        assert (s, error_of(b)) == (421, "bad_host")

    def test_missing_and_duplicate_host(self, harness):
        s, _, _ = harness.client.send(b"GET /v1/health HTTP/1.1\r\n\r\n")
        assert s == 421
        s, _, _ = harness.client.send(
            f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
            f"Host: 127.0.0.1:{harness.port}\r\n\r\n".encode())
        assert s == 400

    def test_any_origin_is_403_even_with_a_valid_token(self, harness):
        for origin in ("http://evil.example", "null", ""):
            s, _, b = harness.client.req("GET", "/v1/usage", headers=[("Origin", origin)])
            assert (s, error_of(b)) == (403, "forbidden_origin"), origin

    @pytest.mark.parametrize("name", ["Origin ", "Origin\t", " Origin", "Or igin", "Origin\x00"])
    def test_malformed_origin_header_is_400_not_silently_dropped(self, harness, name):
        data = (f"GET /v1/usage HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\n{name}: http://evil.example\r\n\r\n")
        s, _, b = harness.client.send(data.encode("latin-1"))
        assert s == 400, repr(name)

    def test_cross_site_is_403_and_node_fetch_cors_alone_is_allowed(self, harness):
        s, _, b = harness.client.req(
            "GET", "/v1/usage", headers=[("Sec-Fetch-Site", "cross-site")])
        assert (s, error_of(b)) == (403, "forbidden_fetch_site")
        s, _, _ = harness.client.req(
            "GET", "/v1/usage", headers=[("Sec-Fetch-Mode", "cors")])
        assert s == 200

    def test_options_is_405_and_no_response_ever_carries_cors_headers(self, harness):
        s, h, b = harness.client.req("OPTIONS", "/v1/check")
        assert (s, error_of(b)) == (405, "method_not_allowed")
        responses = [
            h,
            harness.client.req("GET", "/v1/health", auth=False)[1],
            harness.client.req("GET", "/v1/nope")[1],
            harness.client.req("POST", "/v1/check", {"text": "x"}, auth=False)[1],
        ]
        for hdrs in responses:
            assert not [k for k in hdrs if k.startswith("access-control")]


class TestRequestLine:
    @pytest.mark.parametrize("line, status, code", [
        ("GET /v1/health", 400, "bad_request"),
        ("GET /v1/health HTTP/0.9", 505, "version_not_supported"),
        ("GET  /v1/health HTTP/1.1", 400, "bad_request"),
        ("GET /v1/health  HTTP/1.1", 400, "bad_request"),
        ("GET /v1/health HTTP/1.1 extra", 400, "bad_request"),
        ("GET //v1/health HTTP/1.1", 400, "bad_request"),
        ("GET http://127.0.0.1:{p}/v1/health HTTP/1.1", 400, "bad_request"),
        ("GET /v1/%68ealth HTTP/1.1", 400, "bad_request"),
        ("GET /v1/./health HTTP/1.1", 400, "bad_request"),
        ("GET /v1/health#x HTTP/1.1", 400, "bad_request"),
        ("GET \\v1\\health HTTP/1.1", 400, "bad_request"),
        ("get /v1/health HTTP/1.1", 400, "bad_request"),
        ("GET /v1/health http/1.1", 400, "bad_request"),
        ("GET /v1/health HTTP/1.1\x00", 400, "bad_request"),
        ("GET /v1/health\x7f HTTP/1.1", 400, "bad_request"),
        ("GET /v1/health HTTP/1.1\t", 400, "bad_request"),
        ("GET /v1/health HTTP/1.1\x7f", 400, "bad_request"),
        (" /v1/health HTTP/1.1", 400, "bad_request"),
        ("GET /v1/h\xe9alth HTTP/1.1", 400, "bad_request"),
        ("G\xc9T /v1/health HTTP/1.1", 400, "bad_request"),
        ("GETGETGETGETGETGE /v1/health HTTP/1.1", 400, "bad_request"),
        ("* * HTTP/1.1", 400, "bad_request"),
        ("GET * HTTP/1.1", 400, "bad_request"),
        ("CONNECT 127.0.0.1:{p} HTTP/1.1", 405, "method_not_allowed"),
    ])
    def test_malformed_or_ambiguous_lines_never_succeed(self, harness, line, status, code):
        line = line.format(p=harness.port)
        data = (line + f"\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n").encode("latin-1")
        s, _, b = harness.client.send(data)
        assert (s, error_of(b)) == (status, code), line

    def test_sixteen_letter_method_is_parsed_then_405(self, harness):
        s, _, b = harness.client.send(
            f"GETGETGETGETGETG /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n".encode())
        assert (s, error_of(b)) == (405, "method_not_allowed")

    def test_http2_preface_and_unsupported_versions(self, harness):
        s, _, b = harness.client.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        assert (s, error_of(b)) == (505, "version_not_supported")
        s, _, b = harness.client.send(
            f"GET /v1/health HTTP/2.0\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n".encode())
        assert (s, error_of(b)) == (505, "version_not_supported")

    def test_empty_request_line_is_400(self, harness):
        s, _, b = harness.client.send(b"\r\n\r\n")
        assert (s, error_of(b)) == (400, "bad_request")

    def test_stream_without_any_newline_is_bounded_and_rejected(self, make):
        h = make(head_timeout=0.3)
        t0 = time.monotonic()
        s, _, b = h.client.send(b"A" * 100_000)
        assert (s, error_of(b)) == (414, "uri_too_long")
        s, _, b = h.client.send(b"\x00" * 1000)
        assert (s, error_of(b)) == (408, "request_timeout")
        assert time.monotonic() - t0 < 2.5

    def test_request_line_at_the_limit_is_parsed(self, harness):
        # One byte under the line cap: parsed, then refused by the guard's target cap.
        target = "/" + "a" * (guard.MAX_TARGET + 64 - 2 - len("GET  HTTP/1.1") - 1)
        line = f"GET {target} HTTP/1.1"
        assert len(line) + 2 == guard.MAX_TARGET + 64
        s, _, b = harness.client.send(
            (line + f"\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n").encode())
        assert (s, error_of(b)) == (400, "bad_request")
        s, _, b = harness.client.send(
            (line + f"a\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n").encode())
        assert (s, error_of(b)) == (414, "uri_too_long")

    def test_bare_lf_line_endings_are_rejected(self, harness):
        s, _, _ = harness.client.send(
            f"GET /v1/health HTTP/1.1\nHost: 127.0.0.1:{harness.port}\n\n".encode())
        assert s == 400

    def test_overlong_request_line_is_rejected_and_server_survives(self, harness):
        s, _, b = harness.client.send(b"GET /" + b"a" * 100_000 + b" HTTP/1.1\r\n\r\n")
        assert (s, error_of(b)) == (414, "uri_too_long")
        assert harness.client.req("GET", "/v1/health", auth=False)[0] == 200

    def test_error_bodies_never_echo_the_request(self, harness):
        for path in (f"/{CANARY}", f"/v1/{CANARY}", f"/{CANARY}?{CANARY}={CANARY}"):
            s, h, b = harness.client.req(
                "GET", path, headers=[("X-Canary", CANARY)])
            assert CANARY.encode() not in b
            assert CANARY.lower().encode() not in b.lower()
            assert not any(CANARY.lower() in v.lower() for v in h.values())


class TestHeaders:
    def test_obsolete_line_folding_is_rejected(self, harness):
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                "X-A: one\r\n  two\r\n\r\n").encode()
        assert harness.client.send(data)[0] == 400

    def test_header_without_colon_is_rejected(self, harness):
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                "nocolon\r\n\r\n").encode()
        assert harness.client.send(data)[0] == 400

    def test_too_many_headers(self, harness):
        hdrs = "".join(f"X-{i}: v\r\n" for i in range(guard.MAX_HEADERS + 5))
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"{hdrs}\r\n").encode()
        s, _, b = harness.client.send(data)
        assert (s, error_of(b)) == (431, "headers_too_large")

    def test_exactly_max_headers_is_accepted(self, harness):
        hdrs = "".join(f"X-{i}: v\r\n" for i in range(guard.MAX_HEADERS - 1))
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"{hdrs}\r\n").encode()
        assert harness.client.send(data)[0] == 200

    def test_header_bytes_over_the_total_cap_are_431(self, harness):
        hdrs = "".join(f"X-{i}: {'v' * 8000}\r\n" for i in range(9))
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"{hdrs}\r\n").encode()
        s, _, b = harness.client.send(data)
        assert (s, error_of(b)) == (431, "headers_too_large")

    def test_header_values_are_trimmed_of_space_and_tab_only(self, harness):
        data = (f"GET /v1/health HTTP/1.1\r\nHost: \t 127.0.0.1:{harness.port} \t\r\n"
                "\r\n").encode()
        assert harness.client.send(data)[0] == 200

    def test_eof_mid_headers_is_400(self, harness):
        s, _, b = harness.client.send(
            f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}".encode(),
            shutdown_write=True)
        assert (s, error_of(b)) == (400, "bad_request")

    def test_tab_folded_header_is_rejected(self, harness):
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                "X-A: one\r\n\ttwo\r\n\r\n").encode()
        assert harness.client.send(data)[0] == 400

    def test_very_long_header_line(self, harness):
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                "X-Big: " + "a" * 200_000 + "\r\n\r\n").encode()
        s, _, b = harness.client.send(data)
        assert (s, error_of(b)) == (431, "headers_too_large")
        assert harness.client.req("GET", "/v1/health", auth=False)[0] == 200

    def test_non_ascii_header_name_is_rejected(self, harness):
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                "X-\xe9: v\r\n\r\n").encode("latin-1")
        assert harness.client.send(data)[0] == 400

    def test_transfer_encoding_is_501_and_a_smuggled_request_is_not_served(self, harness):
        smuggled = (f"GET /v1/usage HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                    f"Authorization: Bearer {TOKEN}\r\n\r\n")
        data = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"
                f"0\r\n\r\n{smuggled}").encode()
        with socket.create_connection(("127.0.0.1", harness.port), timeout=5) as s:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            raw = b""
            while True:
                c = s.recv(65536)
                if not c:
                    break
                raw += c
        assert raw.count(b"HTTP/1.0 ") == 1
        assert raw.startswith(b"HTTP/1.0 501")
        assert harness.usage.requests_served == 0


class TestBody:
    def test_missing_content_length_is_411_wrong_type_415(self, harness):
        head = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\n")
        s, _, b = harness.client.send((head + "Content-Type: application/json\r\n\r\n").encode())
        assert (s, error_of(b)) == (411, "length_required")
        s, _, b = harness.client.send(
            (head + "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}").encode())
        assert (s, error_of(b)) == (415, "unsupported_media_type")

    def test_duplicate_content_length_is_400(self, harness):
        data = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
                "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}").encode()
        assert harness.client.send(data)[0] == 400

    def test_oversize_declared_body_is_413_without_waiting_for_it(self, harness):
        head = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {guard.BODY_CAP + 1}\r\n\r\n").encode()
        t0 = time.monotonic()
        s, _, b = harness.client.send(head + b"a" * 200_000)
        assert (s, error_of(b)) == (413, "payload_too_large")
        assert time.monotonic() - t0 < 3

    def test_short_body_then_close_is_400(self, harness):
        data = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
                "Content-Length: 50\r\n\r\n{\"text\"").encode()
        s, _, b = harness.client.send(data, shutdown_write=True)
        assert s == 400

    def test_only_the_declared_length_is_read(self, harness):
        body = json.dumps({"text": "x"}).encode()
        data = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode() + body + b'{"text":"y"}'
        s, _, b = harness.client.send(data)
        assert s == 200 and harness.usage.requests_served == 1

    def test_body_split_across_packets_is_read_to_the_last_byte(self, harness):
        body = json.dumps({"text": "x"}).encode()
        with connect(harness.port) as s:
            s.sendall(post_head(harness.port, len(body)) + body[:-1])
            time.sleep(0.1)
            s.sendall(body[-1:])
            st, _, b = read_all(s)
        assert st == 200 and json.loads(b)["entity_counts"] == {}

    def test_bad_json_is_stable_400_without_echo(self, harness):
        s, _, b = harness.client.req("POST", "/v1/check", body=("{" + CANARY).encode())
        assert (s, error_of(b)) == (400, "invalid_json")
        assert CANARY.encode() not in b

    def test_get_with_a_body_is_rejected(self, harness):
        data = (f"GET /v1/usage HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Length: 5\r\n\r\nhello").encode()
        assert harness.client.send(data)[0] == 400


class TestTimeouts:
    def test_idle_connection_is_closed(self, make):
        h = make(head_timeout=0.4)
        t0 = time.monotonic()
        with connect(h.port) as s:
            s.sendall(b"GET /v1/health HTTP/1.1\r\n")
            st, _, b = read_all(s)
        assert (st, error_of(b)) == (408, "request_timeout")
        assert time.monotonic() - t0 < 3
        assert h.client.req("GET", "/v1/health", auth=False)[0] == 200

    def test_trickling_bytes_cannot_extend_the_deadline(self, make):
        h = make(head_timeout=0.6)
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", h.port), timeout=5) as s:
            try:
                for ch in b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:1\r\n":
                    s.sendall(bytes([ch]))
                    time.sleep(0.15)
            except OSError:
                pass
            closed_after = time.monotonic() - t0
        assert closed_after < 3.0
        assert h.client.req("GET", "/v1/health", auth=False)[0] == 200

    def test_slow_body_is_cut_off(self, make):
        h = make(read_timeout=0.5)
        head = (f"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1:{h.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
                "Content-Length: 20\r\n\r\n").encode()
        t0 = time.monotonic()
        s, _, b = h.client.send(head + b'{"te')
        assert (s, error_of(b)) == (408, "request_timeout")
        assert time.monotonic() - t0 < 3

    def test_body_gets_read_timeout_not_head_timeout(self, make):
        h = make(head_timeout=0.3, read_timeout=3)
        body = json.dumps({"text": "x"}).encode()
        with connect(h.port) as s:
            s.sendall(post_head(h.port, len(body)))
            time.sleep(0.6)
            s.sendall(body)
            st, _, _ = read_all(s)
        assert st == 200

    def test_idle_sockets_cannot_lock_out_health_for_long(self, make):
        h = make(max_connections=8)
        socks = [connect(h.port) for _ in range(8)]
        try:
            t0 = time.monotonic()
            while time.monotonic() - t0 < 6:
                if h.client.req("GET", "/v1/health", auth=False)[0] == 200:
                    break
                time.sleep(0.05)
            took = time.monotonic() - t0
        finally:
            for s in socks:
                s.close()
        assert took < 3.0


class TestConcurrency:
    def test_fifth_post_is_503_busy_and_health_still_answers(self, make):
        gate = threading.Event()
        entered = threading.Semaphore(0)

        def slow(route, body, request_id):
            if route == "POST /v1/check":
                entered.release()
                gate.wait(10)
            return protocol.handle(route, body, request_id=request_id,
                                   usage=protocol.UsageCounter())

        h = make(slow)
        results = []

        def fire():
            results.append(h.client.req("POST", "/v1/check", {"text": "x"}, host=True)[0])

        threads = [threading.Thread(target=fire) for _ in range(guard.MAX_INFLIGHT)]
        for t in threads:
            t.start()
        for _ in range(guard.MAX_INFLIGHT):
            assert entered.acquire(timeout=5)
        s, hdrs, b = h.client.req("POST", "/v1/check", {"text": "x"})
        assert (s, error_of(b)) == (503, "busy") and hdrs["retry-after"] == "1"
        assert h.client.req("GET", "/v1/health", auth=False)[0] == 200
        gate.set()
        for t in threads:
            t.join(10)
        assert results == [200] * guard.MAX_INFLIGHT
        assert h.client.req("POST", "/v1/check", {"text": "x"})[0] == 200

    def test_slow_uploaders_do_not_hold_inflight_slots(self, make):
        h = make(read_timeout=3)
        socks = []
        try:
            for _ in range(guard.MAX_INFLIGHT):
                s = connect(h.port)
                s.sendall(post_head(h.port, 20) + b'{"te')
                socks.append(s)
            time.sleep(0.2)
            assert h.client.req("POST", "/v1/check", {"text": "x"})[0] == 200
        finally:
            for s in socks:
                s.close()

    def test_connection_cap_answers_busy_and_recovers(self, make):
        h = make(head_timeout=3, max_connections=8)
        socks = [connect(h.port) for _ in range(8)]
        try:
            time.sleep(0.2)
            with connect(h.port) as extra:
                extra.sendall(health_req(h.port))
                s, hdrs, b = read_all(extra)
            assert (s, error_of(b)) == (503, "busy")
            assert hdrs["retry-after"] == "1" and hdrs["connection"] == "close"
            assert hdrs["content-type"] == "application/json"
            assert hdrs["content-length"] == str(len(b))
            assert json.loads(b)["request_id"].startswith("r_")
            assert h.records == []
        finally:
            for s in socks:
                s.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if h.client.req("GET", "/v1/health", auth=False)[0] == 200:
                break
            time.sleep(0.1)
        else:
            pytest.fail("server did not recover after the connection cap")


class TestFailureHandling:
    def test_dispatch_exception_is_a_fixed_500_and_server_continues(self, make):
        calls = []

        def boom(route, body, request_id):
            calls.append(1)
            raise RuntimeError("secret " + CANARY)

        h = make(boom)
        s, _, b = h.client.req("POST", "/v1/check", {"text": "x"})
        assert (s, error_of(b)) == (500, "internal_error")
        assert CANARY.encode() not in b
        assert len(calls) == 1
        [r] = h.records
        assert CANARY not in r.getMessage()
        assert fields_of(r) == {
            "request_id": json.loads(b)["request_id"], "route": "POST /v1/check",
            "status": 500, "bytes_in": len(b'{"text": "x"}'),
            "error": "internal_error", "exc_type": "RuntimeError"}
        assert CANARY not in json.dumps(r.fields)

    @pytest.mark.parametrize("exc", [SystemExit, KeyboardInterrupt, GeneratorExit])
    def test_base_exception_is_a_fixed_500_and_server_keeps_serving(self, make, exc):
        def boom(route, body, request_id):
            if route == "POST /v1/check":
                raise exc()
            return protocol.handle(route, body, request_id=request_id,
                                   usage=protocol.UsageCounter())

        h = make(boom)
        s, _, b = h.client.req("POST", "/v1/check", {"text": "x"})
        assert (s, error_of(b)) == (500, "internal_error")
        assert fields_of(h.records[0])["exc_type"] == exc.__name__
        assert h.client.req("GET", "/v1/health", auth=False)[0] == 200

    def test_unsafe_exception_class_name_is_not_logged(self, make):
        bad = type("Bad-" + CANARY, (Exception,), {})

        def boom(route, body, request_id):
            raise bad()

        h = make(boom)
        assert h.client.req("POST", "/v1/check", {"text": "x"})[0] == 500
        assert fields_of(h.records[0])["exc_type"] == "Exception"

    @pytest.mark.parametrize("garbage", [
        "not a Response",
        type("Response", (protocol.Response,), {})(200, b"{}"),
    ])
    def test_dispatch_returning_garbage_is_a_fixed_500(self, make, garbage):
        h = make(lambda route, body, rid: garbage)
        s, _, b = h.client.req("POST", "/v1/check", {"text": "x"})
        assert (s, error_of(b)) == (500, "internal_error")
        [r] = h.records
        assert fields_of(r)["exc_type"] == "TypeError"
        assert fields_of(r)["error"] == "internal_error"

    def test_get_dispatch_gets_no_body_and_post_gets_exact_bytes(self, make):
        seen = []

        def record(route, body, request_id):
            seen.append((route, body, request_id))
            return protocol.handle(route, body, request_id=request_id,
                                   usage=protocol.UsageCounter())

        h = make(record)
        h.client.req("GET", "/v1/health", auth=False)
        _, _, b = h.client.req("POST", "/v1/check", {"text": "x"})
        assert [(r, body) for r, body, _ in seen] == [
            ("GET /v1/health", None), ("POST /v1/check", b'{"text": "x"}')]
        assert [i for _, _, i in seen] == [f["request_id"] for f in map(fields_of, h.records)]

    def test_thread_start_failure_does_not_leak_a_slot_or_print(self, make, monkeypatch, capfd):
        h = make(max_connections=1)
        orig = threading.Thread.start
        failed = []

        def start(t):
            if not failed and t._target == h.server.process_request_thread:
                failed.append(1)
                raise RuntimeError("can't start new thread " + CANARY)
            return orig(t)

        monkeypatch.setattr(threading.Thread, "start", start)
        assert h.client.send(health_req(h.port))[0] is None
        assert failed == [1]
        assert h.client.send(health_req(h.port))[0] == 200
        assert h.client.send(health_req(h.port))[0] == 200
        out, err = capfd.readouterr()
        assert (out, err) == ("", "")

    def test_garbage_bytes_do_not_kill_the_server(self, harness):
        import os
        for blob in (os.urandom(4096), b"\x00" * 1000, b"\xff\xfe" * 500, b"\r\n" * 300):
            harness.client.send(blob, read_timeout=2)
        assert harness.client.req("GET", "/v1/health", auth=False)[0] == 200


class TestLoggingAndBinding:
    def test_binds_loopback_only(self, harness):
        assert harness.server.server_address[0] == "127.0.0.1"

    def test_log_fields_are_exact_and_never_carry_text_or_token(self, harness):
        c = harness.client
        redact = json.dumps({"text": "mail a@b.c " + CANARY}).encode()
        _, _, b_redact = c.req("POST", "/v1/redact", body=redact)
        c.req("GET", "/v1/usage", headers=[("X-Canary", CANARY)])
        _, _, b_401 = c.req("POST", "/v1/check", auth=False, body=("{" + CANARY).encode())
        bad_json = ("{" + CANARY).encode()
        _, _, b_json = c.req("POST", "/v1/check", body=bad_json)
        _, _, b_host = c.send(f"GET /{CANARY} HTTP/1.1\r\n\r\n".encode())
        c.req("GET", "/v1/health", auth=False)
        recs = harness.records
        assert len(recs) == 6
        got = [fields_of(r) for r in recs]
        rid = [g.pop("request_id") for g in got]
        assert all(i.startswith("r_") and len(i) == 18 for i in rid)
        assert len(set(rid)) == 6
        assert rid[2] == json.loads(b_401)["request_id"]
        assert rid[3] == json.loads(b_json)["request_id"]
        assert rid[4] == json.loads(b_host)["request_id"]
        assert got == [
            {"route": "POST /v1/redact", "status": 200, "bytes_in": len(redact),
             "entity_count": 1},
            {"route": "GET /v1/usage", "status": 200, "bytes_in": 0},
            {"status": 401, "bytes_in": 0, "error": "invalid_api_key"},
            {"route": "POST /v1/check", "status": 400, "bytes_in": len(bad_json),
             "error": "invalid_json"},
            {"status": 421, "bytes_in": 0, "error": "bad_host"},
            {"route": "GET /v1/health", "status": 200, "bytes_in": 0},
        ]
        for r in recs:
            text = r.getMessage() + " " + json.dumps(r.fields)
            assert CANARY not in text and CANARY.lower() not in text.lower()
            assert TOKEN not in text
            assert r.exc_info is None and r.levelno == logging.INFO
        assert [r.getMessage() for r in recs][4:] == [
            f"{rid[4]} - 421", f"{rid[5]} GET /v1/health 200"]

    def test_where_from_diag_is_logged(self, make):
        diag = protocol.Diag("internal_error", "ValueError", "core.py:f:1")
        resp = protocol.Response(500, b"{}", protocol.HEADERS, diag)
        h = make(lambda r, b, i: resp)
        h.client.req("GET", "/v1/health", auth=False)
        assert fields_of(h.records[0]) == {
            "request_id": h.records[0].fields["request_id"], "route": "GET /v1/health",
            "status": 500, "bytes_in": 0, "error": "internal_error",
            "exc_type": "ValueError", "where": "core.py:f:1"}

    def test_client_reset_mid_read_is_logged_as_400_not_500(self, make):
        h = make()
        s = connect(h.port)
        s.sendall(b"GET /v1/health HTTP/1.1\r\n")
        time.sleep(0.1)
        reset(s)
        [r] = h.wait_records(1)
        # The 400 cannot reach a reset peer, so the send failure is what is logged.
        assert fields_of(r) == {"request_id": r.fields["request_id"], "status": 400,
                                "bytes_in": 0, "error": "send_failed"}

    def test_client_reset_mid_response_is_logged_send_failed(self, make):
        big = protocol.Response(200, b"x" * (32 << 20), protocol.HEADERS)
        h = make(lambda r, b, i: big)
        s = connect(h.port)
        s.sendall(health_req(h.port))
        s.recv(1024)
        reset(s)
        [r] = h.wait_records(1)
        assert fields_of(r) == {"request_id": r.fields["request_id"],
                                "route": "GET /v1/health", "status": 200,
                                "bytes_in": 0, "error": "send_failed"}

    def test_unread_response_is_cut_off_at_send_timeout(self, make):
        big = protocol.Response(200, b"x" * (32 << 20), protocol.HEADERS)
        h = make(lambda r, b, i: big, send_timeout=0.3)
        t0 = time.monotonic()
        with connect(h.port) as s:
            s.sendall(health_req(h.port))
            [r] = h.wait_records(1, timeout=4)
        assert time.monotonic() - t0 < 2
        assert fields_of(r)["error"] == "send_failed"
        assert fields_of(r)["status"] == 200



class TestDrain:
    def _upload(self, port, length, *, auth=False):
        # Like http.client: write the whole body (paced past the old 0.5 s
        # drain window), only then read the answer.
        with connect(port) as s:
            s.sendall(post_head(port, length, auth=auth))
            for off in range(0, length, 65536):
                s.sendall(b"a" * min(65536, length - off))
                time.sleep(0.08)
            return read_all(s)

    @pytest.mark.parametrize("length", [300_000, guard.BODY_CAP])
    def test_whole_body_uploader_reads_its_401(self, harness, length):
        s, _, b = self._upload(harness.port, length)
        assert (s, error_of(b)) == (401, "invalid_api_key")

    def test_stalled_uploader_releases_its_connection(self, make):
        h = make(max_connections=1, read_timeout=5)
        with connect(h.port) as s:
            s.sendall(post_head(h.port, 400_000, auth=False) + b"a" * 1000)
            assert s.recv(65536).startswith(b"HTTP/1.0 401")
            t0 = time.monotonic()
            while time.monotonic() - t0 < 6:
                if h.client.send(health_req(h.port))[0] == 200:
                    break
                time.sleep(0.05)
            took = time.monotonic() - t0
        assert took < 1.5

    def test_drain_without_length_is_short_and_bounded(self, make):
        h = make(max_connections=1)
        with connect(h.port) as s:
            s.sendall(b"GET /nope HTTP/1.1\r\n\r\n")
            assert s.recv(65536).startswith(b"HTTP/1.0 421")
            t0 = time.monotonic()
            try:
                while time.monotonic() - t0 < 3:
                    s.sendall(b"x" * 4096)
                    time.sleep(0.01)
            except OSError:
                pass
            took = time.monotonic() - t0
        assert took < 1.5

    def test_logger_failure_still_drains_and_prints_nothing(self, make, capfd):
        class Boom:
            def info(self, *a, **k):
                raise RuntimeError("log " + CANARY)

        h = make(logger=Boom())
        s, _, b = self._upload(h.port, 300_000)
        assert (s, error_of(b)) == (401, "invalid_api_key")
        assert h.client.req("GET", "/v1/health", auth=False)[0] == 200
        assert capfd.readouterr() == ("", "")

    def test_request_id_is_fresh_per_request_and_in_error_bodies(self, harness):
        _, _, b1 = harness.client.req("GET", "/v1/nope")
        _, _, b2 = harness.client.req("GET", "/v1/nope")
        i1, i2 = json.loads(b1)["request_id"], json.loads(b2)["request_id"]
        assert i1 != i2 and i1.startswith("r_") and i2.startswith("r_")

    def test_shutdown_stops_serving(self, make):
        h = make()
        port = h.port
        h.close()
        h.thread = threading.Thread(target=lambda: None)
        h.thread.start()
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)
        h.server = type("S", (), {"shutdown": lambda s: None,
                                   "server_close": lambda s: None})()
