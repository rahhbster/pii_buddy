"""Real-socket tests for ``pii_buddy.server.http`` on 127.0.0.1 port 0.

Raw bytes go straight to the socket so the stdlib http.client cannot tidy a
malformed request.  The core is the deterministic stand-in from
``tests._protocol_helpers``; token, port and canary strings are fake.
"""

import json
import logging
import socket
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


class Harness:
    def __init__(self, dispatch=None, **kw):
        self.usage = protocol.UsageCounter()
        self.records = []

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
            dispatch or default, TOKEN, logger=self.logger, **kw)
        self.port = self.server.port
        self.client = Client(self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

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
    @pytest.mark.parametrize("line", [
        "GET /v1/health",
        "GET /v1/health HTTP/0.9",
        "GET  /v1/health HTTP/1.1",
        "GET /v1/health  HTTP/1.1",
        "GET /v1/health HTTP/1.1 extra",
        "GET //v1/health HTTP/1.1",
        "GET http://127.0.0.1:{p}/v1/health HTTP/1.1",
        "GET /v1/%68ealth HTTP/1.1",
        "GET /v1/./health HTTP/1.1",
        "GET /v1/health#x HTTP/1.1",
        "GET \\v1\\health HTTP/1.1",
        "get /v1/health HTTP/1.1",
        "GET /v1/health http/1.1",
        "GET /v1/health HTTP/1.1\x00",
        "* * HTTP/1.1",
        "GET * HTTP/1.1",
        "CONNECT 127.0.0.1:{p} HTTP/1.1",
    ])
    def test_malformed_or_ambiguous_lines_never_succeed(self, harness, line):
        line = line.format(p=harness.port)
        data = (line + f"\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n").encode("latin-1")
        s, _, b = harness.client.send(data)
        assert s in (400, 405, 414, 505), (line, s)
        assert s is not None

    def test_http2_preface_and_unsupported_versions(self, harness):
        s, _, _ = harness.client.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        assert s in (400, 505)
        s, _, _ = harness.client.send(
            f"GET /v1/health HTTP/2.0\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n".encode())
        assert s in (400, 505)

    def test_bare_lf_line_endings_are_rejected(self, harness):
        s, _, _ = harness.client.send(
            f"GET /v1/health HTTP/1.1\nHost: 127.0.0.1:{harness.port}\n\n".encode())
        assert s == 400

    def test_overlong_request_line_is_rejected_and_server_survives(self, harness):
        s, _, _ = harness.client.send(b"GET /" + b"a" * 100_000 + b" HTTP/1.1\r\n\r\n")
        assert s in (400, 414)
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
        assert harness.client.send(data)[0] in (400, 431)

    def test_very_long_header_line(self, harness):
        data = (f"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n"
                "X-Big: " + "a" * 200_000 + "\r\n\r\n").encode()
        assert harness.client.send(data)[0] in (400, 431)
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
        h = make(read_timeout=0.4)
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", h.port), timeout=5) as s:
            s.sendall(b"GET /v1/health HTTP/1.1\r\n")
            raw = s.recv(1024)
        assert raw.startswith(b"HTTP/1.0 408")
        assert time.monotonic() - t0 < 3
        assert h.client.req("GET", "/v1/health", auth=False)[0] == 200

    def test_trickling_bytes_cannot_extend_the_deadline(self, make):
        h = make(read_timeout=0.6)
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
        s, _, _ = h.client.send(head + b'{"te')
        assert s in (None, 400, 408)
        assert time.monotonic() - t0 < 3


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

    def test_connection_cap_drops_extra_connections_and_recovers(self, make):
        h = make(read_timeout=0.8, max_connections=8)
        socks = [socket.create_connection(("127.0.0.1", h.port), timeout=5)
                 for _ in range(8)]
        try:
            time.sleep(0.2)
            extra = socket.create_connection(("127.0.0.1", h.port), timeout=5)
            try:
                extra.sendall(b"GET /v1/health HTTP/1.1\r\n\r\n")
                got = extra.recv(1024)
            except (ConnectionResetError, socket.timeout):
                got = b""
            finally:
                extra.close()
            assert not got.startswith(b"HTTP/1.0 200")
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
        for r in h.records:
            assert CANARY not in r.getMessage()

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
        assert h.client.req("GET", "/v1/health", auth=False)[0] == 200

    def test_dispatch_returning_garbage_is_a_fixed_500(self, make):
        h = make(lambda route, body, rid: "not a Response")
        s, _, b = h.client.req("POST", "/v1/check", {"text": "x"})
        assert (s, error_of(b)) == (500, "internal_error")

    def test_garbage_bytes_do_not_kill_the_server(self, harness):
        import os
        for blob in (os.urandom(4096), b"\x00" * 1000, b"\xff\xfe" * 500, b"\r\n" * 300):
            harness.client.send(blob, read_timeout=2)
        assert harness.client.req("GET", "/v1/health", auth=False)[0] == 200


class TestLoggingAndBinding:
    def test_binds_loopback_only(self, harness):
        assert harness.server.server_address[0] == "127.0.0.1"

    def test_log_has_only_allowed_fields_and_never_text_or_token(self, harness):
        harness.client.req("POST", "/v1/redact", {"text": "mail a@b.c " + CANARY})
        harness.client.req("GET", "/v1/usage", headers=[("X-Canary", CANARY)])
        harness.client.req("POST", "/v1/check", auth=False, body=("{" + CANARY).encode())
        harness.client.send(f"GET /{CANARY} HTTP/1.1\r\n\r\n".encode())
        assert harness.records
        allowed = {"request_id", "route", "status", "ms", "bytes_in",
                   "entity_count", "error", "exc_type", "where"}
        for r in harness.records:
            text = r.getMessage() + " " + json.dumps(getattr(r, "fields", {}), default=str)
            assert CANARY not in text and CANARY.lower() not in text.lower()
            assert TOKEN not in text
            assert r.exc_info is None
            assert set(getattr(r, "fields", {})) <= allowed
        ids = [r.fields["request_id"] for r in harness.records if hasattr(r, "fields")]
        assert all(i.startswith("r_") for i in ids)

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
