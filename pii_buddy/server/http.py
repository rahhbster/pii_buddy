"""Loopback HTTP front end for the local API.

This module owns the bytes: it parses the request itself instead of using
``http.server``, whose parser quietly rewrites ``//path``, drops malformed
header lines, speaks HTTP/0.9 and answers errors with HTML that echoes the
request.  Parsed parts go to ``guard.check_request``; admitted requests go to
an injected ``dispatch(route, body, request_id) -> protocol.Response``.

Every response is HTTP/1.0 with ``Connection: close``.  Error bodies are fixed
JSON and never contain request data.  Logging is limited to the fields in
``_LOG_FIELDS``.
"""

import json
import logging
import secrets
import socket
import socketserver
import threading
import time

from . import guard, protocol

READ_TIMEOUT = guard.READ_TIMEOUT
HEAD_TIMEOUT = 2
MAX_CONNECTIONS = 64
MAX_LINE = 8192 + 256
MAX_HEAD_BYTES = 64 * 1024
DRAIN_BYTES = 256 * 1024
DRAIN_SECONDS = 0.5

_METHOD_OK = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_VERSIONS = ("HTTP/1.0", "HTTP/1.1")

_REASONS = {
    200: "OK", 202: "Accepted", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 411: "Length Required", 413: "Payload Too Large",
    414: "URI Too Long", 415: "Unsupported Media Type",
    421: "Misdirected Request", 431: "Request Header Fields Too Large",
    500: "Internal Server Error", 501: "Not Implemented",
    503: "Service Unavailable", 505: "HTTP Version Not Supported",
}

# Fixed text per code; guard and protocol codes plus the ones raised here.
_MESSAGES = {
    "bad_request": "request is not valid",
    "method_not_allowed": "method not allowed",
    "forbidden_origin": "origin not allowed",
    "forbidden_fetch_site": "cross-site requests are not allowed",
    "bad_host": "host not allowed",
    "invalid_api_key": "missing or invalid API key",
    "not_found": "not found",
    "length_required": "Content-Length is required",
    "payload_too_large": "payload is too large",
    "unsupported_media_type": "Content-Type must be application/json",
    "not_implemented": "not implemented",
    "request_timeout": "request timed out",
    "uri_too_long": "request line is too long",
    "headers_too_large": "request headers are too large",
    "version_not_supported": "HTTP version not supported",
    "busy": "server is busy",
    "internal_error": "internal error",
}

_LOG_FIELDS = ("request_id", "route", "status", "ms", "bytes_in",
               "entity_count", "error", "exc_type", "where")

_NULL_LOGGER = logging.getLogger("pii_buddy.server.http")
_NULL_LOGGER.addHandler(logging.NullHandler())
_NULL_LOGGER.propagate = False


class _Reject(Exception):
    """A request that stops here with a fixed status and code."""

    def __init__(self, status, code):
        super().__init__(code)
        self.status = status
        self.code = code


def _json_error(request_id, code):
    return json.dumps(
        {"error": code, "message": _MESSAGES[code], "request_id": request_id},
        separators=(",", ":"),
    ).encode("ascii")


def _new_request_id():
    return "r_" + secrets.token_hex(8)


def _raw_response(status, body, headers=()):
    head = [f"HTTP/1.0 {status} {_REASONS.get(status, 'Status')}"]
    for k, v in headers:
        head.append(f"{k}: {v}")
    head.append(f"Content-Length: {len(body)}")
    head.append("Connection: close")
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body


def _error_headers(code):
    extra = (("Retry-After", "1"),) if code == "busy" else ()
    return tuple(protocol.HEADERS) + extra


def _declared_length(headers):
    """The Content-Length the guard would accept, else None."""
    values = [v for k, v in headers if k.lower() == "content-length"]
    if len(values) != 1 or not guard._CONTENT_LENGTH.fullmatch(values[0]):
        return None
    return int(values[0])


class _Handler(socketserver.BaseRequestHandler):

    # ---------------------------------------------------------------- reading

    def _deadline_left(self):
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise _Reject(408, "request_timeout")
        return left

    def _recv(self):
        # The deadline is re-armed on every recv: a per-line timeout would let
        # a client trickle one byte at a time and hold the thread indefinitely.
        self.request.settimeout(self._deadline_left())
        try:
            return self.request.recv(65536)
        except (socket.timeout, TimeoutError):
            raise _Reject(408, "request_timeout")
        except OSError:
            raise _Reject(400, "bad_request")

    def _readline(self, limit, too_long):
        while True:
            end = self._buf.find(b"\n")
            if end >= 0:
                line = bytes(self._buf[:end + 1])
                del self._buf[:end + 1]
                if len(line) > limit:
                    raise _Reject(*too_long)
                if not line.endswith(b"\r\n"):
                    raise _Reject(400, "bad_request")  # bare LF
                return line[:-2]
            if len(self._buf) > limit:
                raise _Reject(*too_long)
            chunk = self._recv()
            if not chunk:
                raise _Reject(400, "bad_request")
            self._buf += chunk

    def _read_request_line(self):
        line = self._readline(guard.MAX_TARGET + 64, (414, "uri_too_long"))
        if not line or any(b < 0x20 or b > 0x7E for b in line):
            raise _Reject(400, "bad_request")
        parts = line.decode("ascii").split(" ")
        if len(parts) != 3 or not all(parts):
            raise _Reject(400, "bad_request")
        method, target, version = parts
        if not method.isascii() or not all(ord(c) in _METHOD_OK for c in method):
            raise _Reject(400, "bad_request")
        if len(method) > 16:
            raise _Reject(400, "bad_request")
        if version not in _VERSIONS:
            if version.startswith("HTTP/"):
                raise _Reject(505, "version_not_supported")
            raise _Reject(400, "bad_request")
        return method, target

    def _read_headers(self):
        headers = []
        total = 0
        while True:
            line = self._readline(MAX_LINE, (431, "headers_too_large"))
            if not line:
                return headers
            total += len(line) + 2
            if total > MAX_HEAD_BYTES or len(headers) >= guard.MAX_HEADERS + 1:
                raise _Reject(431, "headers_too_large")
            if line[0] in (0x20, 0x09):
                raise _Reject(400, "bad_request")  # obsolete line folding
            name, sep, value = line.partition(b":")
            if not sep:
                raise _Reject(400, "bad_request")
            # Name is passed exactly as received so the guard sees "Origin "
            # or "Origin\t" instead of a silently tidied "Origin".
            headers.append((name.decode("latin-1"),
                            value.decode("latin-1").strip(" \t")))

    def _read_body(self, length):
        while len(self._buf) < length:
            chunk = self._recv()
            if not chunk:
                raise _Reject(400, "bad_request")
            self._buf += chunk
        # Anything past the declared length is ignored, never parsed.
        return bytes(self._buf[:length])

    # ---------------------------------------------------------------- writing

    def _send(self, status, body, headers=()):
        """Return False if the peer did not take the whole response."""
        self.request.settimeout(self.server.send_timeout)
        try:
            self.request.sendall(_raw_response(status, body, headers))
        except OSError:
            return False
        return True

    def _send_error(self, status, code, request_id):
        return self._send(status, _json_error(request_id, code), _error_headers(code))

    def _drain_and_close(self):
        """Let the peer read our answer even if we left its body unread.

        Closing with unread input sends a RST, which can destroy the response
        before the peer reads it.  An uploader that writes its whole declared
        body before reading (http.client does) is drained up to the cap within
        the body deadline; anything else gets the short drain.
        """
        try:
            self.request.shutdown(socket.SHUT_WR)
            left = 0
            if self._declared is not None:
                left = min(self._declared, guard.BODY_CAP) - len(self._buf)
            if left > 0:
                end = self._deadline
            else:
                end = time.monotonic() + DRAIN_SECONDS
                left = DRAIN_BYTES
            while left > 0 and time.monotonic() < end:
                # A stalled peer is dropped after DRAIN_SECONDS of silence.
                self.request.settimeout(
                    max(0.01, min(DRAIN_SECONDS, end - time.monotonic())))
                chunk = self.request.recv(min(left, 65536))
                if not chunk:
                    break
                left -= len(chunk)
        except OSError:
            pass

    # ---------------------------------------------------------------- logging

    def _log(self, request_id, route, status, started, bytes_in, *,
             entity_count=None, error=None, exc_type=None, where=None):
        fields = {
            "request_id": request_id, "route": route, "status": status,
            "ms": int((time.monotonic() - started) * 1000), "bytes_in": bytes_in,
            "entity_count": entity_count, "error": error,
            "exc_type": exc_type, "where": where,
        }
        fields = {k: fields[k] for k in _LOG_FIELDS if fields[k] is not None}
        self.server.logger.info(
            "%s %s %s", request_id, route or "-", status, extra={"fields": fields})

    # ---------------------------------------------------------------- handling

    def handle(self):
        started = time.monotonic()
        # Unauthenticated peers can hold a connection only for the short head
        # deadline; the longer read_timeout starts once the headers are in.
        self._deadline = started + self.server.head_timeout
        self._buf = bytearray()
        self._declared = None
        request_id = _new_request_id()
        route, status, bytes_in = None, 500, 0
        error = exc_type = where = entity_count = None
        sent = True
        try:
            try:
                method, target = self._read_request_line()
                headers = self._read_headers()
                self._deadline = time.monotonic() + self.server.read_timeout
                self._declared = _declared_length(headers)
                decision = guard.check_request(
                    method, target, headers,
                    expected_ports=(self.server.port,), token=self.server.token)
                if not decision.allowed:
                    raise _Reject(decision.status, decision.code)
                route = decision.route
                if method == "POST":
                    # The body is read before taking a slot so a slow uploader
                    # cannot hold one of the MAX_INFLIGHT workers idle.
                    body = self._read_body(self._declared)
                    bytes_in = self._declared
                    if not self.server.slots.acquire(blocking=False):
                        raise _Reject(503, "busy")
                    try:
                        response = self._dispatch(route, body, request_id)
                    finally:
                        self.server.slots.release()
                else:
                    response = self._dispatch(route, None, request_id)
                status = response.status
                entity_count = response.entity_count
                if response.diag is not None:
                    error = response.diag.code
                    exc_type = response.diag.exc_type
                    where = response.diag.where
                sent = self._send(response.status, response.body, response.headers)
            except _Reject as r:
                status, error = r.status, r.code
                sent = self._send_error(r.status, r.code, request_id)
        except BaseException as exc:  # noqa: BLE001 - see _dispatch
            status, error, exc_type = 500, "internal_error", _class_name(exc)
            sent = self._send_error(500, "internal_error", request_id)
        finally:
            try:
                self._log(request_id, route, status, started, bytes_in,
                          entity_count=entity_count,
                          error=error if sent else "send_failed",
                          exc_type=exc_type, where=where)
            finally:
                self._drain_and_close()

    def _dispatch(self, route, body, request_id):
        """Run the injected dispatch; anything but a Response is a fixed 500.

        A worker can raise a BaseException (SystemExit from a dying child,
        KeyboardInterrupt).  Inside a request thread that must neither kill
        the server nor leave the client hanging, so the caller turns it into
        a fixed 500 and keeps serving; only the class name is logged.
        """
        response = self.server.dispatch(route, body, request_id)
        if type(response) is not protocol.Response:
            raise TypeError("dispatch returned a non-Response")
        return response


def _class_name(exc):
    name = type(exc).__name__
    return name if protocol._NAME_RE.fullmatch(name) else "Exception"


class LocalServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, dispatch, token, *, port=0, logger=None,
                 read_timeout=READ_TIMEOUT, head_timeout=HEAD_TIMEOUT,
                 send_timeout=READ_TIMEOUT, max_connections=MAX_CONNECTIONS):
        self.dispatch = dispatch
        self.token = token
        self.logger = logger or _NULL_LOGGER
        self.read_timeout = read_timeout
        self.head_timeout = head_timeout
        self.send_timeout = send_timeout
        self.slots = threading.BoundedSemaphore(guard.MAX_INFLIGHT)
        self._connections = threading.BoundedSemaphore(max_connections)
        super().__init__(("127.0.0.1", port), _Handler)
        self.port = self.server_address[1]

    def process_request(self, request, client_address):
        if not self._connections.acquire(blocking=False):
            # Runs on the accept thread, so the answer must never block it.
            try:
                request.setblocking(False)
                request.send(_raw_response(
                    503, _json_error(_new_request_id(), "busy"), _error_headers("busy")))
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()

    def handle_error(self, request, client_address):
        # The default prints a traceback (with exception text) to stderr.
        pass


def make_server(dispatch, token, *, port=0, logger=None, **kwargs):
    """Build a LocalServer bound to 127.0.0.1.

    ``dispatch`` must answer GET /v1/health and GET /v1/usage in-process and
    never send them to a worker pool: they bypass the MAX_INFLIGHT slots, so
    they stay answerable while every worker is busy.
    """
    return LocalServer(dispatch, token, port=port, logger=logger, **kwargs)
