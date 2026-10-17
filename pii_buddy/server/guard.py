"""Pure admission control for the local API.

Every function takes already-parsed request parts and returns a verdict; no
sockets, threads, files or logging.  Codes are a stable machine vocabulary and
never contain request data.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass

BODY_CAP = 512 * 1024
TEXT_CAP = 50_000
READ_TIMEOUT = 10
MAX_INFLIGHT = 4

MAX_PORTS = 8
_MAX_PORT_ITEMS = 10_000
MAX_HEADERS = 100
MAX_HEADER_VALUE = 8192
MAX_TARGET = 2048

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HOST = re.compile(r"(?:127\.0\.0\.1|localhost):([1-9][0-9]{0,4})")
_BEARER = re.compile(r"(?ai:bearer) ([\x21-\x7e]{1,512})")
_CONTENT_LENGTH = re.compile(r"[0-9]{1,10}")
_CONTENT_TYPE = re.compile(
    r"application/json(?:[ \t]*;[ \t]*charset=utf-8)?", re.IGNORECASE | re.ASCII
)

_ROUTES = {
    "/v1/health": frozenset({"GET"}),
    "/v1/usage": frozenset({"GET"}),
    "/v1/check": frozenset({"POST"}),
    "/v1/redact": frozenset({"POST"}),
    "/v1/restore": frozenset({"POST"}),
    "/mcp": frozenset({"POST"}),
}
_UNAUTHENTICATED = ("GET", "/v1/health")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    status: int
    code: str
    route: str = ""


_BAD_REQUEST = Decision(False, 400, "bad_request")


def _deny(status, code):
    return Decision(False, status, code)


def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    return None


def compare_token(presented, expected):
    a = _to_bytes(presented)
    b = _to_bytes(expected)
    if a is None or not b:
        return False
    # Digesting first makes the compare independent of either length.
    return hmac.compare_digest(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())


def parse_bearer(header_value):
    if not isinstance(header_value, str):
        return None
    m = _BEARER.fullmatch(header_value)
    return m.group(1) if m else None


def _normalize_ports(expected_ports):
    """Frozenset of valid ports; anything doubtful is the empty set (deny all).

    An iterator is its own iterator and can be consumed only once, so it would
    silently change the answer between calls; it is refused rather than drained.
    """
    if isinstance(expected_ports, int) and not isinstance(expected_ports, bool):
        expected_ports = (expected_ports,)
    if isinstance(expected_ports, (str, bytes, bytearray, memoryview)):
        return frozenset()
    try:
        if iter(expected_ports) is expected_ports:
            return frozenset()
        ports = set()
        for n, p in enumerate(expected_ports):
            if n >= _MAX_PORT_ITEMS:
                return frozenset()
            if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
                return frozenset()
            ports.add(p)
            if len(ports) > MAX_PORTS:
                return frozenset()
    except TypeError:
        return frozenset()
    return frozenset(ports)


def host_allowed(host_header, expected_ports):
    if not isinstance(host_header, str) or len(host_header) > 64:
        return False
    if not host_header.isascii():
        return False
    m = _HOST.fullmatch(host_header.translate(_ASCII_LOWER))
    if not m:
        return False
    port = int(m.group(1))
    return port <= 65535 and port in _normalize_ports(expected_ports)


def target_allowed(target):
    if not isinstance(target, str) or not 0 < len(target) <= MAX_TARGET:
        return False
    if target[0] != "/" or target.startswith("//"):
        return False
    if any(not 0x21 <= ord(c) <= 0x7E for c in target):
        return False
    if "\\" in target or "#" in target:
        return False
    path = target.split("?", 1)[0]
    # Fixed ASCII routes never need percent-encoding, so any '%' is an evasion attempt.
    if "%" in path:
        return False
    return not any(seg in (".", "..") for seg in path.split("/"))


def _clean_headers(headers):
    if not isinstance(headers, (list, tuple)) or len(headers) > MAX_HEADERS:
        return None
    out = {}
    for pair in headers:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            return None
        name, value = pair
        if not isinstance(name, str) or not isinstance(value, str):
            return None
        if not _HEADER_NAME.fullmatch(name) or len(value) > MAX_HEADER_VALUE:
            return None
        if any((ord(c) < 0x20 and c != "\t") or ord(c) == 0x7F for c in value):
            return None
        out.setdefault(name.translate(_ASCII_LOWER), []).append(value)
    return out


def _token(value):
    # HTTP trims only space and tab; str.strip()/lower() would also act on Unicode.
    return value.strip(" \t").translate(_ASCII_LOWER)


def _fetch_metadata_bad(h):
    if any(_token(v) != "none" for v in h.get("sec-fetch-site", ())):
        return True
    return any(_token(v) in ("cors", "no-cors") for v in h.get("sec-fetch-mode", ()))


def _check_body_headers(h):
    cl = h.get("content-length")
    if not cl:
        return _deny(411, "length_required")
    if not _CONTENT_LENGTH.fullmatch(cl[0]):
        return _BAD_REQUEST
    if int(cl[0]) > BODY_CAP:
        return _deny(413, "payload_too_large")
    ct = h.get("content-type")
    if not ct or not _CONTENT_TYPE.fullmatch(ct[0]):
        return _deny(415, "unsupported_media_type")
    return None


def _evaluate(method, target, headers, expected_ports, token):
    if method not in ("GET", "POST"):
        return _deny(405, "method_not_allowed")
    if not target_allowed(target):
        return _BAD_REQUEST
    h = _clean_headers(headers)
    if h is None:
        return _BAD_REQUEST
    if any(len(h.get(k, ())) > 1 for k in ("host", "content-length", "content-type")):
        return _BAD_REQUEST
    if "transfer-encoding" in h:
        return _deny(501, "not_implemented")
    hosts = h.get("host", ())
    if len(hosts) != 1 or not host_allowed(hosts[0], expected_ports):
        return _deny(421, "bad_host")
    if "origin" in h:
        return _deny(403, "forbidden_origin")
    if _fetch_metadata_bad(h):
        return _deny(403, "forbidden_fetch_site")
    if method == "GET" and any(v != "0" for v in h.get("content-length", ())):
        return _BAD_REQUEST

    path = target.split("?", 1)[0]
    if (method, path) == _UNAUTHENTICATED:
        return Decision(True, 200, "ok", f"{method} {path}")

    auth = h.get("authorization", ())
    presented = parse_bearer(auth[0]) if len(auth) == 1 else None
    if not compare_token(presented, token):
        return _deny(401, "invalid_api_key")

    methods = _ROUTES.get(path)
    if methods is None:
        return _deny(404, "not_found")
    if method not in methods:
        return _deny(405, "method_not_allowed")
    if method == "POST":
        bad = _check_body_headers(h)
        if bad is not None:
            return bad
    return Decision(True, 200, "ok", f"{method} {path}")


def check_request(method, target, headers, *, expected_ports, token):
    """Admit or reject a request from its parsed line and raw ordered headers.

    ``headers`` is the list of (name, value) pairs exactly as received, so
    duplicates, case and folding stay visible.  Never raises; anything it
    cannot interpret is a 400.
    """
    try:
        return _evaluate(method, target, headers, expected_ports, token)
    except Exception:
        return _BAD_REQUEST


def check_text_length(n):
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        return _BAD_REQUEST
    if n > TEXT_CAP:
        return _deny(413, "payload_too_large")
    return Decision(True, 200, "ok")
