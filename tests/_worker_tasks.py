"""Module-level handlers for the worker-pool tests; spawn must import them."""

import ctypes
import os
import resource
import signal
import sys
import threading
import time

from pii_buddy.server import protocol

# Read at import, which in a spawned child is before the worker code runs.
OMP_AT_IMPORT = os.environ.get("OMP_NUM_THREADS")
INIT_SLEEP = "PII_BUDDY_TEST_INIT_SLEEP"
DIE_AFTER_READY = "PII_BUDDY_TEST_DIE_AFTER_READY"
PR_GET_DUMPABLE = 3


class Abort(BaseException):
    pass


def _detonate(kind):
    raise Abort() if kind == "base" else RuntimeError("bad pickle Zq7f3a9cXk")


class Bomb:
    """Pickles in the child; unpickling in the parent raises."""

    def __init__(self, kind):
        self.kind = kind

    def __reduce__(self):
        return (_detonate, (self.kind,))


def _ok(body):
    return protocol.Response(200, body or b"{}", protocol.HEADERS)


def echo(route, body, request_id):
    return _ok(body), True


def uncounted(route, body, request_id):
    return _ok(body), False


def behave(route, body, request_id):
    """The body names what to do, so one pool can mix behaviours."""
    if body == b"spin":
        while True:
            pass
    if body == b"stubborn":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        while True:
            pass
    if body == b"sleep":
        time.sleep(60)
    if body == b"slow":
        time.sleep(1.5)
    if body == b"exit":
        os._exit(3)
    if body == b"sysexit":
        sys.exit(1)
    if body == b"segv":
        os.kill(os.getpid(), signal.SIGSEGV)
    if body == b"raise":
        raise RuntimeError("secret Zq7f3a9cXk")
    if body == b"garbage":
        return "not a response", True
    if body == b"pid":
        return _ok(str(os.getpid()).encode()), False
    if body == b"print":
        print("Zq7f3a9cXk")
        print("Zq7f3a9cXk", file=sys.stderr)
    if body == b"oswrite":
        os.write(1, b"Zq7f3a9cXk\n")
        os.write(2, b"Zq7f3a9cXk\n")
    if body == b"triple":
        return _ok(b"{}"), True, 1
    if body in (b"bomb", b"basebomb"):
        return Bomb("base" if body == b"basebomb" else "plain"), True
    if body == b"big":
        return _ok(b"x" * (8 << 20)), False
    if body == b"env":
        return _ok(str(OMP_AT_IMPORT).encode()), False
    if body == b"rlimit":
        return _ok(repr(resource.getrlimit(resource.RLIMIT_CORE)).encode()), False
    if body == b"aslimit":
        return _ok(repr(resource.getrlimit(resource.RLIMIT_AS)).encode()), False
    if body == b"dumpable":
        libc = ctypes.CDLL(None, use_errno=True)
        return _ok(str(libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)).encode()), False
    if body == b"oom":
        with open("/proc/self/oom_score_adj") as f:
            return _ok(f.read().strip().encode()), False
    return _ok(body), True


def sleepy_init():
    """Slow only when the test asks, so a respawn can be caught mid-start."""
    time.sleep(float(os.environ.get(INIT_SLEEP, "0")))


def die_soon_init():
    """Dies just after ready while the test asks: an OOM kill right after the
    model load looks like this."""
    delay = os.environ.get(DIE_AFTER_READY)
    if delay is not None:
        threading.Timer(float(delay), os._exit, (0,)).start()


def failing_init():
    raise RuntimeError("no model")
