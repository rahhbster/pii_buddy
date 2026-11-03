"""Module-level handlers for the worker-pool tests; spawn must import them."""

import os
import signal
import sys
import time

from pii_buddy.server import protocol


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
    return _ok(body), True


def failing_init():
    raise RuntimeError("no model")
