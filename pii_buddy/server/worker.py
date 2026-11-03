"""Killable worker processes: the real bound on request time.

``core`` has no latency bound, and spaCy can run for minutes on hostile input.
``ProcessPoolExecutor`` cannot bound it: ``future.result(timeout=...)`` leaves
the job burning CPU, and killing one of its workers raises BrokenProcessPool
for every sibling.  So each worker here is a single spawned process over its
own pipe.  On a deadline the worker is SIGKILLed and replaced, nothing else is
touched, and the caller gets a fixed response with no partial output.

There is no queue.  If no worker is idle the answer is 503 at once.
"""

import multiprocessing
import os
import queue
import resource
import signal
import sys
import threading
import time

from .. import detector
from . import protocol

DEFAULT_TIMEOUT = 30.0
READY_TIMEOUT = 120.0
RESPAWN_BACKOFF = 1.0

_RETRY_AFTER = ("Retry-After", "1")
_READY = "ready"
_FAILED = "failed"


class WorkerStartError(RuntimeError):
    """A worker never became ready; the message never holds child output."""


def _handle(route, body, request_id):
    usage = protocol.UsageCounter()
    response = protocol.handle(route, body, request_id=request_id, usage=usage)
    return response, usage.requests_served > 0


def _quiet_child():
    """Nothing a dependency prints or a traceback holds may reach a log."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    sink = os.open(os.devnull, os.O_WRONLY)
    os.dup2(sink, 1)
    os.dup2(sink, 2)
    os.close(sink)
    sys.stdout = sys.stderr = open(os.devnull, "w")


def _child(conn, handler, init):
    _quiet_child()
    os.environ["OMP_NUM_THREADS"] = "1"
    try:
        if init is not None:
            init()
    except Exception:
        conn.send(_FAILED)
        return
    conn.send(_READY)
    while True:
        try:
            route, body, request_id = conn.recv()
        except (EOFError, OSError):
            return  # the parent is gone
        try:
            out = handler(route, body, request_id)
        except Exception as exc:
            out = (None, protocol._safe_name(type(exc).__name__))
        conn.send(out)


class _Worker:
    def __init__(self, ctx, handler, init):
        self.conn, child = ctx.Pipe()
        self.proc = ctx.Process(target=_child, args=(child, handler, init), daemon=True)
        self.proc.start()
        child.close()

    def wait_ready(self, seconds):
        if not self.conn.poll(seconds):
            return False
        try:
            return self.conn.recv() == _READY
        except (EOFError, OSError):
            return False

    def kill(self):
        self.proc.kill()
        self.proc.join()
        self.conn.close()


class WorkerPool:
    def __init__(self, size, *, timeout=DEFAULT_TIMEOUT, handler=_handle,
                 init=detector.preflight, ready_timeout=READY_TIMEOUT,
                 spawn_delay=0.0):
        self.size = size
        self.timeout = timeout
        self.usage = protocol.UsageCounter()
        self._handler = handler
        self._init = init
        self._ready_timeout = ready_timeout
        self._spawn_delay = spawn_delay
        self._ctx = multiprocessing.get_context("spawn")
        self._idle = queue.Queue()
        self._lock = threading.Lock()
        self._workers = set()
        self._closed = False

    def start(self):
        for _ in range(self.size):
            w = _Worker(self._ctx, self._handler, self._init)
            with self._lock:
                self._workers.add(w)
            if not w.wait_ready(self._ready_timeout):
                self.close()
                raise WorkerStartError("worker did not become ready")
            self._idle.put(w)

    def idle(self):
        return self._idle.qsize()

    def pids(self):
        with self._lock:
            return [w.proc.pid for w in self._workers]

    def call(self, route, body, request_id):
        try:
            w = self._idle.get_nowait()
        except queue.Empty:
            return self._busy(route, request_id)
        try:
            w.conn.send((route, body, request_id))
            if not w.conn.poll(self.timeout):
                self._replace(w)
                return protocol.failure(route, request_id, "timeout")
            response, counted = w.conn.recv()
        except (EOFError, OSError):
            self._replace(w)
            return protocol.failure(route, request_id, "internal_error",
                                    exc_type="WorkerDied")
        self._idle.put(w)
        if response is None:
            return protocol.failure(route, request_id, "internal_error", exc_type=counted)
        if type(response) is not protocol.Response:
            return protocol.failure(route, request_id, "internal_error",
                                    exc_type="BadWorkerResponse")
        if counted:
            self.usage.increment()
        return response

    def _busy(self, route, request_id):
        r = protocol.failure(route, request_id, "busy")
        if r.status != 503:
            return r
        return protocol.Response(r.status, r.body, r.headers + (_RETRY_AFTER,), r.diag)

    def _replace(self, dead):
        with self._lock:
            self._workers.discard(dead)
        dead.kill()
        threading.Thread(target=self._respawn, daemon=True).start()

    def _respawn(self):
        time.sleep(self._spawn_delay)
        while True:
            with self._lock:
                if self._closed:
                    return
            w = _Worker(self._ctx, self._handler, self._init)
            with self._lock:
                self._workers.add(w)
            if w.wait_ready(self._ready_timeout):
                with self._lock:
                    if not self._closed:
                        self._idle.put(w)
                        return
            with self._lock:
                self._workers.discard(w)
            w.kill()
            time.sleep(RESPAWN_BACKOFF)

    def close(self):
        with self._lock:
            self._closed = True
            workers, self._workers = self._workers, set()
        while True:
            try:
                self._idle.get_nowait()
            except queue.Empty:
                break
        for w in workers:
            w.kill()
