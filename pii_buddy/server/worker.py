"""Killable worker processes: the real bound on request time.

``core`` has no latency bound, and spaCy can run for minutes on hostile input.
``ProcessPoolExecutor`` cannot bound it: ``future.result(timeout=...)`` leaves
the job burning CPU, and killing one of its workers raises BrokenProcessPool
for every sibling.  So each worker here is a single spawned process over its
own pipe.  On a deadline the worker is SIGKILLed and replaced, nothing else is
touched, and the caller gets a fixed response with no partial output.

There is no queue.  If no worker is idle the answer is 503 at once.

A worker's pipe is closed only by the thread that holds the worker (the
caller during a request, the slot thread while it starts, ``close`` while it
is idle); any thread may kill the process, which turns a blocked read into EOF.
Closing a descriptor under another thread's read can hand it a reused one.
"""

import ctypes
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
RESPAWN_BACKOFF_MAX = 60.0

_RETRY_AFTER = ("Retry-After", "1")
_READY = "ready"
_FAILED = "failed"
_TIMED_OUT = object()

_LINUX = sys.platform.startswith("linux")
_PR_SET_PDEATHSIG = 1
_OOM_SCORE_ADJ = "/proc/self/oom_score_adj"
_ENV_LOCK = threading.Lock()


class WorkerStartError(RuntimeError):
    """A worker never became ready; the message never holds child output."""


def _handle(route, body, request_id):
    usage = protocol.UsageCounter()
    response = protocol.handle(route, body, request_id=request_id, usage=usage)
    return response, usage.requests_served > 0


def _backoff(failures):
    return min(RESPAWN_BACKOFF * 2 ** min(failures - 1, 16), RESPAWN_BACKOFF_MAX)


def _die_with_parent(parent_pid):
    """A computing child never reads its pipe, so it never sees the EOF a dead
    parent leaves, and a watchdog thread in it cannot run while spaCy holds the
    GIL.  On Linux the kernel kills it instead.  macOS has no equivalent: there
    an orphan runs until its current request ends, then exits on EOF."""
    if _LINUX:
        try:
            ctypes.CDLL(None, use_errno=True).prctl(
                _PR_SET_PDEATHSIG, ctypes.c_ulong(signal.SIGKILL),
                ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
        except Exception:
            pass
    if os.getppid() != parent_pid:
        os._exit(0)  # the parent died before prctl took effect


def _quiet_child():
    """Nothing a dependency prints or a traceback holds may reach a log."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    sink = os.open(os.devnull, os.O_WRONLY)
    os.dup2(sink, 1)
    os.dup2(sink, 2)
    os.close(sink)
    sys.stdout = sys.stderr = open(os.devnull, "w")


def _limit_child(mem_limit_bytes):
    """The box has no swap and runs production sites: under memory pressure
    the kernel must pick a worker.  RLIMIT_AS is off by default because spaCy
    maps far more virtual memory than it uses; macOS refuses it outright."""
    try:
        with open(_OOM_SCORE_ADJ, "w") as f:
            f.write("1000")
    except OSError:
        pass
    if mem_limit_bytes is not None:
        resource.setrlimit(resource.RLIMIT_AS, (mem_limit_bytes, mem_limit_bytes))


def _child(conn, handler, init, parent_pid, mem_limit_bytes):
    _die_with_parent(parent_pid)
    _quiet_child()
    try:
        _limit_child(mem_limit_bytes)
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


def _start_single_threaded(proc):
    # OpenMP and BLAS read this when they load, which in a spawned child can
    # be while unpickling, before _child runs.
    with _ENV_LOCK:
        saved = os.environ.get("OMP_NUM_THREADS")
        os.environ["OMP_NUM_THREADS"] = "1"
        try:
            proc.start()
        finally:
            if saved is None:
                del os.environ["OMP_NUM_THREADS"]
            else:
                os.environ["OMP_NUM_THREADS"] = saved


class _Worker:
    def __init__(self, ctx, handler, init, mem_limit_bytes=None):
        self.dead = False
        self.gone = threading.Event()
        self._lock = threading.Lock()
        self.conn, child = ctx.Pipe()
        try:
            self.proc = ctx.Process(
                target=_child, args=(child, handler, init, os.getpid(), mem_limit_bytes),
                daemon=True)
            _start_single_threaded(self.proc)
        except BaseException:
            self.conn.close()
            raise
        finally:
            child.close()

    def wait_ready(self, seconds):
        try:
            return self.conn.poll(seconds) and self.conn.recv() == _READY
        except (EOFError, OSError):
            return False

    def kill(self):
        with self._lock:
            if self.dead:
                return
            self.dead = True
            self.proc.kill()
            self.proc.join()

    def discard(self):
        """Holder only: see the module docstring."""
        self.kill()
        with self._lock:
            self.conn.close()
        self.gone.set()


class WorkerPool:
    def __init__(self, size, *, timeout=DEFAULT_TIMEOUT, handler=_handle,
                 init=detector.preflight, ready_timeout=READY_TIMEOUT,
                 spawn_delay=0.0, mem_limit_bytes=None):
        self.size = size
        self.timeout = timeout
        self.usage = protocol.UsageCounter()
        self._failures = {}  # slot thread -> its consecutive failed respawns
        self._handler = handler
        self._init = init
        self._ready_timeout = ready_timeout
        self._spawn_delay = spawn_delay
        self._mem_limit_bytes = mem_limit_bytes
        self._ctx = multiprocessing.get_context("spawn")
        self._idle = queue.Queue()
        self._lock = threading.Lock()
        self._workers = set()
        self._stop = threading.Event()

    def start(self):
        started = queue.Queue()
        try:
            for _ in range(self.size):
                threading.Thread(target=self._slot, args=(started,), daemon=True).start()
            for _ in range(self.size):
                if not started.get():
                    raise WorkerStartError("worker did not become ready")
        except BaseException:
            self.close()
            raise

    def idle(self):
        return self._idle.qsize()

    @property
    def respawn_failures(self):
        """Consecutive failed respawns, summed over the slots now failing."""
        with self._lock:
            return sum(self._failures.values())

    def healthy(self):
        """False while any slot's respawns are failing, or once closed."""
        return not self._stop.is_set() and self.respawn_failures == 0

    def pids(self):
        with self._lock:
            return [w.proc.pid for w in self._workers]

    def call(self, route, body, request_id):
        w = self._take()
        if w is None:
            return self._busy(route, request_id)
        bad = None
        try:
            reply = self._ask(w, (route, body, request_id))
            if reply is not _TIMED_OUT:
                response, counted = reply
        except (EOFError, OSError):
            bad = "WorkerDied"
        except Exception:
            bad = "BadWorkerResponse"
        except BaseException:
            self._replace(w)
            raise
        if bad is not None:
            self._replace(w)
            return protocol.failure(route, request_id, "internal_error", exc_type=bad)
        if reply is _TIMED_OUT:
            self._replace(w)
            return protocol.failure(route, request_id, "timeout")
        self._release(w)
        if response is None:
            return protocol.failure(route, request_id, "internal_error", exc_type=counted)
        if type(response) is not protocol.Response:
            return protocol.failure(route, request_id, "internal_error",
                                    exc_type="BadWorkerResponse")
        if counted:
            self.usage.increment()
        return response

    def _take(self):
        for _ in range(self.size):
            try:
                w = self._idle.get_nowait()
            except queue.Empty:
                return None
            if w.proc.is_alive():
                return w
            self._replace(w)  # died idle: the OOM killer picks workers first
        return None

    def _ask(self, w, msg):
        """The deadline covers the whole reply: a child that stalls after its
        first byte would otherwise hold recv() forever."""
        deadline = time.monotonic() + self.timeout
        w.conn.send(msg)
        if not w.conn.poll(self.timeout):
            return _TIMED_OUT
        late = threading.Event()

        def expire():
            late.set()
            w.kill()

        timer = threading.Timer(max(0.0, deadline - time.monotonic()), expire)
        timer.daemon = True
        timer.start()
        try:
            return w.conn.recv()
        except (EOFError, OSError):
            if late.is_set():
                return _TIMED_OUT
            raise
        finally:
            timer.cancel()
            timer.join()

    def _busy(self, route, request_id):
        r = protocol.failure(route, request_id, "busy")
        if r.status != 503:
            return r
        return protocol.Response(r.status, r.body, r.headers + (_RETRY_AFTER,), r.diag)

    def _release(self, w):
        with self._lock:
            if not (self._stop.is_set() or w.dead):
                self._idle.put(w)
                return
        self._replace(w)

    def _replace(self, w):
        with self._lock:
            self._workers.discard(w)
        w.discard()

    def _slot(self, started):
        """One long-lived thread per slot does every spawn for it, because
        PR_SET_PDEATHSIG fires when the thread that forked the child exits,
        not the process."""
        w = self._spawn()
        started.put(w is not None)
        while w is not None:
            w.gone.wait()
            if self._stop.wait(self._spawn_delay):
                return
            failures = 0
            while True:
                w = self._spawn()
                if w is not None or self._stop.is_set():
                    break
                failures += 1
                with self._lock:
                    self._failures[threading.current_thread()] = failures
                if self._stop.wait(_backoff(failures)):
                    return

    def _spawn(self):
        """-> a ready worker, already idle, or None.  Never raises: a spawn
        that fails (EMFILE, EAGAIN, ENOMEM) must not lose the slot."""
        w = None
        try:
            w = _Worker(self._ctx, self._handler, self._init, self._mem_limit_bytes)
            with self._lock:
                live = not self._stop.is_set()
                if live:
                    self._workers.add(w)
            if live and w.wait_ready(self._ready_timeout):
                with self._lock:
                    if not self._stop.is_set():
                        self._failures.pop(threading.current_thread(), None)
                        self._idle.put(w)
                        return w
        except Exception:
            pass
        if w is not None:
            self._replace(w)
        return None

    def close(self):
        with self._lock:
            self._stop.set()
            workers, self._workers = self._workers, set()
        for w in workers:
            w.kill()
        while True:
            try:
                w = self._idle.get_nowait()
            except queue.Empty:
                break
            w.discard()
