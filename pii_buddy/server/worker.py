"""Killable worker processes: the real bound on request time.

``core`` has no latency bound, and spaCy can run for minutes on hostile input.
``ProcessPoolExecutor`` cannot bound it: ``future.result(timeout=...)`` leaves
the job burning CPU, and killing one of its workers raises BrokenProcessPool
for every sibling.  So each worker here is a single spawned process over its
own pipe.  On a deadline the worker is SIGKILLed and replaced, nothing else is
touched, and the caller gets a fixed response with no partial output.

There is no queue.  If no worker is idle the answer is 503 at once.

A worker's pipe is closed only by the thread that holds the worker (the
caller during a request, the slot thread while it starts or once it died idle,
``close`` while it is idle); any thread may kill the process, which turns a
blocked read into EOF.  Who holds an idle worker is decided under the pool
lock: it leaves ``_idle`` exactly once.
Closing a descriptor under another thread's read can hand it a reused one.
"""

import atexit
import collections
import ctypes
import multiprocessing
import multiprocessing.connection
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
_PR_SET_DUMPABLE = 4
_OOM_SCORE_ADJ = "/proc/self/oom_score_adj"


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


def _no_core_dumps():
    """A core holds request text.  A piped core_pattern (apport,
    systemd-coredump) ignores RLIMIT_CORE, so on Linux the process is also
    made non-dumpable, which also bars same-uid ptrace and /proc/<pid>/mem.
    Failing to do that fails the worker: it has not read a request yet."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if _LINUX:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_DUMPABLE, ctypes.c_ulong(0), ctypes.c_ulong(0),
                      ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE")


def _child(conn, handler, init, parent_pid, mem_limit_bytes):
    _die_with_parent(parent_pid)
    _quiet_child()
    try:
        _limit_child(mem_limit_bytes)  # first: a non-dumpable /proc/self is root's
        _no_core_dumps()
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
    def __init__(self, ctx, handler, init, mem_limit_bytes=None):
        self.dead = False
        self.orphaned = False  # died while held: the holder must not requeue it
        self.gone = threading.Event()
        self._lock = threading.Lock()
        self.conn, child = ctx.Pipe()
        try:
            self.proc = ctx.Process(
                target=_child, args=(child, handler, init, os.getpid(), mem_limit_bytes),
                daemon=True)
            self.proc.start()
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
        self._idle = collections.deque()  # under _lock
        self._lock = threading.Lock()
        self._workers = set()
        self._stop = threading.Event()

    def start(self):
        # OpenMP and BLAS read this when they load, which in a spawned child
        # can be while unpickling, before _child runs.  Spawn has no per-child
        # env, so it is set once here, before any slot thread exists:
        # rewriting os.environ around each spawn raced every other thread.
        os.environ["OMP_NUM_THREADS"] = "1"
        # Before multiprocessing's own exit hook (atexit is LIFO) terminates
        # the daemon workers, which the slot threads would see and respawn.
        atexit.register(self.close)
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
        with self._lock:
            return len(self._idle)

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
            with self._lock:
                if not self._idle:
                    return None
                w = self._idle.popleft()
            if not _exited(w):
                return w
            self._replace(w)  # died before its slot thread noticed
        return None

    def _ask(self, w, msg):
        """The deadline covers the whole reply: a child that stalls after its
        first byte would otherwise hold recv() forever."""
        deadline = time.monotonic() + self.timeout
        w.conn.send(msg)
        if not w.conn.poll(max(0.0, deadline - time.monotonic())):
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
            if not (self._stop.is_set() or w.dead or w.orphaned):
                self._idle.append(w)
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
            self._await_death(w)
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

    def _await_death(self, w):
        """Returns once w is discarded or the pool is closing.  The sentinel fires whether the child
        was killed by its holder or died on its own while idle (the OOM
        killer's first pick), so an idle death is replaced at once instead of
        surfacing as a 503 on the next request."""
        multiprocessing.connection.wait([w.proc.sentinel])
        with self._lock:
            if self._stop.is_set():
                return  # close() owns every worker now
            mine = w in self._idle
            if mine:
                self._idle.remove(w)
            else:
                w.orphaned = True
        if mine:
            self._replace(w)
        else:
            w.gone.wait()  # its holder sees EOF or orphaned, then discards it

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
                        self._idle.append(w)
                        return w
        except Exception:
            pass
        if w is not None:
            self._replace(w)
        return None

    def close(self):
        atexit.unregister(self.close)
        with self._lock:
            self._stop.set()
            workers, self._workers = self._workers, set()
            idle, self._idle = list(self._idle), collections.deque()
        for w in workers:
            w.kill()
        for w in idle:
            w.discard()


def _exited(w):
    """The sentinel, not is_alive(): is_alive() reaps with waitpid, which
    another thread's kill() may be doing at the same moment."""
    return bool(multiprocessing.connection.wait([w.proc.sentinel], 0))
