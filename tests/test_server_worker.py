"""WorkerPool: the real bound on request time.  Workers are real spawned
processes, because the behaviours under test (kill, crash, sibling survival)
do not exist in-process.  Handlers live in ``tests._worker_tasks``."""

import errno
import json
import multiprocessing
import os
import resource
import signal
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from pii_buddy.server import protocol, worker
from tests import _worker_tasks as tasks

CANARY = "Zq7f3a9cXk"
ROUTE = "POST /v1/check"
RID = "r_00ab12cd"


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A killed child stays a zombie until reaped; reaped means really gone.
    return True


def wait_until(check, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def pool():
    made = []

    def _make(size=1, *, timeout=2.0, handler=tasks.behave, **kw):
        p = worker.WorkerPool(size, timeout=timeout, handler=handler, init=None, **kw)
        p.start()
        made.append(p)
        return p

    yield _make
    for p in made:
        p.close()


def pid_of(p):
    return int(p.call(ROUTE, b"pid", RID).body)


def ready(p, n=None, seconds=30):
    return wait_until(lambda: p.idle() == (p.size if n is None else n), seconds)


@pytest.fixture
def thread_errors(monkeypatch):
    errs = []
    monkeypatch.setattr(threading, "excepthook", lambda a: errs.append(repr(a.exc_value)))
    return errs


@pytest.fixture
def spawns(monkeypatch):
    """Wraps _Worker: ``fail(n)`` says whether spawn number n raises EMFILE."""
    real = worker._Worker
    made, lock = [], threading.Lock()
    state = {"fail": lambda n: False, "after": lambda n, w: None, "n": 0}

    def make(*a, **kw):
        with lock:
            n = state["n"]
            state["n"] += 1
            state["at"] = state.get("at", []) + [time.monotonic()]
            state["who"] = state.get("who", []) + [threading.current_thread()]
        if state["fail"](n):
            raise OSError(errno.EMFILE, "Too many open files")
        w = real(*a, **kw)
        w.slot = threading.current_thread()
        made.append(w)
        state["after"](n, w)
        return w

    monkeypatch.setattr(worker, "_Worker", make)
    state["made"] = made
    return state


def run_script(body, timeout=60):
    script = "import os, sys, time\nfrom pii_buddy.server import worker\n" \
             "from tests import _worker_tasks as tasks\n" \
             "if __name__ == '__main__':\n" + textwrap.indent(textwrap.dedent(body), "    ")
    return subprocess.run([sys.executable, "-c", script], capture_output=True,
                          text=True, timeout=timeout)


class TestHappyPath:
    def test_response_round_trips_intact(self, pool):
        p = pool()
        r = p.call(ROUTE, b'{"a":1}', RID)
        assert type(r) is protocol.Response
        assert (r.status, r.body, r.diag) == (200, b'{"a":1}', None)
        assert p.idle() == 1

    def test_counted_requests_reach_the_parent_counter(self, pool):
        p = pool(handler=tasks.echo)
        p.call(ROUTE, b"", RID)
        p.call(ROUTE, b"", RID)
        assert p.usage.requests_served == 2

    def test_uncounted_requests_do_not(self, pool):
        p = pool(handler=tasks.uncounted)
        p.call(ROUTE, b"", RID)
        assert p.usage.requests_served == 0

    def test_a_worker_is_reused_between_requests(self, pool):
        p = pool()
        assert pid_of(p) == pid_of(p)

    def test_workers_are_separate_processes(self, pool):
        p = pool()
        assert pid_of(p) != os.getpid()


class TestTimeoutReallyStopsTheWork:
    @pytest.mark.parametrize("what", [b"spin", b"sleep"])
    def test_overrun_answers_on_time_and_the_worker_is_dead(self, pool, what):
        p = pool(timeout=1.0)
        pid = pid_of(p)
        t0 = time.monotonic()
        r = p.call(ROUTE, what, RID)
        took = time.monotonic() - t0
        assert (r.status, r.diag.code) == (504, "timeout")
        assert json.loads(r.body)["error"] == "timeout"
        assert 0.9 < took < 2.5
        assert wait_until(lambda: not alive(pid), 5)
        assert ready(p)
        assert pid_of(p) != pid

    def test_sibling_mid_request_survives_a_kill(self, pool):
        p = pool(2, timeout=1.0)
        out = {}
        t = threading.Thread(
            target=lambda: out.update(r=p.call(ROUTE, b"spin", RID)))
        t.start()
        time.sleep(0.2)
        p2 = threading.Thread(
            target=lambda: out.update(s=p.call(ROUTE, b"ok", RID)))
        p2.start()
        t.join(5)
        p2.join(5)
        assert out["r"].diag.code == "timeout"
        assert (out["s"].status, out["s"].body) == (200, b"ok")

    def test_requests_during_respawn_are_busy_not_hung(self, pool):
        p = pool(timeout=0.5, spawn_delay=1.5)
        assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        t0 = time.monotonic()
        r = p.call(ROUTE, b"ok", RID)
        assert (r.status, r.diag.code) == (503, "busy")
        time.sleep(0.9)
        assert p.call(ROUTE, b"ok", RID).diag.code == "busy"
        assert ready(p)
        assert time.monotonic() - t0 > 1.4
        assert p.call(ROUTE, b"ok", RID).status == 200

    def test_a_dead_idle_worker_is_skipped_not_answered_with_500(self, pool):
        p = pool(2)
        dead = p._idle.queue[0].proc.pid
        os.kill(dead, signal.SIGKILL)
        time.sleep(0.3)
        r = p.call(ROUTE, b"ok", RID)
        assert (r.status, r.body) == (200, b"ok")
        assert ready(p, seconds=5)
        assert dead not in p.pids()

    def test_when_every_idle_worker_is_dead_the_answer_is_busy(self, pool):
        p = pool(2)
        pids = p.pids()
        for pid in pids:
            os.kill(pid, signal.SIGKILL)
        time.sleep(0.3)
        assert p.call(ROUTE, b"ok", RID).diag.code == "busy"
        assert ready(p, seconds=5)
        assert not set(pids) & set(p.pids())
        assert p.call(ROUTE, b"ok", RID).status == 200

    def test_repeated_kills_do_not_leak_workers_or_shrink_the_pool(self, pool):
        p = pool(2, timeout=0.4)
        for _ in range(5):
            assert wait_until(lambda: p.idle() > 0, 10)
            assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        assert ready(p)
        assert len(p.pids()) == 2
        assert p.call(ROUTE, b"ok", RID).status == 200


class TestWorkerDeath:
    @pytest.mark.parametrize("what", [b"exit", b"sysexit", b"segv"])
    def test_crash_is_a_fixed_500_then_the_pool_recovers(self, pool, what):
        p = pool()
        r = p.call(ROUTE, what, RID)
        assert (r.status, r.diag.code) == (500, "internal_error")
        assert r.diag.exc_type == "WorkerDied"
        assert CANARY.encode() not in r.body
        assert ready(p)
        assert p.call(ROUTE, b"ok", RID).status == 200

    def test_handler_exception_never_crosses_with_its_text(self, pool):
        p = pool()
        r = p.call(ROUTE, b"raise", RID)
        assert (r.status, r.diag.code) == (500, "internal_error")
        assert r.diag.exc_type == "RuntimeError"
        assert CANARY.encode() not in r.body
        assert CANARY not in repr(r)
        assert ready(p)

    def test_handler_returning_garbage_is_a_fixed_500(self, pool):
        p = pool()
        r = p.call(ROUTE, b"garbage", RID)
        assert (r.status, r.diag.code) == (500, "internal_error")


class TestCapacity:
    def test_no_queue_when_every_worker_is_busy(self, pool):
        p = pool(1, timeout=5.0)
        t = threading.Thread(target=lambda: p.call(ROUTE, b"slow", RID))
        t.start()
        assert wait_until(lambda: p.idle() == 0, 5)
        t0 = time.monotonic()
        r = p.call(ROUTE, b"ok", RID)
        assert time.monotonic() - t0 < 0.2
        assert (r.status, r.diag.code) == (503, "busy")
        assert ("Retry-After", "1") in r.headers
        t.join(5)
        assert p.call(ROUTE, b"ok", RID).status == 200

    def test_a_rest_timeout_is_504_without_retry_after(self, pool):
        r = pool(timeout=0.5).call(ROUTE, b"spin", RID)
        assert (r.status, r.diag.code) == (504, "timeout")
        assert json.loads(r.body)["error"] == "timeout"
        assert not any(k.lower() == "retry-after" for k, _ in r.headers)

    def test_mcp_failures_are_json_rpc_shaped(self, pool):
        p = pool(timeout=0.5)
        r = p.call("POST /mcp", b"spin", RID)
        assert r.status == 500
        assert json.loads(r.body)["error"]["code"] == -32603


class TestChildOutputAndLifecycle:
    def test_child_stdout_and_stderr_go_nowhere(self):
        script = textwrap.dedent("""
            from pii_buddy.server import worker
            from tests import _worker_tasks as tasks
            if __name__ == "__main__":
                p = worker.WorkerPool(1, timeout=5, handler=tasks.behave, init=None)
                p.start()
                p.call("POST /v1/check", b"print", "r_1")
                p.call("POST /v1/check", b"raise", "r_1")
                p.close()
        """)
        out = subprocess.run([sys.executable, "-c", script], capture_output=True,
                             text=True, timeout=60)
        assert out.returncode == 0, out.stderr[-500:]
        assert CANARY not in out.stdout and CANARY not in out.stderr

    def test_workers_exit_when_the_parent_is_killed(self):
        script = textwrap.dedent("""
            import os, sys, time
            from pii_buddy.server import worker
            from tests import _worker_tasks as tasks
            if __name__ == "__main__":
                p = worker.WorkerPool(1, timeout=5, handler=tasks.behave, init=None)
                p.start()
                print(p.pids()[0], flush=True)
                time.sleep(60)
        """)
        proc = subprocess.Popen([sys.executable, "-c", script],
                                stdout=subprocess.PIPE, text=True)
        pid = int(proc.stdout.readline())
        proc.kill()
        proc.wait()
        assert wait_until(lambda: not alive(pid), 10)

    def test_close_stops_every_worker_and_later_calls_are_busy(self):
        p = worker.WorkerPool(2, timeout=2.0, handler=tasks.behave, init=None)
        p.start()
        pids = p.pids()
        p.close()
        assert wait_until(lambda: not any(alive(x) for x in pids), 5)
        assert p.call(ROUTE, b"ok", RID).diag.code == "busy"
        p.close()

    def test_failing_init_fails_start_without_echoing(self):
        p = worker.WorkerPool(1, timeout=2.0, handler=tasks.behave,
                              init=tasks.failing_init, ready_timeout=30)
        with pytest.raises(worker.WorkerStartError) as e:
            p.start()
        assert "no model" not in str(e.value)
        p.close()


class TestRealCore:
    def test_the_worst_known_input_is_killed_on_time(self):
        p = worker.WorkerPool(1, timeout=3.0)
        p.start()
        try:
            body = json.dumps({"text": "!" * 50_000}).encode()
            t0 = time.monotonic()
            r = p.call(ROUTE, body, RID)
            assert (r.status, r.diag.code) == (504, "timeout")
            assert time.monotonic() - t0 < 5
            assert wait_until(lambda: p.idle() == 1, 90)
            ok = p.call(ROUTE, json.dumps({"text": "mail a@example.com"}).encode(), RID)
            assert ok.status == 200 and json.loads(ok.body)["entity_counts"]
            assert p.usage.requests_served == 1
        finally:
            p.close()


class TestCloseRaces:
    def test_concurrent_kills_close_the_pipe_once(self, pool):
        p = pool()
        w = p._idle.queue[0]
        real, calls = w.conn._close, []

        def slow_close(*a):
            calls.append(1)
            time.sleep(0.05)
            real(*a)

        w.conn._close = slow_close
        ts = [threading.Thread(target=w.discard)
              for _ in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(5)
        assert len(calls) == 1

    def test_close_during_a_respawn_never_raises(self, monkeypatch, thread_errors):
        for _ in range(2):
            p = worker.WorkerPool(1, timeout=0.3, handler=tasks.behave,
                                  init=tasks.sleepy_init)
            p.start()
            monkeypatch.setenv(tasks.INIT_SLEEP, "2")
            assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
            time.sleep(0.4)
            p.close()
            monkeypatch.delenv(tasks.INIT_SLEEP)
            assert not wait_until(lambda: thread_errors, 0.5), thread_errors

    def test_an_in_flight_call_never_requeues_after_close(self, pool):
        p = pool()
        w = p._idle.queue[0]
        real = w.conn.recv

        def recv_then_close():
            out = real()
            p.close()
            return out

        w.conn.recv = recv_then_close
        assert p.call(ROUTE, b"ok", RID).status == 200
        assert p.idle() == 0
        assert p.call(ROUTE, b"ok", RID).diag.code == "busy"

    def test_no_respawn_after_close(self, spawns):
        p = worker.WorkerPool(1, timeout=0.3, handler=tasks.behave, init=None,
                              spawn_delay=0.3)
        p.start()
        assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        p.close()
        n = spawns["n"]
        time.sleep(0.8)
        assert spawns["n"] == n
        assert not multiprocessing.active_children()

    def test_close_during_a_spawn_kills_that_worker_at_once(self, spawns, monkeypatch):
        p = worker.WorkerPool(1, timeout=0.3, handler=tasks.behave, init=tasks.sleepy_init)
        p.start()
        monkeypatch.setenv(tasks.INIT_SLEEP, "3")
        spawns["after"] = lambda n, w: n == 1 and p.close()
        assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        assert wait_until(lambda: len(spawns["made"]) == 2, 5)
        assert wait_until(lambda: not alive(spawns["made"][1].proc.pid), 1)

    def test_close_while_a_respawn_turns_ready_leaves_nothing_idle(self, spawns):
        p = worker.WorkerPool(1, timeout=0.3, handler=tasks.behave, init=None)
        p.start()

        def close_when_ready(n, w):
            if n == 1:
                real = w.wait_ready
                w.wait_ready = lambda s: real(s) and (p.close() or True)

        spawns["after"] = close_when_ready
        assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        assert wait_until(lambda: len(spawns["made"]) == 2, 5)
        assert wait_until(lambda: spawns["made"][1].gone.is_set(), 5)
        assert p.idle() == 0
        assert not alive(spawns["made"][1].proc.pid)

    def test_close_ends_the_pool_threads(self):
        before = threading.active_count()
        p = worker.WorkerPool(2, timeout=0.3, handler=tasks.behave, init=None)
        p.start()
        assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        p.close()
        assert wait_until(lambda: threading.active_count() == before, 5)

    def test_a_worker_killed_after_its_reply_is_not_requeued(self, pool):
        p = pool()
        w = p._idle.queue[0]
        pid, real = w.proc.pid, w.conn.recv

        def recv_then_kill():
            out = real()
            w.kill()
            return out

        w.conn.recv = recv_then_kill
        assert p.call(ROUTE, b"ok", RID).status == 200
        assert ready(p, seconds=5)
        assert p.call(ROUTE, b"ok", RID).status == 200
        assert pid_of(p) != pid

    def test_close_stops_a_busy_worker(self, pool):
        p = pool(timeout=10.0)
        pid = p.pids()[0]
        t = threading.Thread(target=lambda: p.call(ROUTE, b"spin", RID), daemon=True)
        t.start()
        assert wait_until(lambda: p.idle() == 0, 5)
        p.close()
        assert wait_until(lambda: not alive(pid), 3)
        t.join(3)
        assert not t.is_alive()


class TestSpawnFailures:
    def test_a_failed_respawn_backs_off_and_recovers(self, monkeypatch, spawns,
                                                    thread_errors, capfd):
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF", 0.05)
        spawns["fail"] = lambda n: n in (1, 2)
        p = worker.WorkerPool(1, timeout=0.3, handler=tasks.behave, init=None)
        p.start()
        try:
            assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
            assert ready(p, seconds=5)
            assert p.call(ROUTE, b"ok", RID).status == 200
            assert p.respawn_failures == 0 and p.healthy()
        finally:
            p.close()
        assert thread_errors == []
        assert capfd.readouterr().err == ""

    def test_a_spawn_that_raises_after_starting_kills_its_worker(self, monkeypatch, spawns):
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF", 0.05)

        def break_ready(n, w):
            if n == 1:
                w.wait_ready = lambda s: 1 / 0

        spawns["after"] = break_ready
        p = worker.WorkerPool(1, timeout=0.3, handler=tasks.behave, init=None)
        p.start()
        try:
            assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
            assert ready(p, seconds=5)
            assert wait_until(lambda: not alive(spawns["made"][1].proc.pid), 3)
            assert len(p.pids()) == 1
        finally:
            p.close()

    def test_backoff_doubles_to_its_cap_then_resets(self, monkeypatch, spawns):
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF", 0.05)
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF_MAX", 0.4)
        spawns["fail"] = lambda n: n >= 1
        p = worker.WorkerPool(1, timeout=0.3, handler=tasks.behave, init=None)
        p.start()
        try:
            assert p.healthy()
            assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
            assert wait_until(lambda: spawns["n"] >= 7, 5)
            assert not p.healthy() and p.respawn_failures >= 6
            at = spawns["at"][1:7]
            gaps = [b - a for a, b in zip(at, at[1:])]
            for want, got in zip([0.05, 0.1, 0.2, 0.4, 0.4], gaps):
                assert want * 0.9 < got < want + 0.15, gaps
            spawns["fail"] = lambda n: False
            assert ready(p, seconds=5)
            assert p.respawn_failures == 0 and p.healthy()
        finally:
            p.close()
        assert not p.healthy()

    def test_a_working_slot_does_not_reset_a_failing_slots_backoff(self, monkeypatch,
                                                                    spawns):
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF", 0.05)
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF_MAX", 0.4)
        p = worker.WorkerPool(2, timeout=0.1, handler=tasks.behave, init=None)
        p.start()
        try:
            failing = p._idle.queue[0].slot
            spawns["fail"] = lambda n: threading.current_thread() is failing
            assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
            end = time.monotonic() + 1.6
            while time.monotonic() < end:
                assert wait_until(lambda: p.idle() == 1, 5)
                assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
            assert not p.healthy() and p.respawn_failures >= 4
            at = [t for t, who in zip(spawns["at"], spawns["who"]) if who is failing][1:]
            gaps = [b - a for a, b in zip(at, at[1:])]
            assert len(gaps) >= 3 and gaps[2] > 0.18, gaps
        finally:
            p.close()

    def test_backoff_survives_a_long_outage(self, monkeypatch):
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF", 1.0)
        monkeypatch.setattr(worker, "RESPAWN_BACKOFF_MAX", 60.0)
        assert [worker._backoff(n) for n in (1, 2, 3, 7, 8, 5000)] == \
            [1.0, 2.0, 4.0, 60.0, 60.0, 60.0]

    def test_a_failed_process_start_closes_both_pipe_ends(self):
        made = []

        class Ctx:
            def Pipe(self):
                made.extend(multiprocessing.Pipe())
                return made[0], made[1]

            def Process(self, **kw):
                raise OSError(errno.EAGAIN, "Resource temporarily unavailable")

        with pytest.raises(OSError):
            worker._Worker(Ctx(), tasks.behave, None)
        assert [c.closed for c in made] == [True, True]

    def test_a_failed_start_closes_the_workers_already_started(self, spawns):
        p = worker.WorkerPool(2, timeout=1.0, handler=tasks.behave, init=None)
        spawns["fail"] = lambda n: n == 1 and (wait_until(lambda: p.idle() == 1, 5) or 1)
        with pytest.raises(Exception):
            p.start()
        assert len(spawns["made"]) == 1
        assert wait_until(lambda: not any(alive(w.proc.pid) for w in spawns["made"]), 5)
        p.close()


class TestBadReplies:
    @pytest.mark.parametrize("what", [b"triple", b"bomb"])
    def test_a_reply_that_cannot_be_used_is_a_fixed_500(self, pool, what):
        p = pool()
        pid = pid_of(p)
        r = p.call(ROUTE, what, RID)
        assert (r.status, r.diag.code, r.diag.exc_type) == \
            (500, "internal_error", "BadWorkerResponse")
        assert CANARY.encode() not in r.body and CANARY not in repr(r)
        assert ready(p, seconds=5)
        assert pid_of(p) != pid
        assert wait_until(lambda: not alive(pid), 3)

    def test_a_base_exception_replaces_the_worker_then_propagates(self, pool):
        p = pool()
        pid = pid_of(p)
        with pytest.raises(tasks.Abort):
            p.call(ROUTE, b"basebomb", RID)
        assert ready(p, seconds=5)
        assert pid_of(p) != pid


class TestDeadline:
    def test_a_reply_stalled_after_poll_still_ends_on_time(self, pool):
        """poll() saying "readable" while the child is still computing is what
        a child stalled after its first byte looks like to recv()."""
        p = pool(timeout=1.0)
        w = p._idle.queue[0]
        pid = w.proc.pid
        w.conn.poll = lambda t: time.sleep(0.5) or True
        out = {}
        t = threading.Thread(target=lambda: out.update(r=p.call(ROUTE, b"spin", RID)),
                             daemon=True)
        t0 = time.monotonic()
        t.start()
        t.join(4)
        took = time.monotonic() - t0
        try:
            assert not t.is_alive()
            assert out["r"].diag.code == "timeout"
            assert 0.9 < took < 1.4
            assert ready(p, seconds=5)
        finally:
            if alive(pid):
                os.kill(pid, signal.SIGKILL)

    def test_a_big_reply_inside_the_deadline_is_delivered(self, pool):
        p = pool(timeout=5.0)
        r = p.call(ROUTE, b"big", RID)
        assert r.status == 200 and len(r.body) == 8 << 20
        assert p.idle() == 1


class TestChildHardening:
    def test_raw_fds_1_and_2_go_nowhere(self):
        out = run_script("""
            p = worker.WorkerPool(1, timeout=5, handler=tasks.behave, init=None)
            p.start()
            assert p.call("POST /v1/check", b"oswrite", "r_1").status == 200
            p.close()
        """)
        assert out.returncode == 0, out.stderr[-500:]
        assert CANARY not in out.stdout and CANARY not in out.stderr

    def test_workers_are_daemons(self):
        out = run_script("""
            p = worker.WorkerPool(1, timeout=5, handler=tasks.behave, init=None)
            p.start()
            print(p.pids()[0], flush=True)
        """, timeout=20)
        assert out.returncode == 0, out.stderr[-500:]
        assert wait_until(lambda: not alive(int(out.stdout)), 5)

    def test_a_worker_that_ignores_sigterm_is_still_killed(self, pool):
        p = pool(timeout=0.5)
        pid = pid_of(p)
        assert p.call(ROUTE, b"stubborn", RID).diag.code == "timeout"
        assert wait_until(lambda: not alive(pid), 3)
        assert ready(p, seconds=5)

    def test_sigint_from_a_terminal_does_not_kill_a_worker(self, pool):
        p = pool()
        pid = pid_of(p)
        os.kill(pid, signal.SIGINT)
        time.sleep(0.3)
        assert pid_of(p) == pid

    def test_a_child_whose_parent_is_not_the_pool_exits_before_ready(self):
        ctx = multiprocessing.get_context("spawn")
        mine, theirs = ctx.Pipe()
        proc = ctx.Process(target=worker._child, args=(theirs, tasks.behave, None, 1, None),
                           daemon=True)
        proc.start()
        theirs.close()
        proc.join(10)
        assert proc.exitcode == 0
        with pytest.raises(EOFError):
            mine.recv()
        mine.close()

    def test_no_core_dumps(self, pool):
        assert pool().call(ROUTE, b"rlimit", RID).body == b"(0, 0)"

    def test_omp_is_one_from_child_startup_and_the_parent_is_untouched(self, pool,
                                                                       monkeypatch):
        monkeypatch.delenv("OMP_NUM_THREADS", raising=False)
        p = pool()
        assert p.call(ROUTE, b"env", RID).body == b"1"
        assert "OMP_NUM_THREADS" not in os.environ
        monkeypatch.setenv("OMP_NUM_THREADS", "7")
        assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        assert ready(p, seconds=5)
        assert os.environ["OMP_NUM_THREADS"] == "7"

    def test_prctl_comes_before_the_ppid_check(self, monkeypatch):
        seen = []

        class Libc:
            def prctl(self, *a):
                seen.append(("prctl",) + tuple(getattr(x, "value", x) for x in a))
                return 0

        monkeypatch.setattr(worker, "_LINUX", True)
        monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **kw: Libc())
        monkeypatch.setattr(os, "getppid", lambda: seen.append(("ppid",)) or 4242)
        monkeypatch.setattr(os, "_exit", lambda code: pytest.fail("exited"))
        worker._die_with_parent(4242)
        assert seen == [("prctl", 1, signal.SIGKILL, 0, 0, 0), ("ppid",)]

    def test_no_prctl_off_linux(self, monkeypatch):
        monkeypatch.setattr(worker, "_LINUX", False)
        monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **kw: pytest.fail("prctl"))
        worker._die_with_parent(os.getppid())

    def test_a_ppid_mismatch_exits(self, monkeypatch):
        class Exited(BaseException):
            pass

        def fake_exit(code):
            raise Exited(code)

        monkeypatch.setattr(worker, "_LINUX", False)
        monkeypatch.setattr(os, "_exit", fake_exit)
        with pytest.raises(Exited):
            worker._die_with_parent(os.getppid() + 1)

    def test_oom_score_adj_is_raised_and_errors_are_ignored(self, monkeypatch, tmp_path):
        f = tmp_path / "oom"
        f.write_text("0")
        monkeypatch.setattr(worker, "_OOM_SCORE_ADJ", str(f))
        worker._limit_child(None)
        assert f.read_text() == "1000"
        monkeypatch.setattr(worker, "_OOM_SCORE_ADJ", str(tmp_path / "no" / "such"))
        worker._limit_child(None)

    def test_rlimit_as_only_when_asked(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(worker, "_OOM_SCORE_ADJ", str(tmp_path / "oom"))
        monkeypatch.setattr(resource, "setrlimit", lambda *a: calls.append(a))
        worker._limit_child(None)
        assert calls == []
        worker._limit_child(1 << 30)
        assert calls == [(resource.RLIMIT_AS, (1 << 30, 1 << 30))]

    def test_mem_limit_reaches_the_child_or_fails_start(self):
        limit = 4 << 30
        p = worker.WorkerPool(1, timeout=2.0, handler=tasks.behave, init=None,
                              mem_limit_bytes=limit)
        try:
            if sys.platform.startswith("linux"):
                p.start()
                assert p.call(ROUTE, b"aslimit", RID).body == repr((limit, limit)).encode()
            else:
                with pytest.raises(worker.WorkerStartError):
                    p.start()
        finally:
            p.close()

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
    def test_linux_child_is_first_to_be_oom_killed(self, pool):
        assert pool().call(ROUTE, b"oom", RID).body == b"1000"

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
    def test_linux_orphan_mid_computation_dies_at_once(self):
        script = textwrap.dedent("""
            import threading
            from pii_buddy.server import worker
            from tests import _worker_tasks as tasks
            if __name__ == "__main__":
                p = worker.WorkerPool(1, timeout=600, handler=tasks.behave, init=None)
                threading.Thread(target=p.start).start()
                while not p.idle():
                    pass
                print(p.pids()[0], flush=True)
                p.call("POST /v1/check", b"spin", "r_1")
        """)
        proc = subprocess.Popen([sys.executable, "-c", script],
                                stdout=subprocess.PIPE, text=True)
        pid = int(proc.stdout.readline())
        time.sleep(0.5)
        proc.kill()
        proc.wait()
        try:
            assert wait_until(lambda: not alive(pid), 2)
        finally:
            if alive(pid):
                os.kill(pid, signal.SIGKILL)
