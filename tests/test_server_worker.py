"""WorkerPool: the real bound on request time.  Workers are real spawned
processes, because the behaviours under test (kill, crash, sibling survival)
do not exist in-process.  Handlers live in ``tests._worker_tasks``."""

import json
import os
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


def ready(p, n=None):
    return wait_until(lambda: p.idle() == (p.size if n is None else n))


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
        assert (r.status, r.diag.code) == (503, "timeout")
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
        p = pool(timeout=0.5, spawn_delay=1.0)
        assert p.call(ROUTE, b"spin", RID).diag.code == "timeout"
        r = p.call(ROUTE, b"ok", RID)
        assert (r.status, r.diag.code) == (503, "busy")
        assert ready(p)
        assert p.call(ROUTE, b"ok", RID).status == 200

    def test_repeated_kills_do_not_leak_workers_or_shrink_the_pool(self, pool):
        p = pool(2, timeout=0.4)
        for _ in range(5):
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
            assert (r.status, r.diag.code) == (503, "timeout")
            assert time.monotonic() - t0 < 5
            assert wait_until(lambda: p.idle() == 1, 90)
            ok = p.call(ROUTE, json.dumps({"text": "mail a@example.com"}).encode(), RID)
            assert ok.status == 200 and json.loads(ok.body)["entity_counts"]
            assert p.usage.requests_served == 1
        finally:
            p.close()
