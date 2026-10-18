"""Machine-independent complexity checks for the detector regression tests.

Absolute wall-clock limits are flaky on slow shared CI runners, so the primary
check compares t(2N) with t(N) on the same input shape: linear work gives a
ratio near 2, quadratic work near 4. One generous absolute backstop at full
size still catches a catastrophic blow-up (the earlier 25-minute case).

All timing is CPU time (`time.process_time`), not wall time: when the machine
is oversubscribed, a process is descheduled for arbitrary stretches that wall
time counts and CPU time does not. BOTH sizes are the minimum of several runs
(noise only ever adds time, and a median on one side only would bias the ratio
down), and the denominator has a constant floor so a baseline of a few
milliseconds cannot turn jitter into a "4x".
"""

import time

RATIO_LIMIT = 3.5
RATIO_FLOOR_S = 0.005
BACKSTOP_S = 8.0
RUNS = 5
SLOW_RUN_S = 1.0


def cpu_time(run, text):
    t0 = time.process_time()
    result = run(text)
    return time.process_time() - t0, result


def best_of(run, text, runs=RUNS):
    times = []
    for _ in range(runs):
        times.append(cpu_time(run, text)[0])
        if times[-1] > SLOW_RUN_S:
            break  # already failing; do not spend more runs proving it
    return min(times)


def assert_ratio_linear(t_small, t_large, label, small_n, large_n,
                        limit=RATIO_LIMIT, floor=RATIO_FLOOR_S):
    ratio = t_large / max(t_small, floor)
    assert ratio < limit, (
        f"{label}: cpu t({large_n})={t_large:.3f}s / t({small_n})={t_small:.3f}s "
        f"= {ratio:.2f}x, expected ~2x for linear work"
    )


def assert_scales_linearly(run, make, label, small=50_000, backstop_size=400_000):
    """`make(size)` builds the input; `run(text)` does the work being timed.

    Returns whatever `run` returned for the backstop-size input so callers can
    keep their correctness assertions.
    """
    t_small = best_of(run, make(small))
    t_large = best_of(run, make(small * 2))
    assert_ratio_linear(t_small, t_large, label, small, small * 2)
    text = make(backstop_size)
    elapsed, result = cpu_time(run, text)
    assert elapsed < BACKSTOP_S, f"{label}: {elapsed:.2f}s CPU for {len(text)} chars"
    return result
