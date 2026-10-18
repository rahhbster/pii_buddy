"""Machine-independent complexity checks for the detector regression tests.

Absolute wall-clock limits are flaky on slow shared CI runners, so the primary
check compares t(2N) with t(N) on the same input shape: linear work gives a
ratio near 2, quadratic work near 4. One generous absolute backstop at full
size still catches a catastrophic blow-up (the earlier 25-minute case).

All timing is CPU time (`time.process_time`), not wall time: when the machine
is oversubscribed, a process is descheduled for arbitrary stretches that wall
time counts and CPU time does not. The small size is the median of several
runs and the large size the best of a few, so one noisy sample cannot push the
ratio over the limit, and the denominator has a floor so a baseline of a few
milliseconds cannot turn jitter into a "4x".
"""

import statistics
import time

RATIO_LIMIT = 3.5
RATIO_FLOOR_S = 0.01
BACKSTOP_S = 8.0
SMALL_RUNS = 5
LARGE_RUNS = 3


def cpu_time(run, text):
    t0 = time.process_time()
    result = run(text)
    return time.process_time() - t0, result


def _median_of(run, text, runs=SMALL_RUNS):
    return statistics.median(cpu_time(run, text)[0] for _ in range(runs))


def _best_of(run, text, runs=LARGE_RUNS):
    return min(cpu_time(run, text)[0] for _ in range(runs))


def assert_ratio_linear(t_small, t_large, label, small_n, large_n):
    ratio = t_large / max(t_small, RATIO_FLOOR_S)
    assert ratio < RATIO_LIMIT, (
        f"{label}: cpu t({large_n})={t_large:.3f}s / t({small_n})={t_small:.3f}s "
        f"= {ratio:.2f}x, expected ~2x for linear work"
    )


def assert_scales_linearly(run, make, label, small=50_000, backstop_size=400_000):
    """`make(size)` builds the input; `run(text)` does the work being timed.

    Returns whatever `run` returned for the backstop-size input so callers can
    keep their correctness assertions.
    """
    t_small = _median_of(run, make(small))
    t_large = _best_of(run, make(small * 2))
    assert_ratio_linear(t_small, t_large, label, small, small * 2)
    text = make(backstop_size)
    elapsed, result = cpu_time(run, text)
    assert elapsed < BACKSTOP_S, f"{label}: {elapsed:.2f}s CPU for {len(text)} chars"
    return result
