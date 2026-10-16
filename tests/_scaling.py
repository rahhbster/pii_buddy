"""Machine-independent complexity checks for the detector regression tests.

Absolute wall-clock limits are flaky on slow shared CI runners, so the primary
check compares t(2N) with t(N) on the same input shape: linear work gives a
ratio near 2, quadratic work near 4. One generous absolute backstop at full
size still catches a catastrophic blow-up (the earlier 25-minute case).
"""

import time

RATIO_LIMIT = 3.5
RATIO_FLOOR_S = 0.005
BACKSTOP_S = 8.0
RUNS = 3


def _best_of(run, text, runs=RUNS):
    best = float("inf")
    for _ in range(runs):
        t0 = time.perf_counter()
        run(text)
        best = min(best, time.perf_counter() - t0)
    return best


def assert_scales_linearly(run, make, label, small=50_000, backstop_size=400_000):
    """`make(size)` builds the input; `run(text)` does the work being timed.

    Returns whatever `run` returned for the backstop-size input so callers can
    keep their correctness assertions.
    """
    t_small = _best_of(run, make(small))
    t_large = _best_of(run, make(small * 2))
    ratio = t_large / max(t_small, RATIO_FLOOR_S)
    assert ratio < RATIO_LIMIT, (
        f"{label}: t({small * 2})={t_large:.3f}s / t({small})={t_small:.3f}s "
        f"= {ratio:.2f}x, expected ~2x for linear work"
    )
    text = make(backstop_size)
    t0 = time.perf_counter()
    result = run(text)
    elapsed = time.perf_counter() - t0
    assert elapsed < BACKSTOP_S, f"{label}: {elapsed:.2f}s for {len(text)} chars"
    return result
