"""Validation must stay linear in the number of PERSON entities.

Each case builds the spaCy doc and the candidate entities once (outside the
timer) and times validate_entities alone: t(2N) / t(N) is ~2 for linear work
and ~4 for the old per-entity scan of every token. The large run is also the
full-size backstop (8 s), so a blow-up on any machine is caught. Timing is CPU
time (process_time) and the minimum of several runs for BOTH sizes, so
scheduler load cannot fake a ratio. The small N is chosen so t(N) is well above
the constant ratio floor: a floor above t(N) would turn the ratio check into an
absolute limit that a mild slowdown slips under. A ratio cannot see a slowdown
that is linear in the entity count, so the large run also has a CPU-time limit
at ~10x the measured time (min of five, so scheduler load does not move it).
"""

import time

import pytest

from pii_buddy import detector
from pii_buddy.validation import validate_entities
from tests._scaling import SLOW_RUN_S

RATIO_LIMIT = 3.0
BACKSTOP_S = 8.0
RUNS = 5
RATIO_FLOOR_S = 0.005
LARGE_LIMIT_S = 0.4

# (unit, N for the small run); the large run is 2N and doubles as the backstop
SHAPES = [
    ("Sam, ", 4000),
    ("John Smith, ", 2100),
    ("Mr. Smith, ", 2650),
]


def _prepare(text):
    doc = detector.get_nlp()(text)
    return doc, [e for e in doc.ents if e.label_ == "PERSON"]


def _time_validation(unit, n):
    text = unit * n
    doc, ents = _prepare(text)
    times = []
    for _ in range(RUNS):
        cands = [detector.PIIEntity(text=e.text, label="PERSON",
                                    start=e.start_char, end=e.end_char)
                 for e in ents]
        t0 = time.process_time()
        out = validate_entities(cands, text, doc)
        times.append(time.process_time() - t0)
        if times[-1] > SLOW_RUN_S:
            break  # already failing; do not spend four more runs proving it
    return min(times), len(ents), len(out)


@pytest.mark.parametrize("unit,small", SHAPES, ids=[s[0].strip(" ,") for s in SHAPES])
def test_validation_scales_linearly(unit, small):
    t_small, n_small, _ = _time_validation(unit, small)
    t_large, n_large, _ = _time_validation(unit, small * 2)
    assert n_small >= small // 2 and n_large >= small, "NER found too few entities"
    ratio = t_large / max(t_small, RATIO_FLOOR_S)
    assert ratio < RATIO_LIMIT, (
        f"{unit!r}: t({small * 2})={t_large:.3f}s / t({small})={t_small:.3f}s "
        f"= {ratio:.2f}x, expected ~2x for linear work"
    )
    assert t_large < LARGE_LIMIT_S, (
        f"{unit!r} x{small * 2}: {t_large:.3f}s CPU in validation, "
        f"limit {LARGE_LIMIT_S}s (~10x the normal time)"
    )
    assert t_large < BACKSTOP_S, f"{unit!r} x{small * 2}: {t_large:.2f}s in validation"
