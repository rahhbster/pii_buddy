"""Validation must stay linear in the number of PERSON entities.

Each case builds the spaCy doc and the candidate entities once (outside the
timer) and times validate_entities alone: t(2N) / t(N) is ~2 for linear work
and ~4 for the old per-entity scan of every token. One absolute backstop at
full size catches a blow-up on any machine. Timing is CPU time (process_time)
and the median of several runs, so scheduler load cannot fake a ratio.
"""

import statistics
import time

import pytest

from pii_buddy import detector
from pii_buddy.validation import validate_entities

RATIO_LIMIT = 3.0
BACKSTOP_S = 8.0
RUNS = 5
RATIO_FLOOR_S = 0.01

# (unit, N for the small run, N for the backstop run)
SHAPES = [
    ("Sam, ", 1000, 7999),
    ("John Smith, ", 500, 4166),
    ("Mr. Smith, ", 650, 5300),
]


def _prepare(text):
    doc = detector.get_nlp()(text)
    return doc, [e for e in doc.ents if e.label_ == "PERSON"]


def _time_validation(unit, n, agg=statistics.median):
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
    return agg(times), len(ents), len(out)


@pytest.mark.parametrize("unit,small,full", SHAPES, ids=[s[0].strip(" ,") for s in SHAPES])
def test_validation_scales_linearly(unit, small, full):
    t_small, n_small, _ = _time_validation(unit, small)
    t_large, n_large, _ = _time_validation(unit, small * 2, min)
    assert n_small >= small // 2 and n_large >= small, "NER found too few entities"
    ratio = t_large / max(t_small, RATIO_FLOOR_S)
    assert ratio < RATIO_LIMIT, (
        f"{unit!r}: t({small * 2})={t_large:.3f}s / t({small})={t_small:.3f}s "
        f"= {ratio:.2f}x, expected ~2x for linear work"
    )
    t_full, _, _ = _time_validation(unit, full, min)
    assert t_full < BACKSTOP_S, f"{unit!r} x{full}: {t_full:.2f}s in validation"
