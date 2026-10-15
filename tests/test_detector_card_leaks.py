"""CARD leaks: glued digits, full-length writings, and the glued-email shrink.

Every number is a well-known test PAN or an invented value. Coverage (a digit is
redacted) is asserted separately from the CARD label: an ordinary hyphenated ID
may be covered by another label but must never be called a card.
"""

import json
from pathlib import Path

import pytest

from pii_buddy.detector import detect_pii


def _ents(text):
    return [(e.label, e.text) for e in detect_pii(text, doc_type="general")]


def _cards(text):
    return [t for l, t in _ents(text) if l == "CARD"]


def _covered(text):
    return {i for e in detect_pii(text, doc_type="general")
            for i in range(e.start, e.end) if not text[i].isspace()}


def _visible_digits(text, tail=None):
    """Digits left visible, from the start of ``tail`` (default: everything)."""
    got = _covered(text)
    start = text.index(tail) if tail else 0
    return [(i, c) for i, c in enumerate(text)
            if i >= start and c.isdigit() and i not in got]


GLUED = [
    "4111-1111-1111-1111326",
    "4111 1111 1111 1111" + "12345678",
    "4111 1111 1111 1111" + "123456789",
    "5500 0000 0000 00045500 0000 0000 0004",
    "123 45 67894111-1111-1111-1111",
    "6304 9000 1740 0000 0017543232",
    "98403782 822463 10005678870",
    "123 45 67894111 1111 1111 1111",
    "4111 1111 1111 1111326",
    "4111–1111–1111–1111326",
    "12345678 3782 822463 10005",
    "3782 822463 10005123456",
]


@pytest.mark.parametrize("text", GLUED)
def test_glued_digits_leave_no_digit_visible(text):
    # "123 45 " ahead of a glued run is a separate (non-SSN) number, not part of it.
    tail = text[7:] if text.startswith("123 45 ") else None
    assert _visible_digits(text, tail) == [], (text, _ents(text))


@pytest.mark.parametrize("text", GLUED)
def test_glued_digits_are_labelled_card(text):
    assert _cards(text), (text, _ents(text))


_LEAKING_WRITINGS = [
    # Amex 4-4-4-3
    "3782 8224 6310 005", "3782-8224-6310-005", "3782 8224 6310 005",
    # 13-digit Visa 4-4-4-1
    "4222 2222 2222 2", "4222-2222-2222-2", "4222 2222 2222 2",
    # Diners 14-digit 4-4-4-2
    "3056 9309 0259 04", "3056-9309-0259-04", "3056 9309 0259 04",
    # 16-digit 4-4-8 and 8-8
    "4111 1111 11111111", "4111-1111-11111111", "4111 1111 11111111",
    "41111111 11111111", "41111111-11111111", "41111111 11111111",
    "5500 0000 00000004", "55000000 00000004",
    # trailing group split once more
    "4111 1111 1111 111 1", "4111 1111 1111 11 11",
]


@pytest.mark.parametrize("text", _LEAKING_WRITINGS)
def test_standard_and_split_writings_are_cards(text):
    assert text in _cards(text), (text, _ents(text))
    assert _visible_digits(text) == []


@pytest.mark.parametrize("text", [
    "INV-5642-29793087-1525",
    "ref 91-4066-4944-80939-07",
    "ref 95-5665-6017-68299-25",
    "INV-8552-80387294-1242",
    "ref 07-5012-0526-92837-79",
])
def test_owner_listed_ids_stay_non_card(text):
    assert _cards(text) == []


# 30 generated hyphenated IDs. Each has a Luhn-valid contiguous digit run of
# 13-19 digits and was not a CARD at f53182a.
GENERATED_IDS = json.loads(
    (Path(__file__).parent / "data" / "non_card_ids.json").read_text()
)


def test_generated_non_card_ids_present():
    assert len(GENERATED_IDS) >= 30


@pytest.mark.parametrize("text", GENERATED_IDS)
def test_generated_hyphenated_ids_stay_non_card(text):
    assert _cards(text) == [], (text, _ents(text))


def test_ordinary_text_false_positive_rate_is_bounded():
    """300 generated lines of invoice/ISBN/tracking/order/UUID/timestamp text.
    The corpus deliberately includes 4-4-4-3 and 8-8 shapes, which are cards by
    design when Luhn-valid. Measured: 63c 21, f53182a 13, this change 22."""
    lines = (Path(__file__).parent / "data" / "ordinary_text_lines.txt").read_text().splitlines()
    assert len(lines) == 300
    hits = [l for l in lines if _cards(l)]
    print(f"\nordinary-text CARD lines: {len(hits)} of {len(lines)}")
    assert len(hits) <= 22


# --- glued email --------------------------------------------------------------

@pytest.mark.parametrize("text,secret", [
    ("jo.q@example.com+sam+x@x.io", "+sam+x@x.io"),
    ("jo.q@example.com.sam@x.io", ".sam@x.io"),
    ("jo.q@example.com_sam@x.io", "_sam@x.io"),
    ("jo.q@example.com%sam@x.io", "%sam@x.io"),
    ("a@b.co+c@d.io+e@f.org", "+c@d.io+e@f.org"),
])
def test_email_glued_after_email_is_fully_covered(text, secret):
    start = text.index(secret)
    got = _covered(text)
    assert all(i in got for i in range(start, start + len(secret))), _ents(text)


# --- coverage never shrinks vs origin/main -------------------------------------

MAIN_CORPUS = Path(__file__).parent / "data" / "main_covered_spans.json"


def test_coverage_is_superset_of_origin_main():
    """Frozen from origin/main's detector by tests/data/make_main_corpus.py. A
    missing corpus is a failure, never a skip."""
    if not MAIN_CORPUS.is_file():
        pytest.fail(f"main corpus missing: {MAIN_CORPUS}")
    cases = json.loads(MAIN_CORPUS.read_text())["cases"]
    assert len(cases) >= 400
    assert all(c["covered"] for c in cases)
    lost = []
    for case in cases:
        gone = sorted(set(case["covered"]) - _covered(case["text"]))
        if gone:
            lost.append((case["text"], gone))
    print(f"\nmain superset: cases={len(cases)} lost={len(lost)}")
    for text, gone in lost[:10]:
        print("  LOST", repr(text), gone)
    assert lost == []


# --- a second, larger adjacency seed -------------------------------------------

NEW_SEED = 20261015
NEW_N = 8000
# "_" and ".." are left out on purpose: an underscore is a word character and
# ".." extends a dotted run, so the two items fuse into one token for every
# word-boundary pattern. Main and 63c show the same on those separators.
NEW_SEPS = [
    " ", ", ", "|", "\n", ";", "/", ",+", "\t", "", "-", " - ", "(", ")", ":",
    " ", "--", "–", "—", "−", "=", " _ ", "- ", " -",
    " ", "  ", ". ", "#",
]
_NEW_ITEMS = [
    "jane.doe@example.com", "a_b+tag@mail.example.org", "q@example.dev",
    "+33 1 42 68 53 00", "+44 20 7946 0958", "+442079460958",
    "415-555-0132", "(415) 555-0132", "4155550132",
    "123-45-6789", "123 45 6789", "123456789",
    "4111 1111 1111 1111", "4111-1111-1111-1111", "5500 0000 0000 0004",
    "3782 822463 10005", "3782 8224 6310 005", "4222 2222 2222 2",
    "3056 9309 0259 04", "4111 1111 11111111", "41111111 11111111",
    "4111 1111 1111 111 1", "4111111111111111",
    "10.0.0.1", "192.168.1.254",
    "https://example.com/path?q=1", "example.com/a", "example.com",
    "@jane_doe", "12/25/1990", "1990-12-25", "March 3, 1985",
]


def test_adjacency_invariant_on_new_seed():
    import random

    from tests.test_detector_adjacency import run_invariant

    rng = random.Random(NEW_SEED)
    cases = []
    while len(cases) < NEW_N:
        k = 3 if rng.random() < 0.2 else 2
        cases.append(([rng.choice(_NEW_ITEMS) for _ in range(k)], rng.choice(NEW_SEPS)))
    n, violations = run_invariant(
        lambda t: [(e.start, e.end) for e in detect_pii(t, doc_type="general")],
        cases,
    )
    print(f"\nadjacency (new seed {NEW_SEED}): cases={n} seps={len(NEW_SEPS)} "
          f"violations={len(violations)}")
    for v in violations[:20]:
        print("  VIOLATION", repr(v[0]), "item", repr(v[1]), "missing", v[2])
    assert n >= 8000 and len(NEW_SEPS) >= 25
    assert violations == []
