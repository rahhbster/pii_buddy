"""Adjacent-PII behaviour of the detector.

Redaction coverage must never shrink because two items sit next to each other:
when candidates overlap the higher-priority one stays whole and the other is
trimmed, never dropped. The seeded invariant test below is the guard.
"""

import json
import random
import time
from pathlib import Path

import pytest

from pii_buddy import detector
from pii_buddy.detector import detect_pii


def _ents(text):
    return [(e.label, e.text) for e in detect_pii(text, doc_type="general")]


def _covered(text):
    """Set of redacted non-whitespace character offsets."""
    out = set()
    for e in detect_pii(text, doc_type="general"):
        out.update(i for i in range(e.start, e.end) if not text[i].isspace())
    return out


# --- the five verified defects ------------------------------------------------

@pytest.mark.parametrize("phone", ["415-555-0132", "(415) 555-0132"])
def test_ip_does_not_crowd_out_adjacent_phone(phone):
    text = f"Server 10.0.0.1 {phone} end"
    assert any(l == "PHONE" and phone in t for l, t in _ents(text))
    covered = _covered(text)
    for i, ch in enumerate(text):
        if i >= text.index("10.") and i < text.index(" end") and not ch.isspace():
            assert i in covered, (text, i, ch)


def test_intl_phone_does_not_eat_following_ssn():
    ents = _ents("Call +33 1 42 68 53 00 123-45-6789 now")
    assert ("PHONE", "+33 1 42 68 53 00") in ents
    assert ("SSN", "123-45-6789") in ents


def test_intl_phone_does_not_eat_following_date():
    ents = _ents("Call +44 20 7946 0958 12/25/1990 now")
    assert ("PHONE", "+44 20 7946 0958") in ents
    assert ("DOB", "12/25/1990") in ents


def test_url_path_does_not_swallow_next_phone():
    text = "see example.com/a,+1 415 555 0132 ok"
    covered = _covered(text)
    start = text.index("example.com")
    for i in range(start, text.index(" ok")):
        if not text[i].isspace():
            assert i in covered
    assert any(l == "PHONE" for l, _ in _ents(text))


def test_intl_phone_glued_to_email_keeps_email():
    ents = _ents("x +33 1 42 68 53 00@example.dev y")
    assert ("EMAIL", "00@example.dev") in ents
    assert any(l == "PHONE" for l, _ in ents)


def test_overlap_never_drops_wholesale_keeps_remainder():
    # IP loses to PHONE on the shared "1"; its remainder is still redacted.
    text = "Server 10.0.0.1 415-555-0132 end"
    covered = _covered(text)
    assert all(i in covered for i in range(text.index("10."), text.index("10.") + 8))


def test_intl_phone_fallback_keeps_old_coverage():
    # "12/25" is not a date, so the narrowed phone must not leave "12" visible.
    text = "Call +44 20 7946 0958 12/25 now"
    covered = _covered(text)
    for i in range(text.index("+44"), text.index("12/25") + 2):
        if not text[i].isspace():
            assert i in covered


# --- _check_handle must be linear -------------------------------------------

@pytest.mark.parametrize("size", [400_000])
def test_handle_check_is_linear_on_single_line_input(size):
    text = "@override " * (size // 10)
    t0 = time.perf_counter()
    n = 0
    for m in detector.HANDLE_RE.finditer(text):
        detector._check_handle(m, text)
        n += 1
    elapsed = time.perf_counter() - t0
    assert n == size // 10
    assert elapsed < 1.0, f"{elapsed:.2f}s for {size} chars"


def test_regex_and_overlap_stages_are_fast_on_400kb_single_line():
    text = "@override " * 40_000
    t0 = time.perf_counter()
    ents = detector._regex_entities(text)
    kept = detector._resolve_overlaps(ents, text)
    elapsed = time.perf_counter() - t0
    assert len(kept) == 40_000
    assert elapsed < 1.0, f"{elapsed:.2f}s"


def test_handle_decorator_still_skipped_at_line_start():
    assert _ents("@override\ndef f(): pass") == []


def test_decorator_after_long_indent_is_redacted_fail_closed():
    assert any(l == "HANDLE" for l, _ in _ents("x" * 600 + " @override"))


# --- separator leaks and linear-time resolver ---------------------------------

@pytest.mark.parametrize("text,secret", [
    ("10.0.0.1-4012888888881881", "4012888888881881"),
    ("415.555.0132-4111 1111 1111 1111 123", "4111 1111 1111 1111"),
    ("123-45-6789-5500 0000 0000 0004", "5500 0000 0000 0004"),
    ("123-45-6789 - 4111 1111 1111 1111", "4111 1111 1111 1111"),
    ("4111\u00a01111\u00a01111\u00a01111", "4111\u00a01111\u00a01111\u00a01111"),
    ("4111\u202f1111\u202f1111\u202f1111", "4111\u202f1111\u202f1111\u202f1111"),
    ("4111\u20091111\u20091111\u20091111", "4111\u20091111\u20091111\u20091111"),
    ("4111\u20131111\u20131111\u20131111", "4111\u20131111\u20131111\u20131111"),
    ("4111\u20151111\u20151111\u20151111", "4111\u20151111\u20151111\u20151111"),
    ("4111\u22121111\u22121111\u22121111", "4111\u22121111\u22121111\u22121111"),
])
def test_card_next_to_dash_or_unicode_separator_is_fully_covered(text, secret):
    covered = _covered(text)
    start = text.index(secret)
    for i in range(start, start + len(secret)):
        if not text[i].isspace():
            assert i in covered, (text, i, text[i])


@pytest.mark.parametrize("name,text", [
    ("email x url", "a@b.co http://x.com/p " * 18000),
    ("handles", "@override " * 40000),
    ("ips", "1.2.3.4 " * 50000),
    ("cards", "4111 1111 1111 1111 " * 20000),
])
def test_pipeline_stages_are_fast_at_400kb(name, text):
    t0 = time.perf_counter()
    ents = detector._regex_entities(text)
    detector._resolve_overlaps(ents, text)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, f"{name}: {elapsed:.2f}s for {len(text)} chars"


# --- seeded adjacency invariant ----------------------------------------------

SEED = 20261014
N_CASES = 3000

_ITEMS = {
    "email": ["jane.doe@example.com", "a_b+tag@mail.example.org", "q@example.dev"],
    "intl": ["+33 1 42 68 53 00", "+44 20 7946 0958", "+49 30 1234567",
             "+61 2 9876 5432", "+81 3-1234-5678", "+442079460958"],
    "us": ["415-555-0132", "(415) 555-0132", "+1 415 555 0132",
           "415.555.0132", "4155550132"],
    "ssn": ["123-45-6789", "123 45 6789", "123456789", "123.45.6789"],
    "card": ["4111 1111 1111 1111", "4111-1111-1111-1111",
             "5500 0000 0000 0004", "3782 822463 10005"],
    "ip": ["10.0.0.1", "192.168.1.254", "172.16.0.5"],
    "url": ["https://example.com/path?q=1", "http://example.org",
            "www.example.net/a", "example.com/a", "example.com",
            "sub.example.co/x"],
    "handle": ["@jane_doe", "@bob.smith"],
    "date": ["12/25/1990", "1990-12-25", "March 3, 1985", "25.12.1990"],
}
_FLAT = [it for items in _ITEMS.values() for it in items]
_SEPS = [" ", ", ", "|", "\n", ";", "/", ",+", "\t", "",
         "-", " - ", "(", ")", ":", "\u00a0"]


def _join(items, sep):
    out = items[0]
    for nxt in items[1:]:
        if sep == "":
            # glue only where the shapes cannot fuse into one digit/word run
            if not (nxt[0] in "+(" and not out[-1].isdigit()):
                s = " "
            else:
                s = ""
        elif sep == ",+":
            s = ",+"
            nxt = nxt.lstrip("+")
        else:
            s = sep
        out += s + nxt
    return out


def _cases():
    rng = random.Random(SEED)
    cases = []
    while len(cases) < N_CASES:
        k = 3 if rng.random() < 0.2 else 2
        items = [rng.choice(_FLAT) for _ in range(k)]
        sep = rng.choice(_SEPS)
        cases.append((items, sep))
    return cases


def run_invariant(detect, cases):
    """Return (n_cases, violations) for a detect(text) -> [(start, end)] fn."""
    alone_cache = {}

    def alone(item):
        if item not in alone_cache:
            alone_cache[item] = {
                i for s, e in detect(item) for i in range(s, e)
                if not item[i].isspace()
            }
        return alone_cache[item]

    violations = []
    for items, sep in cases:
        text = _join(items, sep)
        # recompute offsets by walking the same join
        pos = 0
        offsets = []
        for idx, it in enumerate(items):
            piece = it.lstrip("+") if (sep == ",+" and idx) else it
            found = text.index(piece, pos)
            if piece is not it:  # leading "+" was stripped; alone-set shifts by 1
                offsets.append((it, found - 1))
            else:
                offsets.append((it, found))
            pos = found + len(piece)
        covered = {
            i for s, e in detect(text) for i in range(s, e)
            if not text[i].isspace()
        }
        for it, off in offsets:
            if sep == ",+" and off >= 0 and text[off:off + len(it)] != it:
                # stripped "+": the "+" lives in the separator, still compare
                # the remaining characters only
                missing = {
                    i + off for i in alone(it)
                    if i > 0 and (i + off) not in covered
                }
            else:
                missing = {i + off for i in alone(it) if (i + off) not in covered}
            if missing:
                violations.append((text, it, sorted(missing)))
                break
    return len(cases), violations


def _spans(text):
    return [(e.start, e.end) for e in detect_pii(text, doc_type="general")]


def test_adjacency_invariant_coverage_is_superset():
    cases = _cases()
    n, violations = run_invariant(_spans, cases)
    print(f"\nadjacency invariant: seed={SEED} cases={n} violations={len(violations)}")
    for v in violations[:20]:
        print("  VIOLATION", repr(v[0]), "item", repr(v[1]), "missing", v[2])
    assert n >= 3000
    assert violations == []


# --- no coverage lost against the reviewed baseline ---------------------------

CORPUS = Path(__file__).parent / "data" / "baseline_covered_spans.json"


def test_coverage_is_superset_of_baseline():
    """Frozen from 63c332d by tests/data/make_baseline_corpus.py, so no git
    checkout is needed. A missing corpus is a failure, never a skip."""
    if not CORPUS.is_file():
        pytest.fail(f"baseline corpus missing: {CORPUS}")
    cases = json.loads(CORPUS.read_text())["cases"]
    assert len(cases) >= 600
    lost = []
    for case in cases:
        text = case["text"]
        got = {i for e in detect_pii(text, doc_type="general")
               for i in range(e.start, e.end) if not text[i].isspace()}
        gone = sorted(set(case["covered"]) - got)
        if gone:
            lost.append((text, gone))
    print(f"\nbaseline superset: cases={len(cases)} lost={len(lost)}")
    for text, gone in lost[:10]:
        print("  LOST", repr(text), gone)
    assert lost == []
