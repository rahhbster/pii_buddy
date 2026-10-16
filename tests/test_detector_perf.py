"""Every detector regex and the overlap resolver must stay linear on
adversarial single-line input: t(100 KB) / t(50 KB) must stay near 2 (a
machine-independent check) with one generous absolute backstop at 400 KB."""

import pytest

from pii_buddy import detector
from tests._scaling import assert_scales_linearly

SIZE = 400_000

_UNITS = [
    "a-b.", "-a.", "a.b-c.d-", "a-b-c.", "x-", "9-", "4111-", "a@b.co-",
    "-a@b.co.", "1-2-3-", "4111-1111-1111-1111-", "http://a-", "+1 ",
    "a.", "a@", "@a", "@a.", "1.", "1.1.", "1-", "12/", "1/1/", "1990-12-",
    "a.b@", "www.", "a.com.", "a.com-", "x.co/", "4111 ", "4111 ",
    "123-45-", "123 45 ", "(415) ", "+33 1 ", "+", "-", ".", "@", " ", "1",
    "a", "0.0.", "255.", "Jan 1, ", "1st ", "12 Main St ", "ID ", "CA 9",
    "AB-CD-", "AB1234", "12345678", "a-", "-1", "a.b.c.d.e.f.g.h.i.j-",
    "a-" * 30 + ".", "4111-1111-1111-", "4111–1111–", "1-1-1-1-",
    "@a-b.", "a@b-", "x@y.z.", "-@",
    # glued-email starts after "+ . _ %" and the card scanner
    "a+", "a_", "a%", "a@b.co+", "a@b.co.", "a@b.co_", "@a@", "@a@b.co",
    "a.b+c_d%", "4111-1111-1111-1111326 ", "98403782 822463 10005678870 ",
    "123 45 67894111 1111 1111 1111 ", "4111 1111 1111 111 1 ",
    "4111111111111111 ", "41111111 11111111 ", "12345678 ", "1234 ",
    "4111 1111 1111 1111" + "12345678" + " ", "3782 8224 6310 005 ",
]


def _patterns():
    pats = [(p, p in detector._OVERLAPPING) for p, _ in detector.REGEX_PATTERNS]
    pats.append((detector.INTL_PHONE_WIDE_RE, False))
    return pats


def _work(text):
    for pat, overlapping in _patterns():
        check = detector._SPAN_CHECKS.get(pat)
        for m in detector._iter_matches(pat, text, overlapping):
            if check:
                check(m, text)
    ents = detector._regex_entities(text)
    detector._resolve_overlaps(ents, text)


@pytest.mark.parametrize("unit", _UNITS, ids=[repr(u)[:24] for u in _UNITS])
def test_every_pattern_and_resolver_linear_at_400kb(unit):
    assert_scales_linearly(
        _work, lambda size: unit * max(1, size // len(unit)), repr(unit)[:24],
        small=25_000, backstop_size=SIZE,
    )
