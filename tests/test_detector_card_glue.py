"""Short-last-group cards (4-4-4-1/2/3) with glued digits, and glued pairs.

Every digit of a Luhn-valid card must be covered, including digits glued to
the last group and a second card glued straight onto the first. All numbers
are generated test values."""

import random

import pytest

from pii_buddy.detector import detect_pii


def _luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def _pan(rng, length: int) -> str:
    body = rng.choice("3456") + "".join(
        rng.choice("0123456789") for _ in range(length - 2))
    return body + _luhn_digit(body)


def _group(pan: str, shape) -> list[str]:
    out, pos = [], 0
    for n in shape:
        out.append(pan[pos:pos + n])
        pos += n
    return out


def _uncovered_digits(text: str) -> int:
    covered = {i for e in detect_pii(text, doc_type="general")
               for i in range(e.start, e.end)}
    return sum(1 for i, c in enumerate(text) if c.isdigit() and i not in covered)


@pytest.mark.parametrize("text", [
    "3782 8224 6310 005123",
    "3782 8224 6310 0051234",
    "4222 2222 2222 2123",
    "3056 9309 0259 04123",
    "3056 9309 0259 0412345678",
    "4222 2222 2222 23056 9309 0259 04",
])
def test_short_last_group_with_glued_digits_fully_covered(text):
    assert _uncovered_digits(text) == 0, text


_SHORT = [(15, (4, 4, 4, 3)), (14, (4, 4, 4, 2)), (13, (4, 4, 4, 1))]


@pytest.mark.parametrize("length,shape", _SHORT)
def test_short_last_group_glued_digits_random(length, shape):
    rng = random.Random(20261015 + length)
    leaks = []
    for _ in range(300):
        groups = _group(_pan(rng, length), shape)
        glued = "".join(rng.choice("0123456789")
                        for _ in range(rng.randint(1, 8)))
        text = "ref " + " ".join(groups[:-1] + [groups[-1] + glued]) + " ok"
        if _uncovered_digits(text):
            leaks.append(text)
    assert not leaks, (len(leaks), leaks[:3])


@pytest.mark.parametrize("length,shape", _SHORT)
def test_glued_adjacent_cards_leave_no_card_digit_visible(length, shape):
    rng = random.Random(20261016 + length)
    seconds = [(16, (4, 4, 4, 4)), (15, (4, 6, 5)), (14, (4, 6, 4)),
               (15, (4, 4, 4, 3)), (14, (4, 4, 4, 2)), (13, (4, 4, 4, 1)),
               (16, (4, 4, 8)), (16, (8, 8))]
    leaks = []
    for i in range(500):
        first = _group(_pan(rng, length), shape)
        n2, s2 = seconds[i % len(seconds)]
        second = _group(_pan(rng, n2), s2)
        text = " ".join(first[:-1] + [first[-1] + second[0]] + second[1:])
        if _uncovered_digits(text):
            leaks.append(text)
    assert not leaks, (len(leaks), leaks[:3])
