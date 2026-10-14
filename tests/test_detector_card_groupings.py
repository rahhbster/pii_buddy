"""CARD matching: standard card groupings only, never arbitrary hyphenated IDs.

Separated numbers count as a card only in 4-4-4-4, 4-6-5, 4-6-4 or
4-4-4-4-3 grouping (plus unseparated 13-19 digit runs), and Luhn still gates
every match. All numbers are well-known test or invented values."""

import itertools

import pytest

from pii_buddy.detector import detect_pii


def _ents(text):
    return [(e.label, e.text) for e in detect_pii(text, doc_type="general")]


def _cards(text):
    return [t for l, t in _ents(text) if l == "CARD"]


@pytest.mark.parametrize("text", [
    "INV-5642-29793087-1525",
    "ref 91-4066-4944-80939-07",
    "INV-8552-80387294-1242",
    "PO-0033-22453832-3640",
    "ref 5744-7621-68275217",
])
def test_arbitrary_hyphenated_ids_are_not_cards(text):
    assert _cards(text) == []


_NUMBERS = [
    ("4111", "1111", "1111", "1111"),
    ("5500", "0000", "0000", "0004"),
    ("3782", "822463", "10005"),
    ("3056", "930902", "5904"),
    ("6304", "9000", "1740", "0000", "001"),
]
_SEPS = [" ", "-", " ", "–", " "]
_AROUND = [("", ""), ("-", ""), ("", "-"), ("_", "_"), ("|", "|"), ("(", ")"),
           (" ", " "), ("ab-", "-cd"), ("x_", ""), ("", "_y"), (":", ";")]


@pytest.mark.parametrize(
    "groups,sep,around",
    list(itertools.product(_NUMBERS, _SEPS, _AROUND)),
)
def test_real_card_groupings_redacted_next_to_separators(groups, sep, around):
    card = sep.join(groups)
    pre, post = around
    text = f"{pre}{card}{post}"
    assert card in _cards(text), (text, _ents(text))


@pytest.mark.parametrize("card", [
    "4222222222222", "4111111111111111", "6011111111111117",
    "6304900017400000001",
])
@pytest.mark.parametrize("around", _AROUND)
def test_unseparated_luhn_runs_redacted_next_to_separators(card, around):
    pre, post = around
    text = f"{pre}{card}{post}"
    assert card in _cards(text), (text, _ents(text))


def test_card_with_trailing_short_group_still_absorbed():
    assert _cards("card 4111 1111 1111 1111 123 ok") == ["4111 1111 1111 1111 123"]


def _covered(text):
    return {i for e in detect_pii(text, doc_type="general")
            for i in range(e.start, e.end) if not text[i].isspace()}


@pytest.mark.parametrize("text,card", [
    ("+33 1 23 45 67 894111 1111 1111 1111", "4111 1111 1111 1111"),
    ("+33 1 23 45 67 894111 1111 1111 1111",
     "4111 1111 1111 1111"),
    ("4111 1111 1111 1111078 05", "4111 1111 1111 1111"),
    ("Boise, ID 83702-4111111111111111", "4111111111111111"),
])
def test_card_glued_to_neighbouring_digits_is_fully_covered(text, card):
    covered = _covered(text)
    start = text.index(card)
    for i in range(start, start + len(card)):
        if not text[i].isspace():
            assert i in covered, (text, i)


@pytest.mark.parametrize("text,date", [
    ("Boise, ID 83702-4111111111111111", "83702-"),
    ("10001-0001_5368 4891 5817 2437", "10001-0001_"),
    ("4425–0862–0541–93|1990-12-25T10:00:00", "1990-12"),
])
def test_date_remainder_beside_a_card_is_kept(text, date):
    covered = _covered(text)
    start = text.index(date)
    assert all(i in covered for i in range(start, start + len(date))
               if not text[i].isspace()), (text, _ents(text))


def test_card_tail_does_not_hide_the_date_that_follows_it():
    # "020 7946" is read as a date; the card's trailing-group absorption takes
    # "020" and the rest of the date must still be redacted.
    text = "6554 5738 3778 3458 020 7946 0958"
    covered = _covered(text)
    assert all(i in covered for i in range(0, text.index("0958") - 1)
               if not text[i].isspace())
