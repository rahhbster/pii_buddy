"""Tag-collision and round-trip tests for redactor.py and restorer.py."""

import json
import re

import pytest

from pii_buddy.detector import detect_pii
from pii_buddy.redactor import redact
from pii_buddy.restorer import restore
from tests.conftest import FakeEntity


def _entities(text, spans):
    """Build entities for every occurrence of each (substring, label) pair."""
    found = []
    for needle, label in spans:
        for m in re.finditer(re.escape(needle), text):
            found.append(FakeEntity(m.group(), label, m.start(), m.end()))
    return sorted(found, key=lambda e: e.start)


def _restore(redacted, mapping, tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps(mapping), encoding="utf-8")
    return restore(redacted, path)


def _round_trip(text, spans, tmp_path):
    redacted, mapping = redact(text, _entities(text, spans))
    return redacted, mapping, _restore(redacted, mapping, tmp_path)


class TestNameIsSubstringOfAnotherWord:
    def test_longer_word_is_left_alone(self, tmp_path):
        text = "Ann Testperson read the Annual report. JoAnn Smith agreed."
        redacted, _, restored = _round_trip(
            text, [("Ann Testperson", "PERSON")], tmp_path
        )
        assert "Annual" in redacted
        assert "JoAnn" in redacted
        assert restored == text

    def test_name_part_inside_tag_text_is_not_replaced(self, tmp_path):
        text = "Ema Lindgren wrote to jane@example.invalid about Ema Lindgren."
        redacted, _, restored = _round_trip(
            text,
            [("Ema Lindgren", "PERSON"), ("jane@example.invalid", "EMAIL")],
            tmp_path,
        )
        assert "<<EMAIL_1>>" in redacted
        assert redacted.count("<<") == 1
        assert restored == text


class TestIdenticalInitials:
    def test_two_people_get_distinct_tags_and_round_trip(self, tmp_path):
        text = (
            "Ema Lindgren met Erik Lund. Then Ema Lindgren emailed "
            "jane@example.invalid and Erik Lund replied."
        )
        redacted, mapping, restored = _round_trip(
            text,
            [("Ema Lindgren", "PERSON"), ("Erik Lund", "PERSON"),
             ("jane@example.invalid", "EMAIL")],
            tmp_path,
        )
        person_tags = {t for t in mapping["tags"] if t.startswith("<NAME")}
        assert len(person_tags) == 2
        assert restored == text

    def test_each_tag_appears_exactly_for_its_person(self):
        text = "Ema Lindgren and Erik Lund."
        redacted, mapping = redact(
            text,
            _entities(text, [("Ema Lindgren", "PERSON"), ("Erik Lund", "PERSON")]),
        )
        for tag in mapping["tags"]:
            assert redacted.count(tag) == 1


class TestLiteralTagTextInSource:
    def test_literal_email_tag_survives_round_trip(self, tmp_path):
        text = "Template uses <<EMAIL_1>> but real is jane@example.invalid."
        _, mapping, restored = _round_trip(
            text, [("jane@example.invalid", "EMAIL")], tmp_path
        )
        assert restored == text
        assert "<<EMAIL_1>>" not in mapping["tags"]

    def test_literal_name_tag_survives_round_trip(self, tmp_path):
        text = "Legend: <NAME JQT> means a person. Jane Q. Testperson signed."
        _, mapping, restored = _round_trip(
            text, [("Jane Q. Testperson", "PERSON")], tmp_path
        )
        assert restored == text
        assert "<NAME JQT>" not in mapping["tags"]

    def test_restore_is_single_pass(self, tmp_path):
        mapping = {"tags": {"<<EMAIL_1>>": "<<PHONE_1>>", "<<PHONE_1>>": "555-0100"}}
        restored = _restore("<<EMAIL_1>> / <<PHONE_1>>", mapping, tmp_path)
        assert restored == "<<PHONE_1>> / 555-0100"


class TestNameInEmailLocalPart:
    def test_email_entity_is_not_rewritten_by_name_pass(self, tmp_path):
        text = "Jane Testperson <jane.testperson@example.invalid> wrote."
        redacted, _, restored = _round_trip(
            text,
            [("Jane Testperson", "PERSON"),
             ("jane.testperson@example.invalid", "EMAIL")],
            tmp_path,
        )
        assert "<<EMAIL_1>>" in redacted
        assert "example.invalid" not in redacted
        assert restored == text

    def test_name_in_undetected_local_part_is_still_redacted(self):
        text = "Ema Lindgren owns ema@example.invalid."
        redacted, _ = redact(text, _entities(text, [("Ema Lindgren", "PERSON")]))
        assert redacted == "<NAME EL> owns <NAME EL>@example.invalid."


ROUND_TRIP_TABLE = [
    "Ema Lindgren, Erik Lund and jane@example.invalid.",
    "(Ema Lindgren), <Erik Lund>; \"Ema Lindgren\" -- jane@example.invalid!",
    "Annual review for Ann Testperson, not JoAnn Smith or Annabel Reed.",
    "Call 555-867-5309 or write to jane@example.invalid, Ema Lindgren.",
    "Literal <<EMAIL_1>> and <NAME EL> then Ema Lindgren at jane@example.invalid.",
    "<<EMAIL_<<EMAIL_1>>",
]


@pytest.mark.parametrize("text", ROUND_TRIP_TABLE)
def test_detected_entities_round_trip(text, tmp_path):
    redacted, mapping = redact(text, detect_pii(text))
    assert _restore(redacted, mapping, tmp_path) == text
