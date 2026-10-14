"""A PERSON span that overlaps a regex hit must be trimmed, not dropped."""

from pii_buddy.detector import detect_pii


def _by_label(text):
    out = {}
    for e in detect_pii(text):
        out.setdefault(e.label, []).append(e.text)
    return out


def test_name_then_email_on_next_line_keeps_name():
    text = "Jane Q. Testperson\njane@example.invalid | (555) 010-1234\nSenior Engineer\n"
    found = _by_label(text)
    assert found.get("PERSON") == ["Jane Q. Testperson"]
    assert found.get("EMAIL") == ["jane@example.invalid"]
    assert found.get("PHONE") == ["(555) 010-1234"]


def test_name_and_email_only_keeps_name():
    found = _by_label("Jane Q. Testperson\njane@example.invalid\n")
    assert found.get("PERSON") == ["Jane Q. Testperson"]
    assert found.get("EMAIL") == ["jane@example.invalid"]


def test_name_and_phone_same_line_keeps_name():
    found = _by_label("Contact Jane Q. Testperson 555-010-1234 for details.\n")
    assert found.get("PERSON") == ["Jane Q. Testperson"]
    assert found.get("PHONE") == ["555-010-1234"]


def test_person_offsets_match_text():
    text = "Jane Q. Testperson\njane@example.invalid\n"
    person = [e for e in detect_pii(text) if e.label == "PERSON"][0]
    assert text[person.start:person.end] == person.text
