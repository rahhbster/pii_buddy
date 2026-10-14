"""Smoke test: the real spaCy pipeline loads and finds a PERSON.

Every other test mocks or bypasses the detector, so without this CI
would stay green even if model loading or NER were broken.
"""

from pii_buddy.detector import detect_pii


def test_detect_pii_finds_a_person():
    entities = detect_pii("Alex Sample met Rory Mockdata")
    persons = [e for e in entities if e.label == "PERSON"]
    assert persons, f"no PERSON detected, got {entities!r}"
