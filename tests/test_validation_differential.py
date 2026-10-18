"""Validation output must be identical to what origin/main produced.

tests/data/validation_frozen.json holds the validated entity list (text,
label, start, end, confidence) of every document in tests/_validation_corpus,
generated once from main's validation.py. A missing file is a failure, not a
skip: without it this test would pass vacuously.
"""

import json

import pytest

from tests import _validation_corpus as corpus


def _load():
    assert corpus.FROZEN.is_file(), f"{corpus.FROZEN} is missing"
    return json.loads(corpus.FROZEN.read_text(encoding="utf-8"))


def test_frozen_set_is_large_and_matches_the_corpus():
    rows = _load()
    assert len(rows) >= 300
    assert [r["text"] for r in rows] == corpus.build_docs()
    assert any(r["validated"] for r in rows)
    assert any(not r["validated"] for r in rows)


@pytest.mark.parametrize("index", range(len(corpus.build_docs())))
def test_validated_entities_match_frozen(index):
    row = _load()[index]
    got = corpus.capture(row["text"])
    assert [list(g) for g in got] == row["validated"]
