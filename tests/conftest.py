"""Shared fixtures for PII Buddy tests."""

import json
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Minimal entity dataclass (mirrors detector output)
# ---------------------------------------------------------------------------
@dataclass
class FakeEntity:
    text: str
    label: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Settings fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def default_settings():
    """Return a Settings instance with all defaults."""
    from pii_buddy.settings import Settings
    return Settings.defaults()


# ---------------------------------------------------------------------------
# Sample texts and mappings
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_text():
    """A raw text with PII."""
    return (
        "Dear Mr. Singh,\n\n"
        "This is to confirm that Atul Singh and Robert Merrill "
        "will attend the meeting on March 5. Robert's assistant "
        "will prepare the agenda.\n\n"
        "Best,\nDr. Amanda Chen"
    )


@pytest.fixture
def sample_redacted_text():
    """Text after Pass 1 (spaCy + regex) — deliberately leaves some PII."""
    return (
        "Dear Mr. Singh,\n\n"
        "This is to confirm that <NAME AS> and <NAME RM> "
        "will attend the meeting on March 5. Robert's assistant "
        "will prepare the agenda.\n\n"
        "Best,\nDr. Amanda Chen"
    )


@pytest.fixture
def sample_mapping():
    """Mapping after Pass 1 — matches sample_redacted_text."""
    return {
        "tags": {
            "<NAME AS>": "Atul Singh",
            "<NAME RM>": "Robert Merrill",
        },
        "persons": {
            "Atul Singh": "<NAME AS>",
            "Robert Merrill": "<NAME RM>",
            "Atul": "<NAME AS>",
            "Singh": "<NAME AS>",
            "Robert": "<NAME RM>",
            "Merrill": "<NAME RM>",
        },
    }


@pytest.fixture
def sample_redacted_clean():
    """Fully redacted text (all PII caught by Pass 1)."""
    return (
        "Dear Mr. <NAME AS>,\n\n"
        "This is to confirm that <NAME AS> and <NAME RM> "
        "will attend the meeting on March 5. <NAME RM>'s assistant "
        "will prepare the agenda.\n\n"
        "Best,\n<NAME AC>"
    )
