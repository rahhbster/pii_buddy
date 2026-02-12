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


@pytest.fixture
def settings_with_verify(default_settings):
    """Settings with cloud verification enabled."""
    default_settings.verify_enabled = True
    default_settings.verify_api_key = "test-key-12345"
    default_settings.verify_endpoint = "https://api.piibuddy.com/v1"
    default_settings.verify_confidence = 0.7
    return default_settings


@pytest.fixture
def settings_with_openrouter(default_settings):
    """Settings with OpenRouter enabled."""
    default_settings.openrouter_enabled = True
    default_settings.openrouter_api_key = "sk-or-test-key"
    default_settings.openrouter_model = "meta-llama/llama-3.1-8b-instruct:free"
    default_settings.openrouter_endpoint = "https://openrouter.ai/api/v1"
    return default_settings


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


# ---------------------------------------------------------------------------
# Mock httpx responses
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_httpx_response():
    """Factory for mock httpx responses."""
    def _make(status_code=200, json_data=None, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text or json.dumps(json_data or {})
        resp.json.return_value = json_data or {}
        if status_code >= 400:
            import httpx
            resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                message=f"HTTP {status_code}",
                request=MagicMock(),
                response=resp,
            )
        else:
            resp.raise_for_status.return_value = None
        return resp
    return _make


# ---------------------------------------------------------------------------
# Verify API response fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def verify_api_success_response():
    """Successful verify API response with findings and credit info."""
    return {
        "results": [
            {
                "shard_id": "s1",
                "findings": [
                    {
                        "text": "Amanda Chen",
                        "type": "PERSON",
                        "confidence": 0.95,
                        "start_offset": 10,
                        "end_offset": 21,
                    }
                ],
            }
        ],
        "usage": {
            "shards_processed": 5,
            "tokens_used": 1200,
            "cost_cents": 0.5,
            "credits_remaining": 950,
        },
    }


@pytest.fixture
def verify_api_low_credits_response():
    """Verify response with low credit balance."""
    return {
        "results": [],
        "usage": {
            "shards_processed": 5,
            "tokens_used": 800,
            "cost_cents": 0.3,
            "credits_remaining": 15,
        },
    }


@pytest.fixture
def verify_api_no_credits_response():
    """Verify response body for 402 (insufficient credits)."""
    return {
        "error": "insufficient_credits",
        "message": "You have 0 credits remaining. Purchase more at github.com/rahhbster/pii_buddy",
        "credits_remaining": 0,
        "purchase_url": "https://app.piibuddy.com/buy",
    }


# ---------------------------------------------------------------------------
# OpenRouter response fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def openrouter_success_response():
    """Successful OpenRouter chat completion with PII findings."""
    return {
        "choices": [
            {
                "message": {
                    "content": json.dumps([
                        {"text": "Amanda Chen", "type": "PERSON", "confidence": 0.9},
                        {"text": "Singh", "type": "PERSON", "confidence": 0.85},
                    ])
                }
            }
        ],
        "model": "meta-llama/llama-3.1-8b-instruct:free",
    }


@pytest.fixture
def openrouter_empty_response():
    """OpenRouter response with no findings."""
    return {
        "choices": [{"message": {"content": "[]"}}],
        "model": "meta-llama/llama-3.1-8b-instruct:free",
    }


@pytest.fixture
def openrouter_fenced_response():
    """OpenRouter response with JSON wrapped in code fences."""
    return {
        "choices": [
            {
                "message": {
                    "content": "```json\n[{\"text\": \"Dr. Amanda Chen\", \"type\": \"PERSON\", \"confidence\": 0.92}]\n```"
                }
            }
        ],
        "model": "meta-llama/llama-3.1-8b-instruct:free",
    }
