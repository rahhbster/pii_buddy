"""Tests for Pass 3 — OpenRouter client and verifier.

Tests cover:
- Response parsing (plain JSON, code fences, embedded arrays, garbage)
- Finding extraction and confidence filtering
- Client retry logic and error handling
- Batch creation in the orchestration layer
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from pii_buddy.openrouter_client import (
    OpenRouterClient,
    OpenRouterError,
    OpenRouterResponse,
    _extract_findings,
    _items_to_findings,
)
from pii_buddy.verify_client import Finding


# -----------------------------------------------------------------------
# _extract_findings — parsing LLM response text
# -----------------------------------------------------------------------
class TestExtractFindings:
    def test_plain_json_array(self):
        """Standard JSON array should parse correctly."""
        content = '[{"text": "John Smith", "type": "PERSON", "confidence": 0.9}]'
        findings = _extract_findings(content)
        assert len(findings) == 1
        assert findings[0].text == "John Smith"
        assert findings[0].entity_type == "PERSON"
        assert findings[0].confidence == 0.9

    def test_empty_array(self):
        """Empty array means no findings."""
        findings = _extract_findings("[]")
        assert findings == []

    def test_code_fenced_json(self):
        """JSON wrapped in ```json code fences."""
        content = '```json\n[{"text": "Jane Doe", "type": "PERSON", "confidence": 0.85}]\n```'
        findings = _extract_findings(content)
        assert len(findings) == 1
        assert findings[0].text == "Jane Doe"

    def test_code_fenced_no_lang(self):
        """JSON wrapped in plain ``` code fences (no language tag)."""
        content = '```\n[{"text": "test@email.com", "type": "EMAIL", "confidence": 0.95}]\n```'
        findings = _extract_findings(content)
        assert len(findings) == 1
        assert findings[0].entity_type == "EMAIL"

    def test_json_with_surrounding_text(self):
        """LLM adds extra text around the JSON array."""
        content = 'Here are the findings:\n[{"text": "555-1234", "type": "PHONE", "confidence": 0.8}]\nThat\'s all.'
        findings = _extract_findings(content)
        assert len(findings) == 1
        assert findings[0].entity_type == "PHONE"

    def test_garbage_response(self):
        """Non-JSON garbage should return empty list."""
        findings = _extract_findings("I found no PII in the text.")
        assert findings == []

    def test_low_confidence_filtered(self):
        """Findings below 0.5 confidence should be filtered out."""
        content = '[{"text": "maybe", "type": "PERSON", "confidence": 0.3}]'
        findings = _extract_findings(content)
        assert findings == []

    def test_multiple_findings(self):
        """Multiple findings in one response."""
        content = json.dumps([
            {"text": "Alice", "type": "PERSON", "confidence": 0.9},
            {"text": "bob@test.com", "type": "EMAIL", "confidence": 0.95},
            {"text": "555-0123", "type": "PHONE", "confidence": 0.7},
        ])
        findings = _extract_findings(content)
        assert len(findings) == 3

    def test_missing_type_defaults_to_person(self):
        """If 'type' is missing, default to PERSON."""
        content = '[{"text": "John", "confidence": 0.8}]'
        findings = _extract_findings(content)
        assert len(findings) == 1
        assert findings[0].entity_type == "PERSON"

    def test_missing_confidence_defaults(self):
        """If 'confidence' is missing, default to 0.8."""
        content = '[{"text": "John", "type": "PERSON"}]'
        findings = _extract_findings(content)
        assert len(findings) == 1
        assert findings[0].confidence == 0.8


# -----------------------------------------------------------------------
# _items_to_findings
# -----------------------------------------------------------------------
class TestItemsToFindings:
    def test_non_dict_items_skipped(self):
        """Non-dict items in the list should be skipped."""
        items = [
            {"text": "valid", "type": "PERSON", "confidence": 0.9},
            "not a dict",
            42,
            None,
        ]
        findings = _items_to_findings(items)
        assert len(findings) == 1

    def test_empty_text_skipped(self):
        """Items with empty text should be skipped."""
        items = [{"text": "", "type": "PERSON", "confidence": 0.9}]
        findings = _items_to_findings(items)
        assert findings == []


# -----------------------------------------------------------------------
# OpenRouterClient._parse_response
# -----------------------------------------------------------------------
class TestParseResponse:
    def test_success_response(self, openrouter_success_response):
        resp = OpenRouterClient._parse_response(openrouter_success_response)
        assert isinstance(resp, OpenRouterResponse)
        assert len(resp.findings) == 2
        assert resp.model == "meta-llama/llama-3.1-8b-instruct:free"

    def test_empty_choices(self):
        resp = OpenRouterClient._parse_response({"choices": []})
        assert resp.findings == []

    def test_no_choices_key(self):
        resp = OpenRouterClient._parse_response({})
        assert resp.findings == []

    def test_fenced_response(self, openrouter_fenced_response):
        resp = OpenRouterClient._parse_response(openrouter_fenced_response)
        assert len(resp.findings) == 1
        assert resp.findings[0].text == "Dr. Amanda Chen"


# -----------------------------------------------------------------------
# OpenRouterClient.check_pii — HTTP behavior
# -----------------------------------------------------------------------
class TestCheckPii:
    @patch("pii_buddy.openrouter_client._require_httpx")
    def test_success(self, mock_require, openrouter_success_response):
        """Successful API call returns parsed findings."""
        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = openrouter_success_response
        mock_resp.raise_for_status.return_value = None
        mock_httpx.post.return_value = mock_resp
        mock_require.return_value = mock_httpx

        client = OpenRouterClient(api_key="test-key")
        result = client.check_pii("Some text with John Smith in it")

        assert len(result.findings) == 2
        mock_httpx.post.assert_called_once()

    @patch("pii_buddy.openrouter_client._require_httpx")
    def test_4xx_no_retry(self, mock_require):
        """4xx errors should raise immediately without retry."""
        import httpx

        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=mock_resp,
        )
        mock_httpx.post.return_value = mock_resp
        mock_httpx.HTTPStatusError = httpx.HTTPStatusError
        mock_httpx.RequestError = httpx.RequestError
        mock_require.return_value = mock_httpx

        client = OpenRouterClient(api_key="bad-key")
        with pytest.raises(OpenRouterError, match="API error 401"):
            client.check_pii("test")

        # Should NOT retry on 4xx
        assert mock_httpx.post.call_count == 1

    @patch("time.sleep")
    @patch("pii_buddy.openrouter_client._require_httpx")
    def test_5xx_retries(self, mock_require, mock_sleep):
        """5xx errors should trigger retries."""
        import httpx

        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=mock_resp,
        )
        mock_httpx.post.return_value = mock_resp
        mock_httpx.HTTPStatusError = httpx.HTTPStatusError
        mock_httpx.RequestError = httpx.RequestError
        mock_require.return_value = mock_httpx

        client = OpenRouterClient(api_key="test-key")
        with pytest.raises(OpenRouterError, match="API error 500"):
            client.check_pii("test")

        # Should retry _MAX_RETRIES times (2 retries + 1 initial = 3 total)
        assert mock_httpx.post.call_count == 3


# -----------------------------------------------------------------------
# openrouter_verify_and_patch — orchestration
# -----------------------------------------------------------------------
class TestOpenRouterVerifyAndPatch:
    @patch("pii_buddy.openrouter_verifier.OpenRouterClient")
    def test_applies_findings(self, MockClient, sample_redacted_text, sample_mapping, settings_with_openrouter):
        """Findings from OpenRouter should be applied to text."""
        from pii_buddy.openrouter_verifier import openrouter_verify_and_patch

        mock_client = MockClient.return_value
        mock_client.check_pii.return_value = OpenRouterResponse(
            findings=[
                Finding(shard_id="", text="Amanda Chen", entity_type="PERSON",
                        confidence=0.9, start_offset=0, end_offset=0),
            ],
            model="test",
        )

        patched, mapping = openrouter_verify_and_patch(
            sample_redacted_text, sample_mapping, settings_with_openrouter
        )

        assert "Amanda Chen" not in patched

    @patch("pii_buddy.openrouter_verifier.OpenRouterClient")
    def test_graceful_degradation(self, MockClient, sample_redacted_text, sample_mapping, settings_with_openrouter):
        """On API error, original text should be returned unchanged."""
        from pii_buddy.openrouter_verifier import openrouter_verify_and_patch

        mock_client = MockClient.return_value
        mock_client.check_pii.side_effect = OpenRouterError("Network error")

        patched, mapping = openrouter_verify_and_patch(
            sample_redacted_text, sample_mapping, settings_with_openrouter
        )

        assert patched == sample_redacted_text
        assert mapping == sample_mapping

    @patch("pii_buddy.openrouter_verifier.OpenRouterClient")
    def test_no_findings_unchanged(self, MockClient, sample_redacted_text, sample_mapping, settings_with_openrouter):
        """When OpenRouter finds nothing, text should be unchanged."""
        from pii_buddy.openrouter_verifier import openrouter_verify_and_patch

        mock_client = MockClient.return_value
        mock_client.check_pii.return_value = OpenRouterResponse(findings=[], model="test")

        patched, mapping = openrouter_verify_and_patch(
            sample_redacted_text, sample_mapping, settings_with_openrouter
        )

        assert patched == sample_redacted_text

    @patch("pii_buddy.openrouter_verifier.OpenRouterClient")
    def test_batching(self, MockClient, settings_with_openrouter):
        """Long text should be split into multiple batches."""
        from pii_buddy.openrouter_verifier import openrouter_verify_and_patch

        # Create text with many sentences to force multiple batches
        sentences = [f"Sentence {i} about the project." for i in range(20)]
        text = " ".join(sentences)
        mapping = {"tags": {}, "persons": {}}

        mock_client = MockClient.return_value
        mock_client.check_pii.return_value = OpenRouterResponse(findings=[], model="test")

        openrouter_verify_and_patch(text, mapping, settings_with_openrouter)

        # Should have been called multiple times (one per batch)
        assert mock_client.check_pii.call_count >= 1
