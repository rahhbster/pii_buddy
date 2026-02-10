"""HTTP client for the OpenRouter chat completions API.

Sends partially-redacted text shards to an LLM for PII detection.
Mirrors the verify_client.py interface but uses OpenRouter's
OpenAI-compatible endpoint.
"""

import json
import logging
from dataclasses import dataclass, field

from .verify_client import Finding

logger = logging.getLogger("pii_buddy")

_TIMEOUT = 60
_MAX_RETRIES = 2
_RETRY_BACKOFF = 1.0

_DEFAULT_MODEL = "meta-llama/llama-3.1-8b-instruct:free"
_DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1"

_SYSTEM_PROMPT = """\
You are a PII detection assistant. The following text has been partially redacted \
(existing tags look like <NAME XX> or <<TYPE_N>>). Identify any REMAINING personally \
identifiable information that was missed.

For each PII found, return a JSON array of objects:
[{"text": "exact text", "type": "PERSON", "confidence": 0.9}]

Valid types: PERSON, EMAIL, PHONE, ADDRESS, SSN, DOB, URL

If nothing was missed, return: []
Return ONLY the JSON array, no other text."""


class OpenRouterError(Exception):
    """Raised when the OpenRouter API returns an error."""


@dataclass
class OpenRouterResponse:
    """Parsed response from an OpenRouter batch."""
    findings: list[Finding] = field(default_factory=list)
    model: str = ""


def _require_httpx():
    try:
        import httpx
        return httpx
    except ImportError:
        raise OpenRouterError(
            "OpenRouter verification requires the 'httpx' package. "
            "Install it with: pip install httpx"
        )


class OpenRouterClient:
    """Client for the OpenRouter chat completions API."""

    def __init__(
        self,
        api_key: str,
        model: str = _DEFAULT_MODEL,
        endpoint: str = _DEFAULT_ENDPOINT,
    ):
        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint.rstrip("/")

    def check_pii(self, text_batch: str) -> OpenRouterResponse:
        """Send a batch of text to the LLM for PII detection.

        Args:
            text_batch: Combined text from multiple shards to check.

        Returns:
            OpenRouterResponse with findings.

        Raises:
            OpenRouterError on network or API errors.
        """
        httpx = _require_httpx()

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": text_batch},
            ],
            "temperature": 0.0,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_err = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = httpx.post(
                    f"{self.endpoint}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                return self._parse_response(resp.json())

            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                body = e.response.text
                if 400 <= code < 500:
                    raise OpenRouterError(f"API error {code}: {body}") from e
                last_err = OpenRouterError(f"API error {code}: {body}")

            except httpx.RequestError as e:
                last_err = OpenRouterError(f"Request failed: {e}")

            if attempt < _MAX_RETRIES:
                import time
                time.sleep(_RETRY_BACKOFF * (attempt + 1))

        raise last_err

    @staticmethod
    def _parse_response(data: dict) -> OpenRouterResponse:
        """Parse the OpenRouter chat completion response."""
        choices = data.get("choices", [])
        if not choices:
            return OpenRouterResponse()

        content = choices[0].get("message", {}).get("content", "").strip()
        model = data.get("model", "")

        findings = _extract_findings(content)
        return OpenRouterResponse(findings=findings, model=model)


def _extract_findings(content: str) -> list[Finding]:
    """Extract Finding objects from LLM response text.

    Tries to parse JSON array from the response, handling cases where
    the LLM wraps it in markdown code fences or adds extra text.
    """
    # Try direct JSON parse first
    try:
        items = json.loads(content)
        if isinstance(items, list):
            return _items_to_findings(items)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try extracting JSON from markdown code fences
    import re
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
    if fence_match:
        try:
            items = json.loads(fence_match.group(1))
            if isinstance(items, list):
                return _items_to_findings(items)
        except (json.JSONDecodeError, ValueError):
            pass

    # Try finding a JSON array anywhere in the text
    bracket_match = re.search(r"\[.*\]", content, re.DOTALL)
    if bracket_match:
        try:
            items = json.loads(bracket_match.group(0))
            if isinstance(items, list):
                return _items_to_findings(items)
        except (json.JSONDecodeError, ValueError):
            pass

    return []


def _items_to_findings(items: list) -> list[Finding]:
    """Convert parsed JSON items to Finding objects."""
    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        text = item.get("text", "").strip()
        entity_type = item.get("type", "PERSON").upper()
        confidence = float(item.get("confidence", 0.8))
        if text and confidence >= 0.5:
            findings.append(Finding(
                shard_id="",
                text=text,
                entity_type=entity_type,
                confidence=confidence,
                start_offset=0,
                end_offset=0,
            ))
    return findings
