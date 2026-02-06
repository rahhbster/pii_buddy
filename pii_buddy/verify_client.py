"""HTTP client for the PII Buddy Verify API."""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("pii_buddy")

# Seconds before the verify request times out
_VERIFY_TIMEOUT = 60
_HEALTH_TIMEOUT = 5
_USAGE_TIMEOUT = 10

# Retry configuration
_MAX_RETRIES = 2
_RETRY_BACKOFF = 1.0  # seconds


class VerifyError(Exception):
    """Raised when the Verify API returns an error."""


@dataclass
class Finding:
    """A single PII finding from verification."""
    shard_id: str
    text: str
    entity_type: str
    confidence: float
    start_offset: int
    end_offset: int


@dataclass
class VerifyResponse:
    """Parsed response from the Verify API."""
    findings: list[Finding] = field(default_factory=list)
    shards_processed: int = 0
    tokens_used: int = 0
    cost_cents: float = 0.0


def _require_httpx():
    """Import httpx or raise a helpful error."""
    try:
        import httpx
        return httpx
    except ImportError:
        raise VerifyError(
            "Cloud verification requires the 'httpx' package. "
            "Install it with: pip install httpx"
        )


class VerifyClient:
    """Client for the PII Buddy Verify API."""

    def __init__(self, api_key: str, endpoint: str = "https://api.piibuddy.dev/v1"):
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")

    def verify(
        self,
        shards,
        context: dict,
        confidence_threshold: float = 0.7,
    ) -> VerifyResponse:
        """Send shards to the Verify API and return findings.

        Args:
            shards: list of Shard objects (including canaries — server
                    cannot distinguish them).
            context: dict with entity_counts and document_type.
            confidence_threshold: minimum confidence for returned findings.

        Returns:
            VerifyResponse with findings and usage info.

        Raises:
            VerifyError on network or API errors.
        """
        httpx = _require_httpx()

        payload = {
            "shards": [
                {"id": s.id, "text": s.text, "context": context}
                for s in shards
            ],
            "options": {
                "confidence_threshold": confidence_threshold,
            },
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_err = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = httpx.post(
                    f"{self.endpoint}/verify",
                    json=payload,
                    headers=headers,
                    timeout=_VERIFY_TIMEOUT,
                )
                resp.raise_for_status()
                return self._parse_response(resp.json())

            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                body = e.response.text
                # Don't retry client errors (auth, quota, validation)
                if 400 <= code < 500:
                    raise VerifyError(f"API error {code}: {body}") from e
                last_err = VerifyError(f"API error {code}: {body}")

            except httpx.RequestError as e:
                last_err = VerifyError(f"Request failed: {e}")

            # Exponential-ish backoff for retryable errors
            if attempt < _MAX_RETRIES:
                import time
                time.sleep(_RETRY_BACKOFF * (attempt + 1))

        raise last_err

    def check_usage(self) -> dict:
        """Query current usage/quota. Returns raw API response dict."""
        httpx = _require_httpx()
        resp = httpx.get(
            f"{self.endpoint}/usage",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=_USAGE_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def health_check(self) -> bool:
        """Check API availability. Returns True if healthy."""
        httpx = _require_httpx()
        try:
            resp = httpx.get(f"{self.endpoint}/health", timeout=_HEALTH_TIMEOUT)
            return resp.status_code == 200
        except Exception:
            return False

    @staticmethod
    def _parse_response(data: dict) -> VerifyResponse:
        """Parse the raw API JSON into a VerifyResponse."""
        findings = []
        for result in data.get("results", []):
            shard_id = result.get("shard_id", "")
            for f in result.get("findings", []):
                findings.append(Finding(
                    shard_id=shard_id,
                    text=f["text"],
                    entity_type=f["type"],
                    confidence=f["confidence"],
                    start_offset=f.get("start_offset", 0),
                    end_offset=f.get("end_offset", 0),
                ))

        usage = data.get("usage", {})
        return VerifyResponse(
            findings=findings,
            shards_processed=usage.get("shards_processed", 0),
            tokens_used=usage.get("tokens_used", 0),
            cost_cents=usage.get("cost_cents", 0.0),
        )
