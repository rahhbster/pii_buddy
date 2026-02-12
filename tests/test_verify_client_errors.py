"""Tests for verify_client.py error specialization.

These tests define acceptance criteria for specialized error handling:
- 401 → InvalidAPIKeyError
- 402 → InsufficientCreditsError (with credits_remaining and purchase_url)
- 429 → RateLimitError (with retry_after)
- credits_remaining in VerifyResponse
- check_usage returns balance info

These tests are written BEFORE the implementation exists.
They will fail until we add the specialized exception classes and
update the error handling in verify_client.py.
"""

import json
from unittest.mock import MagicMock, patch

import pytest


# -----------------------------------------------------------------------
# Specialized exception classes (to be implemented)
# -----------------------------------------------------------------------
class TestExceptionClasses:
    def test_invalid_api_key_error_exists(self):
        """InvalidAPIKeyError should be importable from verify_client."""
        from pii_buddy.verify_client import InvalidAPIKeyError
        assert issubclass(InvalidAPIKeyError, Exception)

    def test_insufficient_credits_error_exists(self):
        """InsufficientCreditsError should be importable from verify_client."""
        from pii_buddy.verify_client import InsufficientCreditsError
        assert issubclass(InsufficientCreditsError, Exception)

    def test_insufficient_credits_has_fields(self):
        """InsufficientCreditsError should carry credits_remaining and purchase_url."""
        from pii_buddy.verify_client import InsufficientCreditsError
        err = InsufficientCreditsError(
            "No credits",
            credits_remaining=0,
            purchase_url="https://app.piibuddy.com/buy",
        )
        assert err.credits_remaining == 0
        assert err.purchase_url == "https://app.piibuddy.com/buy"

    def test_rate_limit_error_exists(self):
        """RateLimitError should be importable from verify_client."""
        from pii_buddy.verify_client import RateLimitError
        assert issubclass(RateLimitError, Exception)

    def test_rate_limit_has_retry_after(self):
        """RateLimitError should carry a retry_after field."""
        from pii_buddy.verify_client import RateLimitError
        err = RateLimitError("Too fast", retry_after=30)
        assert err.retry_after == 30

    def test_all_errors_subclass_verify_error(self):
        """All specialized errors should subclass VerifyError."""
        from pii_buddy.verify_client import (
            VerifyError,
            InvalidAPIKeyError,
            InsufficientCreditsError,
            RateLimitError,
        )
        assert issubclass(InvalidAPIKeyError, VerifyError)
        assert issubclass(InsufficientCreditsError, VerifyError)
        assert issubclass(RateLimitError, VerifyError)


# -----------------------------------------------------------------------
# VerifyClient.verify — error handling per HTTP status
# -----------------------------------------------------------------------
class TestVerifyErrorHandling:
    @patch("pii_buddy.verify_client._require_httpx")
    def test_401_raises_invalid_api_key(self, mock_require):
        """401 response should raise InvalidAPIKeyError."""
        import httpx
        from pii_buddy.verify_client import VerifyClient, InvalidAPIKeyError

        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = json.dumps({"error": "invalid_api_key", "message": "Invalid API key"})
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=mock_resp,
        )
        mock_httpx.post.return_value = mock_resp
        mock_httpx.HTTPStatusError = httpx.HTTPStatusError
        mock_httpx.RequestError = httpx.RequestError
        mock_require.return_value = mock_httpx

        client = VerifyClient(api_key="bad-key")
        with pytest.raises(InvalidAPIKeyError):
            client.verify([], {})

    @patch("pii_buddy.verify_client._require_httpx")
    def test_402_raises_insufficient_credits(self, mock_require):
        """402 response should raise InsufficientCreditsError with balance info."""
        import httpx
        from pii_buddy.verify_client import VerifyClient, InsufficientCreditsError

        error_body = {
            "error": "insufficient_credits",
            "message": "You have 0 credits remaining",
            "credits_remaining": 0,
            "purchase_url": "https://app.piibuddy.com/buy",
        }
        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 402
        mock_resp.text = json.dumps(error_body)
        mock_resp.json.return_value = error_body
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "402", request=MagicMock(), response=mock_resp,
        )
        mock_httpx.post.return_value = mock_resp
        mock_httpx.HTTPStatusError = httpx.HTTPStatusError
        mock_httpx.RequestError = httpx.RequestError
        mock_require.return_value = mock_httpx

        client = VerifyClient(api_key="valid-but-broke")
        with pytest.raises(InsufficientCreditsError) as exc_info:
            client.verify([], {})
        assert exc_info.value.credits_remaining == 0
        assert "piibuddy.com" in exc_info.value.purchase_url

    @patch("pii_buddy.verify_client._require_httpx")
    def test_429_raises_rate_limit(self, mock_require):
        """429 response should raise RateLimitError with retry_after."""
        import httpx
        from pii_buddy.verify_client import VerifyClient, RateLimitError

        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = json.dumps({"error": "rate_limited", "retry_after": 60})
        mock_resp.headers = {"Retry-After": "60"}
        mock_resp.json.return_value = {"error": "rate_limited", "retry_after": 60}
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=mock_resp,
        )
        mock_httpx.post.return_value = mock_resp
        mock_httpx.HTTPStatusError = httpx.HTTPStatusError
        mock_httpx.RequestError = httpx.RequestError
        mock_require.return_value = mock_httpx

        client = VerifyClient(api_key="valid-key")
        with pytest.raises(RateLimitError) as exc_info:
            client.verify([], {})
        assert exc_info.value.retry_after == 60

    @patch("pii_buddy.verify_client._require_httpx")
    def test_400_raises_generic_verify_error(self, mock_require):
        """Other 4xx errors should raise generic VerifyError (not specialized)."""
        import httpx
        from pii_buddy.verify_client import VerifyClient, VerifyError, InvalidAPIKeyError

        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad request"
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "400", request=MagicMock(), response=mock_resp,
        )
        mock_httpx.post.return_value = mock_resp
        mock_httpx.HTTPStatusError = httpx.HTTPStatusError
        mock_httpx.RequestError = httpx.RequestError
        mock_require.return_value = mock_httpx

        client = VerifyClient(api_key="key")
        with pytest.raises(VerifyError) as exc_info:
            client.verify([], {})
        # Should NOT be one of the specialized subclasses
        assert not isinstance(exc_info.value, InvalidAPIKeyError)


# -----------------------------------------------------------------------
# VerifyResponse.credits_remaining
# -----------------------------------------------------------------------
class TestCreditsInResponse:
    def test_credits_remaining_parsed(self, verify_api_success_response):
        """credits_remaining should be parsed from the API response."""
        from pii_buddy.verify_client import VerifyClient
        resp = VerifyClient._parse_response(verify_api_success_response)
        assert resp.credits_remaining == 950

    def test_credits_remaining_default(self):
        """If credits_remaining is not in response, default to None."""
        from pii_buddy.verify_client import VerifyClient
        resp = VerifyClient._parse_response({
            "results": [],
            "usage": {"shards_processed": 0, "tokens_used": 0, "cost_cents": 0},
        })
        assert resp.credits_remaining is None

    def test_low_credits_parsed(self, verify_api_low_credits_response):
        """Low credit balance should be correctly parsed."""
        from pii_buddy.verify_client import VerifyClient
        resp = VerifyClient._parse_response(verify_api_low_credits_response)
        assert resp.credits_remaining == 15


# -----------------------------------------------------------------------
# VerifyClient.check_usage
# -----------------------------------------------------------------------
class TestCheckUsage:
    @patch("pii_buddy.verify_client._require_httpx")
    def test_returns_balance(self, mock_require):
        """check_usage should return credit balance information."""
        mock_httpx = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "credits_remaining": 500,
            "credits_used": 250,
            "plan": "pay_as_you_go",
        }
        mock_resp.raise_for_status.return_value = None
        mock_httpx.get.return_value = mock_resp
        mock_require.return_value = mock_httpx

        from pii_buddy.verify_client import VerifyClient
        client = VerifyClient(api_key="test-key")
        usage = client.check_usage()

        assert usage["credits_remaining"] == 500
        assert usage["plan"] == "pay_as_you_go"
