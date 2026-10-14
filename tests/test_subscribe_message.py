"""--subscribe only saves locally; its output must not claim a subscription."""

import logging
from unittest.mock import patch

import pytest


@pytest.fixture
def subscribe_output(tmp_path, caplog):
    for d in ("input", "output", "mappings", "originals", "logs", "blocklists"):
        (tmp_path / d).mkdir(exist_ok=True)
    argv = ["main.py", "--subscribe", "a@example.com", "--dir", str(tmp_path)]
    with caplog.at_level(logging.INFO, logger="pii_buddy"):
        with patch("sys.argv", argv):
            from main import main
            main()
    return caplog.text, tmp_path


def test_message_does_not_claim_subscription(subscribe_output):
    text, _ = subscribe_output
    lowered = text.lower()
    assert "subscribed!" not in lowered
    assert "you'll receive" not in lowered
    assert "will sync" not in lowered


def test_message_says_saved_locally_and_no_server(subscribe_output):
    text, _ = subscribe_output
    lowered = text.lower()
    assert "saved locally" in lowered
    assert "no update server" in lowered


def test_address_written_under_base_dir(subscribe_output):
    _, base = subscribe_output
    stored = (base / "feedback" / "pending_subscriptions.txt").read_text()
    assert "a@example.com" in stored
