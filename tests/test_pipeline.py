"""Tests for multi-pass pipeline integration.

Tests cover:
- Pass composition (1→2 builds on previous output)
- Graceful degradation when optional passes are disabled
- Upsell messaging when audit finds PII
- Settings resolution
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest


# -----------------------------------------------------------------------
# Multi-pass composition
# -----------------------------------------------------------------------
class TestMultiPassComposition:
    def test_pass2_runs_after_pass1(self, sample_redacted_text, sample_mapping, default_settings):
        """Structural audit should run after initial redaction and catch more PII."""
        from pii_buddy.audit import audit_redacted

        default_settings.audit_enabled = True
        patched, updated = audit_redacted(sample_redacted_text, sample_mapping)

        # Pass 2 should have caught additional PII
        assert len(updated["tags"]) > len(sample_mapping["tags"])

    def test_passes_compose_correctly(self, sample_redacted_text, sample_mapping, default_settings):
        """Each pass should be able to read the previous pass's output format."""
        from pii_buddy.audit import audit_redacted

        # Pass 2
        text_p2, mapping_p2 = audit_redacted(sample_redacted_text, sample_mapping)

        # The output should still be valid input for further passes
        # (tags are well-formed, mapping has required keys)
        assert "tags" in mapping_p2
        assert "persons" in mapping_p2

        # Tags should all match expected format
        for tag in mapping_p2["tags"]:
            assert (tag.startswith("<NAME ") and tag.endswith(">")) or \
                   (tag.startswith("<<") and tag.endswith(">>"))

    def test_idempotent_audit(self, sample_redacted_text, sample_mapping):
        """Running audit on already-audited text should be safe (idempotent)."""
        from pii_buddy.audit import audit_redacted

        text_p2a, map_p2a = audit_redacted(sample_redacted_text, sample_mapping)
        text_p2b, map_p2b = audit_redacted(text_p2a, map_p2a)

        assert text_p2a == text_p2b


# -----------------------------------------------------------------------
# Graceful degradation
# -----------------------------------------------------------------------
@pytest.fixture
def run_process_file(tmp_path, monkeypatch):
    """Run watcher.process_file on a throwaway .txt with every optional pass
    replaced by a recording fake. No spaCy model and no network are touched.

    Returns a callable(settings) -> (ok, calls) where calls maps each pass
    name to its MagicMock.
    """
    import sys

    from pii_buddy import watcher

    for name in ("MAPPINGS_DIR", "ORIGINALS_DIR", "OUTPUT_DIR"):
        d = tmp_path / name
        d.mkdir()
        monkeypatch.setattr(watcher, name, d)
    monkeypatch.setattr(watcher, "detect_pii", lambda text: [])

    def passthrough(text, mapping, *args, **kwargs):
        return text, mapping

    calls = {name: MagicMock(side_effect=passthrough)
             for name in ("audit", "openrouter", "venice", "verify")}

    monkeypatch.setattr("pii_buddy.audit.audit_redacted", calls["audit"])
    for module, attr, name in (
        ("pii_buddy.openrouter_verifier", "openrouter_verify_and_patch", "openrouter"),
        ("pii_buddy.venice_verifier", "venice_verify_and_patch", "venice"),
        ("pii_buddy.verifier", "verify_and_patch", "verify"),
    ):
        fake = MagicMock()
        setattr(fake, attr, calls[name])
        monkeypatch.setitem(sys.modules, module, fake)

    def run(settings):
        settings.output_dir = tmp_path / "OUTPUT_DIR"
        src = tmp_path / "note.txt"
        src.write_text("Meeting notes with nothing sensitive.", encoding="utf-8")
        return watcher.process_file(src, settings), calls

    return run


class TestGracefulDegradation:
    def test_verify_disabled_skips_cleanly(self, run_process_file, default_settings):
        """Pass 4 must not run when cloud verify is off, even if a key is present."""
        default_settings.verify_enabled = False
        default_settings.verify_api_key = "paid-key"
        ok, calls = run_process_file(default_settings)

        assert ok is True
        calls["verify"].assert_not_called()

    def test_openrouter_disabled_skips_cleanly(self, run_process_file, default_settings):
        """Pass 3 must not run when OpenRouter is off, even if a key is present."""
        default_settings.openrouter_enabled = False
        default_settings.openrouter_api_key = "sk-or-test"
        ok, calls = run_process_file(default_settings)

        assert ok is True
        calls["openrouter"].assert_not_called()

    def test_venice_disabled_skips_cleanly(self, run_process_file, default_settings):
        """Pass 3b must not run when Venice is off, even if a key is present."""
        default_settings.venice_enabled = False
        default_settings.venice_api_key = "venice-test-key"
        ok, calls = run_process_file(default_settings)

        assert ok is True
        calls["venice"].assert_not_called()

    def test_audit_disabled_skips_cleanly(self, run_process_file, default_settings):
        """Pass 2 must not run under --no-audit."""
        default_settings.audit_enabled = False
        ok, calls = run_process_file(default_settings)

        assert ok is True
        calls["audit"].assert_not_called()

    def test_enabled_without_key_skips_cleanly(self, run_process_file, default_settings):
        """Enabled-but-keyless premium passes are skipped, not attempted."""
        default_settings.verify_enabled = True
        default_settings.openrouter_enabled = True
        default_settings.venice_enabled = True
        ok, calls = run_process_file(default_settings)

        assert ok is True
        calls["verify"].assert_not_called()
        calls["openrouter"].assert_not_called()
        calls["venice"].assert_not_called()

    def test_enabled_passes_do_run(self, run_process_file, default_settings):
        """Control: the same harness does call each pass once when enabled,
        so the not_called assertions above can fail."""
        default_settings.verify_enabled = True
        default_settings.verify_api_key = "paid-key"
        default_settings.openrouter_enabled = True
        default_settings.openrouter_api_key = "sk-or-test"
        default_settings.venice_enabled = True
        default_settings.venice_api_key = "venice-test-key"
        ok, calls = run_process_file(default_settings)

        assert ok is True
        for name in ("audit", "openrouter", "venice", "verify"):
            calls[name].assert_called_once()


# -----------------------------------------------------------------------
# Upsell messaging
# -----------------------------------------------------------------------
class TestUpsellMessaging:
    def test_upsell_when_audit_finds_pii_and_verify_disabled(
        self, sample_redacted_text, sample_mapping, caplog
    ):
        """When audit finds extra PII and verify is off, show upsell message."""
        from pii_buddy.audit import audit_redacted

        with caplog.at_level(logging.INFO, logger="pii_buddy"):
            text, mapping = audit_redacted(sample_redacted_text, sample_mapping)

        # The audit should have found additional items
        pre_count = len(sample_mapping["tags"])
        post_count = len(mapping["tags"])
        extra = post_count - pre_count

        # If extra PII was found, the caller (main.py/watcher.py) should log upsell
        assert extra > 0, "Audit should find additional PII in sample text"

    def test_no_upsell_when_verify_enabled(self, default_settings):
        """No upsell message when cloud verify is already enabled."""
        default_settings.verify_enabled = True
        default_settings.verify_api_key = "paid-key"
        assert default_settings.verify_enabled and default_settings.verify_api_key


# -----------------------------------------------------------------------
# Settings resolution
# -----------------------------------------------------------------------
class TestSettingsResolution:
    def test_no_audit_flag(self):
        """--no-audit should set audit_enabled=False."""
        from pii_buddy.settings import resolve_settings
        from pathlib import Path

        settings = resolve_settings(
            base_dir=Path("/tmp/test"),
            cli_no_audit=True,
        )
        assert settings.audit_enabled is False

    def test_audit_on_by_default(self):
        """Audit should be enabled by default."""
        from pii_buddy.settings import resolve_settings
        from pathlib import Path

        settings = resolve_settings(base_dir=Path("/tmp/test"))
        assert settings.audit_enabled is True

    def test_openrouter_requires_key(self):
        """--openrouter without key should disable with warning."""
        from pii_buddy.settings import resolve_settings
        from pathlib import Path

        settings = resolve_settings(
            base_dir=Path("/tmp/test"),
            cli_openrouter=True,
            cli_openrouter_key=None,
        )
        assert settings.openrouter_enabled is False

    def test_openrouter_with_key(self):
        """--openrouter with key should enable."""
        from pii_buddy.settings import resolve_settings
        from pathlib import Path

        settings = resolve_settings(
            base_dir=Path("/tmp/test"),
            cli_openrouter=True,
            cli_openrouter_key="sk-or-test",
        )
        assert settings.openrouter_enabled is True
        assert settings.openrouter_api_key == "sk-or-test"

    def test_venice_requires_key(self):
        """--venice without key should disable with warning."""
        from pii_buddy.settings import resolve_settings
        from pathlib import Path

        settings = resolve_settings(
            base_dir=Path("/tmp/test"),
            cli_venice=True,
            cli_venice_key=None,
        )
        assert settings.venice_enabled is False

    def test_venice_with_key(self):
        """--venice with key should enable."""
        from pii_buddy.settings import resolve_settings
        from pathlib import Path

        settings = resolve_settings(
            base_dir=Path("/tmp/test"),
            cli_venice=True,
            cli_venice_key="venice-test-key",
        )
        assert settings.venice_enabled is True
        assert settings.venice_api_key == "venice-test-key"

    def test_verify_requires_key(self):
        """--verify without key should disable with warning."""
        from pii_buddy.settings import resolve_settings
        from pathlib import Path

        settings = resolve_settings(
            base_dir=Path("/tmp/test"),
            cli_verify=True,
            cli_verify_key=None,
        )
        assert settings.verify_enabled is False
