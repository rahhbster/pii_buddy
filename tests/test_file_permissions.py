"""Files that hold plaintext PII or secrets must be created 0600 inside
0700 directories, with no window where they are more permissive."""
import hashlib
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

import pii_buddy.config as cfg
from pii_buddy import feedback, watcher
from pii_buddy.settings import Settings, seed_settings_file


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture
def base(tmp_path, monkeypatch):
    old = os.umask(0o022)
    root = tmp_path / "PII_Buddy"
    root.mkdir()
    (root / "input").mkdir()
    monkeypatch.setattr(cfg, "INPUT_DIR", root / "input")
    monkeypatch.setattr(cfg, "OUTPUT_DIR", root / "output")
    monkeypatch.setattr(cfg, "MAPPINGS_DIR", root / "mappings")
    monkeypatch.setattr(cfg, "ORIGINALS_DIR", root / "originals")
    monkeypatch.setattr(cfg, "FEEDBACK_DIR", root / "feedback")
    yield root
    os.umask(old)


class TestPrivateHelpers:
    def test_ensure_private_dir_is_0700(self, tmp_path):
        d = tmp_path / "x" / "y"
        cfg.ensure_private_dir(d)
        assert mode(d) == 0o700

    def test_ensure_private_dir_tightens_existing(self, tmp_path):
        d = tmp_path / "x"
        d.mkdir()
        os.chmod(d, 0o755)
        cfg.ensure_private_dir(d)
        assert mode(d) == 0o700

    def test_write_private_text_is_0600_even_with_open_umask(self, tmp_path):
        old = os.umask(0)
        try:
            p = tmp_path / "s.txt"
            cfg.write_private_text(p, "fake secret")
        finally:
            os.umask(old)
        assert mode(p) == 0o600
        assert p.read_text() == "fake secret"

    def test_write_private_text_tightens_existing_file(self, tmp_path):
        p = tmp_path / "s.txt"
        p.write_text("old")
        os.chmod(p, 0o644)
        cfg.write_private_text(p, "new")
        assert mode(p) == 0o600


class TestPipelinePermissions:
    def _process(self, base, overwrite=False):
        src = base / "input" / "note.txt"
        src.write_text("fake note body", encoding="utf-8")
        os.chmod(src, 0o644)
        settings = Settings.defaults()
        settings.overwrite = overwrite
        with patch("pii_buddy.watcher.detect_pii", return_value=[]):
            assert watcher.process_file(src, settings)

    def test_mapping_is_0600(self, base):
        self._process(base)
        maps = list(cfg.MAPPINGS_DIR.glob("*.map.json"))
        assert maps
        for m in maps:
            assert mode(m) == 0o600

    def test_original_is_0600(self, base):
        self._process(base)
        files = list(cfg.ORIGINALS_DIR.iterdir())
        assert files
        for f in files:
            assert mode(f) == 0o600

    def test_overwrite_backup_is_0600(self, base):
        self._process(base, overwrite=True)
        files = list(cfg.ORIGINALS_DIR.iterdir())
        assert files
        for f in files:
            assert mode(f) == 0o600

    def test_mappings_and_originals_dirs_are_0700(self, base):
        self._process(base)
        assert mode(cfg.MAPPINGS_DIR) == 0o700
        assert mode(cfg.ORIGINALS_DIR) == 0o700


class TestSettingsAndFeedbackPermissions:
    def test_settings_conf_is_0600(self, tmp_path):
        seed_settings_file(tmp_path)
        assert mode(tmp_path / cfg.SETTINGS_FILENAME) == 0o600

    def test_existing_settings_conf_is_tightened(self, tmp_path):
        p = tmp_path / cfg.SETTINGS_FILENAME
        p.write_text("# old")
        os.chmod(p, 0o644)
        seed_settings_file(tmp_path)
        assert mode(p) == 0o600
        assert p.read_text() == "# old"

    def test_feedback_log_and_dir_private(self, base):
        feedback.record_rating(4, comment="fine", filename="fake_name.pdf")
        assert mode(cfg.FEEDBACK_DIR / "feedback.jsonl") == 0o600
        assert mode(cfg.FEEDBACK_DIR) == 0o700


class TestFeedbackFilenameHash:
    def test_hash_is_not_plain_sha256(self, base):
        h = feedback._hash_filename("fake_person_resume.pdf")
        plain = hashlib.sha256(b"fake_person_resume.pdf").hexdigest()[:16]
        assert h != plain

    def test_hash_is_stable_within_install(self, base):
        assert feedback._hash_filename("a.pdf") == feedback._hash_filename("a.pdf")
        assert feedback._hash_filename("a.pdf") != feedback._hash_filename("b.pdf")

    def test_salt_differs_between_installs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cfg, "FEEDBACK_DIR", tmp_path / "one")
        h1 = feedback._hash_filename("a.pdf")
        monkeypatch.setattr(cfg, "FEEDBACK_DIR", tmp_path / "two")
        h2 = feedback._hash_filename("a.pdf")
        assert h1 != h2

    def test_salt_file_is_0600(self, base):
        feedback._hash_filename("a.pdf")
        salts = [p for p in cfg.FEEDBACK_DIR.iterdir() if "salt" in p.name]
        assert len(salts) == 1
        assert mode(salts[0]) == 0o600
