"""Red-team fixes for PR #7: cross-extension clobber, salt race, mapping/output
stem pairing, and ensure_private_dir not touching foreign directories."""
import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

import pii_buddy.config as cfg
from pii_buddy import feedback, watcher
from pii_buddy.settings import Settings
from pii_buddy.writers import write_output


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture
def base(tmp_path, monkeypatch):
    root = tmp_path / "PII_Buddy"
    for name in ("input", "output"):
        (root / name).mkdir(parents=True)
    monkeypatch.setattr(cfg, "INPUT_DIR", root / "input")
    monkeypatch.setattr(cfg, "OUTPUT_DIR", root / "output")
    monkeypatch.setattr(cfg, "MAPPINGS_DIR", root / "mappings")
    monkeypatch.setattr(cfg, "ORIGINALS_DIR", root / "originals")
    monkeypatch.setattr(cfg, "FEEDBACK_DIR", root / "feedback")
    return root


def _run(path, settings=None, text=None):
    settings = settings or Settings.defaults()
    with patch("pii_buddy.watcher.detect_pii", return_value=[]):
        if text is None:
            return watcher.process_file(path, settings)
        with patch("pii_buddy.watcher.extract_text", return_value=text):
            return watcher.process_file(path, settings)


class TestCrossExtensionClobber:
    def test_doc_overwrite_does_not_clobber_sibling_docx(self, base):
        sibling = base / "input" / "resume.docx"
        sibling.write_bytes(b"USER OWN DOCX")
        src = base / "input" / "resume.doc"
        src.write_bytes(b"fake binary doc")
        s = Settings.defaults()
        s.overwrite = True
        assert _run(src, s, text="fake resume text")

        assert sibling.read_bytes() == b"USER OWN DOCX"
        assert not src.exists()
        outs = [p for p in (base / "input").iterdir() if p != sibling]
        assert len(outs) == 1 and outs[0].suffix == ".docx"

    def test_same_extension_overwrite_still_backs_up_first(self, base):
        src = base / "input" / "note.txt"
        src.write_text("fake original body")
        s = Settings.defaults()
        s.overwrite = True
        assert _run(src, s)
        backups = list(cfg.ORIGINALS_DIR.iterdir())
        assert [b.read_text() for b in backups] == ["fake original body"]
        assert src.exists()

    def test_write_output_same_extension_replaces(self, tmp_path):
        target = tmp_path / "a.txt"
        target.write_text("old")
        out = write_output("new", tmp_path / "a", "same", ".txt", overwrite_existing=True)
        assert out == target and target.read_text() == "new"

    def test_write_output_different_extension_claims_unique(self, tmp_path):
        target = tmp_path / "a.docx"
        target.write_bytes(b"keep")
        out = write_output("new", tmp_path / "a", "same", ".doc", overwrite_existing=True)
        assert out != target
        assert target.read_bytes() == b"keep"


class TestSaltRace:
    def test_empty_salt_is_replaced(self, base):
        cfg.ensure_private_dir(cfg.FEEDBACK_DIR)
        (cfg.FEEDBACK_DIR / ".salt").write_bytes(b"")
        salt = feedback._install_salt()
        assert len(salt) == 32
        assert (cfg.FEEDBACK_DIR / ".salt").read_bytes() == salt
        assert mode(cfg.FEEDBACK_DIR / ".salt") == 0o600

    def test_truncated_salt_is_replaced(self, base):
        cfg.ensure_private_dir(cfg.FEEDBACK_DIR)
        (cfg.FEEDBACK_DIR / ".salt").write_bytes(b"short")
        assert len(feedback._install_salt()) == 32

    def test_valid_salt_is_kept(self, base):
        first = feedback._install_salt()
        assert feedback._install_salt() == first

    def test_no_temp_files_left_behind(self, base):
        feedback._install_salt()
        assert [p.name for p in cfg.FEEDBACK_DIR.iterdir()] == [".salt"]


class TestMappingStemPairing:
    def test_mapping_stem_matches_output_stem_on_reprocess(self, base):
        for sub in ("a", "b"):
            d = base / "drop" / sub
            d.mkdir(parents=True)
            p = d / "c.txt"
            p.write_text(f"fake doc {sub}")
            assert _run(p)

        outs = list(cfg.OUTPUT_DIR.iterdir())
        assert len(outs) == 2
        for out in outs:
            mp = cfg.MAPPINGS_DIR / f"{out.stem}.map.json"
            assert mp.exists(), f"no mapping paired with {out.name}"
            meta = json.loads(mp.read_text())["metadata"]
            assert meta["output_file"] == out.name
            assert meta["mapping_file"] == mp.name

    def test_first_run_mapping_is_named_after_output(self, base):
        p = base / "input" / "c.txt"
        p.write_text("fake doc")
        assert _run(p)
        assert (cfg.OUTPUT_DIR / "PII_FREE_c.txt").exists()
        assert (cfg.MAPPINGS_DIR / "PII_FREE_c.map.json").exists()


class TestEnsurePrivateDir:
    def test_new_dir_is_0700(self, tmp_path):
        d = tmp_path / "originals"
        cfg.ensure_private_dir(d)
        assert mode(d) == 0o700

    def test_existing_dir_only_loses_group_other_bits(self, tmp_path):
        d = tmp_path / "mappings"
        d.mkdir()
        os.chmod(d, 0o750)
        cfg.ensure_private_dir(d)
        assert mode(d) == 0o700

    def test_existing_stricter_dir_is_never_loosened(self, tmp_path):
        d = tmp_path / "feedback"
        d.mkdir()
        os.chmod(d, 0o500)
        cfg.ensure_private_dir(d)
        assert mode(d) == 0o500
        os.chmod(d, 0o700)

    def test_never_recurses_into_children(self, tmp_path):
        d = tmp_path / "originals"
        d.mkdir()
        child = d / "mine.txt"
        child.write_text("x")
        os.chmod(child, 0o644)
        sub = d / "sub"
        sub.mkdir()
        os.chmod(sub, 0o755)
        os.chmod(d, 0o755)
        cfg.ensure_private_dir(d)
        assert mode(child) == 0o644
        assert mode(sub) == 0o755
