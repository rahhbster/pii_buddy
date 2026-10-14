"""Regression tests: processing two different files with the same name must
never overwrite an earlier output, mapping or original, and --overwrite
must not leave a PII-bearing .doc beside its .docx replacement."""
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import pii_buddy.config as cfg
from pii_buddy import watcher
from pii_buddy.settings import Settings


@pytest.fixture
def base(tmp_path, monkeypatch):
    root = tmp_path / "PII_Buddy"
    dirs = {
        "INPUT_DIR": root / "input",
        "OUTPUT_DIR": root / "output",
        "MAPPINGS_DIR": root / "mappings",
        "ORIGINALS_DIR": root / "originals",
    }
    for name, path in dirs.items():
        path.mkdir(parents=True)
        monkeypatch.setattr(cfg, name, path)
    return root


def _run(path: Path, settings=None):
    settings = settings or Settings.defaults()
    with patch("pii_buddy.watcher.detect_pii", return_value=[]):
        return watcher.process_file(path, settings)


def _drop(base, content, subdir="a", name="resume.txt"):
    d = base / "drop" / subdir
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(content, encoding="utf-8")
    return p


class TestFilenameCollisions:
    def test_second_same_named_file_keeps_first_output(self, base):
        assert _run(_drop(base, "FIRST fake document", "a"))
        assert _run(_drop(base, "SECOND fake document", "b"))

        outputs = sorted(cfg.OUTPUT_DIR.iterdir())
        assert len(outputs) == 2
        assert {o.read_text() for o in outputs} == {"FIRST fake document", "SECOND fake document"}

    def test_second_same_named_file_keeps_first_original(self, base):
        assert _run(_drop(base, "FIRST fake document", "a"))
        assert _run(_drop(base, "SECOND fake document", "b"))

        originals = list(cfg.ORIGINALS_DIR.iterdir())
        assert len(originals) == 2
        assert {o.read_text() for o in originals} == {"FIRST fake document", "SECOND fake document"}

    def test_second_same_named_file_keeps_first_mapping(self, base):
        assert _run(_drop(base, "FIRST fake document", "a"))
        assert _run(_drop(base, "SECOND fake document", "b"))

        assert len(list(cfg.MAPPINGS_DIR.glob("*.map.json"))) == 2

    def test_mapping_metadata_points_at_stored_files(self, base):
        assert _run(_drop(base, "FIRST fake document", "a"))
        assert _run(_drop(base, "SECOND fake document", "b"))

        for m in cfg.MAPPINGS_DIR.glob("*.map.json"):
            meta = json.loads(m.read_text())["metadata"]
            assert meta["original_file"] == "resume.txt"
            assert (cfg.OUTPUT_DIR / meta["output_file"]).exists()
            assert (cfg.ORIGINALS_DIR / meta["stored_original"]).exists()

    def test_first_file_keeps_bare_name(self, base):
        assert _run(_drop(base, "FIRST fake document"))
        assert (cfg.ORIGINALS_DIR / "resume.txt").exists()
        assert (cfg.MAPPINGS_DIR / "resume.map.json").exists()

    def test_overwrite_mode_backups_do_not_collide(self, base):
        settings = Settings.defaults()
        settings.overwrite = True
        assert _run(_drop(base, "FIRST fake document", "a"), settings)
        assert _run(_drop(base, "SECOND fake document", "b"), settings)

        backups = list(cfg.ORIGINALS_DIR.iterdir())
        assert {b.read_text() for b in backups} == {"FIRST fake document", "SECOND fake document"}
        assert len(list(cfg.MAPPINGS_DIR.glob("*.map.json"))) == 2

    def test_dotted_names_do_not_collapse_to_one_output(self, base):
        assert _run(_drop(base, "fake body 1", "a", "report.v1.txt"))
        assert _run(_drop(base, "fake body 2", "a", "report.v2.txt"))
        assert len(list(cfg.OUTPUT_DIR.iterdir())) == 2

    def test_text_output_extra_file_does_not_collide(self, base):
        settings = Settings.defaults()
        settings.output_format = "same"
        settings.text_output = True
        for sub in ("a", "b"):
            p = _drop(base, "ignored", sub, "memo.docx")
            with patch("pii_buddy.watcher.extract_text", return_value=f"fake memo {sub}"):
                assert _run(p, settings)
        txts = list(cfg.OUTPUT_DIR.glob("*.txt"))
        assert {t.read_text() for t in txts} == {"fake memo a", "fake memo b"}
        assert len(list(cfg.OUTPUT_DIR.glob("*.docx"))) == 2


class TestOverwriteDocInput:
    def test_doc_original_not_left_beside_docx_output(self, base):
        settings = Settings.defaults()
        settings.overwrite = True
        src = base / "input" / "legacy.doc"
        src.write_bytes(b"fake binary doc")
        with patch("pii_buddy.watcher.extract_text", return_value="fake legacy text"):
            assert _run(src, settings)

        assert (base / "input" / "legacy.docx").exists()
        assert not src.exists(), "PII-bearing .doc left beside the output"
        assert (cfg.ORIGINALS_DIR / "legacy.doc").exists(), "backup of the .doc must survive"


class TestCleanupOriginals:
    def _age(self, path, hours):
        past = time.time() - hours * 3600
        os.utime(path, (past, past), follow_symlinks=False)

    def test_removes_only_expired_regular_files(self, base):
        old = cfg.ORIGINALS_DIR / "old.txt"
        new = cfg.ORIGINALS_DIR / "new.txt"
        old.write_text("x")
        new.write_text("y")
        self._age(old, cfg.ORIGINALS_RETENTION_HOURS + 1)

        assert watcher.cleanup_originals() == 1
        assert not old.exists()
        assert new.exists()

    def test_does_not_follow_symlinks(self, base, tmp_path):
        target = tmp_path / "precious.txt"
        target.write_text("keep me")
        self._age(target, cfg.ORIGINALS_RETENTION_HOURS + 1)
        link = cfg.ORIGINALS_DIR / "link.txt"
        link.symlink_to(target)

        watcher.cleanup_originals()

        assert target.exists()

    def test_missing_directory_is_not_an_error(self, base, monkeypatch):
        monkeypatch.setattr(cfg, "ORIGINALS_DIR", base / "nope")
        assert watcher.cleanup_originals() == 0

    def test_custom_retention_hours(self, base):
        f = cfg.ORIGINALS_DIR / "a.txt"
        f.write_text("x")
        self._age(f, 2)
        assert watcher.cleanup_originals(retention_hours=1) == 1
