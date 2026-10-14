"""PR #7 review round: empty output keeps input, chmod tolerance, own-output reprocessing."""
from pathlib import Path
from unittest.mock import patch

import pytest

import pii_buddy.config as cfg
from pii_buddy import watcher
from pii_buddy.settings import Settings


@pytest.fixture
def base(tmp_path, monkeypatch):
    root = tmp_path / "PII_Buddy"
    for name in ("INPUT_DIR", "OUTPUT_DIR", "MAPPINGS_DIR", "ORIGINALS_DIR"):
        p = root / name.split("_")[0].lower()
        p.mkdir(parents=True)
        monkeypatch.setattr(cfg, name, p)
    return root


def _overwrite_settings():
    s = Settings.defaults()
    s.overwrite = True
    return s


class TestEmptyOutputKeepsInput:
    def test_empty_docx_output_fails_and_keeps_input_and_backup(self, base, caplog):
        src = cfg.INPUT_DIR / "CV.doc"
        src.write_bytes(b"fake legacy body")

        def empty_writer(text, path):
            Path(path).write_bytes(b"")

        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch("pii_buddy.writers.write_docx", side_effect=empty_writer), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                caplog.at_level("DEBUG", logger="pii_buddy"):
            assert watcher.process_file(src, _overwrite_settings()) is False
        assert src.read_bytes() == b"fake legacy body"
        assert not (cfg.INPUT_DIR / "CV.docx").exists()
        assert [p.name for p in cfg.ORIGINALS_DIR.iterdir()] == ["CV.doc"]
        assert list(cfg.MAPPINGS_DIR.iterdir()) == []
        assert "EmptyOutputError" in caplog.text
        assert "fake body" not in caplog.text

    def test_empty_same_name_output_is_restored_from_backup(self, base):
        src = cfg.INPUT_DIR / "CV.txt"
        src.write_text("fake document body", encoding="utf-8")
        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch("pii_buddy.writers.write_txt",
                      side_effect=lambda t, p: Path(p).write_bytes(b"")), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]):
            assert watcher.process_file(src, _overwrite_settings()) is False
        assert src.read_text(encoding="utf-8") == "fake document body"


class TestSamefileBranch:
    def test_samefile_true_blocks_unlink(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("x")
        b.write_text("y")
        assert watcher._safe_to_unlink_input(a, b) is True
        with patch("pii_buddy.watcher.os.path.samefile", return_value=True):
            assert watcher._safe_to_unlink_input(a, b) is False


class TestEnsurePrivateDirTolerance:
    def test_chmod_oserror_is_warned_once_and_ignored(self, tmp_path, caplog):
        d = tmp_path / "shared"
        d.mkdir()
        d.chmod(0o755)
        cfg._warned_dirs.clear()
        with patch("pii_buddy.config.os.chmod", side_effect=PermissionError("nope")), \
                caplog.at_level("WARNING", logger="pii_buddy"):
            cfg.ensure_private_dir(d)
            cfg.ensure_private_dir(d)
        assert d.exists()
        assert caplog.text.count("Could not tighten") == 1


def _event(path):
    return type("E", (), {"is_directory": False, "src_path": str(path),
                          "dest_path": str(path)})()


class TestOwnOutputNotReprocessed:
    def test_plain_name_processed(self, base):
        handler = watcher.NewFileHandler(Settings.defaults())
        with patch("pii_buddy.watcher.process_file") as pf, \
                patch("pii_buddy.watcher.time.sleep"):
            handler.on_created(_event(cfg.INPUT_DIR / "CV.docx"))
        pf.assert_called_once()

    def test_just_written_output_is_skipped_once(self, base):
        out = cfg.INPUT_DIR / "weird.docx"
        watcher._mark_written(out)
        handler = watcher.NewFileHandler(Settings.defaults())
        with patch("pii_buddy.watcher.process_file") as pf, \
                patch("pii_buddy.watcher.time.sleep"):
            handler.on_created(_event(out))
            handler.on_created(_event(out))
        assert pf.call_count == 1
