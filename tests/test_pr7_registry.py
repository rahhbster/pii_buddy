"""PR #7 round 4: own-output registry keyed by file identity, not path or name."""
import logging
import os
import stat
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
        p = root / name.removesuffix("_DIR").lower()
        p.mkdir(parents=True)
        monkeypatch.setattr(cfg, name, p)
    watcher._just_written.clear()
    return root


def _event(path):
    return type("E", (), {"is_directory": False, "src_path": str(path),
                          "dest_path": str(path)})()


def _overwrite_settings():
    s = Settings.defaults()
    s.overwrite = True
    return s


def _process(path, settings):
    with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
            patch("pii_buddy.watcher.detect_pii", return_value=[]):
        return watcher.process_file(path, settings)


def _dispatch(handler, path):
    """Deliver a created event; return True if process_file was invoked."""
    with patch("pii_buddy.watcher.process_file") as pf, \
            patch("pii_buddy.watcher.time.sleep"):
        handler.on_created(_event(path))
    return pf.called


class TestOutputDirEqualsInputDir:
    def test_no_loop(self, base):
        s = Settings.defaults()
        s.output_dir = cfg.INPUT_DIR
        src = cfg.INPUT_DIR / "x.txt"
        src.write_text("fake body", encoding="utf-8")
        assert _process(src, s)
        outs = sorted(p.name for p in cfg.INPUT_DIR.iterdir())
        assert outs == ["PII_FREE_x.txt"]
        handler = watcher.NewFileHandler(s)
        assert _dispatch(handler, cfg.INPUT_DIR / outs[0]) is False

    def test_extra_text_output_also_registered(self, base):
        s = Settings.defaults()
        s.output_dir = cfg.INPUT_DIR
        s.output_format = "same"
        s.text_output = True
        src = cfg.INPUT_DIR / "x.docx"
        src.write_bytes(b"PK fake")
        assert _process(src, s)
        outs = sorted(p.name for p in cfg.INPUT_DIR.iterdir())
        assert outs == ["PII_FREE_x.docx", "PII_FREE_x.txt"]
        handler = watcher.NewFileHandler(s)
        for name in outs:
            assert _dispatch(handler, cfg.INPUT_DIR / name) is False

    def test_symlinked_output_dir_still_registered(self, base, tmp_path):
        link = tmp_path / "link"
        link.symlink_to(cfg.INPUT_DIR)
        s = Settings.defaults()
        s.output_dir = link
        src = cfg.INPUT_DIR / "x.txt"
        src.write_text("fake body", encoding="utf-8")
        assert _process(src, s)
        handler = watcher.NewFileHandler(s)
        assert _dispatch(handler, cfg.INPUT_DIR / "PII_FREE_x.txt") is False


class TestRedropAfterInPlaceOverwrite:
    def test_same_path_new_content_is_processed(self, base):
        src = cfg.INPUT_DIR / "a.txt"
        src.write_text("first fake body", encoding="utf-8")
        s = _overwrite_settings()
        assert _process(src, s)
        src.write_text("a completely different second drop", encoding="utf-8")
        assert _dispatch(watcher.NewFileHandler(s), src) is True

    def test_unchanged_output_event_skipped_then_redrop_processed(self, base):
        src = cfg.INPUT_DIR / "a.txt"
        src.write_text("first fake body", encoding="utf-8")
        s = _overwrite_settings()
        assert _process(src, s)
        handler = watcher.NewFileHandler(s)
        assert _dispatch(handler, src) is False
        assert _dispatch(handler, src) is True


class TestStatMatchSkipsOnceAndWarns:
    def test_skip_once_with_warning(self, base, caplog):
        out = cfg.INPUT_DIR / "weirdname_zq.docx"
        out.write_bytes(b"fake")
        watcher._mark_written(out)
        handler = watcher.NewFileHandler(Settings.defaults())
        with caplog.at_level("WARNING", logger="pii_buddy"):
            assert _dispatch(handler, out) is False
        assert ".docx" in caplog.text and "weirdname" not in caplog.text
        assert any(r.levelno == logging.WARNING for r in caplog.records)
        assert _dispatch(handler, out) is True

    def test_mismatching_stat_never_skips(self, base):
        out = cfg.INPUT_DIR / "a.txt"
        out.write_text("fake", encoding="utf-8")
        watcher._mark_written(out)
        out.write_text("fake but changed", encoding="utf-8")
        assert _dispatch(watcher.NewFileHandler(Settings.defaults()), out) is True

    def test_expired_entry_does_not_skip(self, base):
        out = cfg.INPUT_DIR / "a.txt"
        out.write_text("fake", encoding="utf-8")
        watcher._mark_written(out)
        for k in list(watcher._just_written):
            watcher._just_written[k] -= 301
        assert _dispatch(watcher.NewFileHandler(Settings.defaults()), out) is True

    def test_stat_error_processes(self, base):
        out = cfg.INPUT_DIR / "a.txt"
        out.write_text("fake", encoding="utf-8")
        watcher._mark_written(out)
        with patch("pii_buddy.watcher.os.stat", side_effect=OSError("boom")):
            assert watcher._is_own_output(out) is False


class TestRepeatedTagBound:
    def test_triple_prefix_refused_and_left(self, base, caplog):
        src = cfg.INPUT_DIR / "PII_FREE_PII_FREE_PII_FREE_x.txt"
        src.write_text("fake body", encoding="utf-8")
        with caplog.at_level("WARNING", logger="pii_buddy"):
            assert _process(src, Settings.defaults()) is False
        assert src.read_text(encoding="utf-8") == "fake body"
        assert [p.name for p in cfg.INPUT_DIR.iterdir()] == [src.name]
        assert list(cfg.OUTPUT_DIR.iterdir()) == []
        assert "Refusing" in caplog.text and "PII_FREE" not in caplog.text

    def test_double_prefix_still_processed(self, base):
        src = cfg.INPUT_DIR / "PII_FREE_PII_FREE_x.txt"
        src.write_text("fake body", encoding="utf-8")
        assert _process(src, Settings.defaults()) is True


class TestRestoreHardening:
    def _fail_midwrite(self, src, partial=b"Contact <N"):
        def half_then_raise(text, path):
            Path(path).write_bytes(partial)
            raise RuntimeError("boom")
        with patch("pii_buddy.watcher.extract_text", return_value="Contact Jane Fake"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                patch("pii_buddy.writers.write_txt", half_then_raise):
            return watcher.process_file(src, _overwrite_settings())

    def test_mode_preserved_and_no_temp_left(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_bytes(b"Contact Jane Fake\n")
        os.chmod(src, 0o640)
        assert self._fail_midwrite(src) is False
        assert src.read_bytes() == b"Contact Jane Fake\n"
        assert stat.S_IMODE(src.stat().st_mode) == 0o640
        assert [p.name for p in cfg.INPUT_DIR.iterdir()] == ["c.txt"]

    def test_temp_cleaned_when_replace_fails(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_bytes(b"Contact Jane Fake\n")
        with patch("pii_buddy.watcher.os.replace", side_effect=OSError("nope")):
            assert self._fail_midwrite(src) is False
        assert [p.name for p in cfg.INPUT_DIR.iterdir()] == ["c.txt"]
        assert len(list(cfg.ORIGINALS_DIR.iterdir())) == 1

    def test_restored_input_event_is_skipped(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_bytes(b"Contact Jane Fake\n")
        assert self._fail_midwrite(src) is False
        assert _dispatch(watcher.NewFileHandler(Settings.defaults()), src) is False

    def test_input_untouched_by_failure_is_not_rewritten(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_bytes(b"Contact Jane Fake\n")
        before = src.stat()

        def raise_early(text, path):
            raise RuntimeError("boom")
        with patch("pii_buddy.watcher.extract_text", return_value="Contact Jane Fake"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                patch("pii_buddy.writers.write_txt", raise_early), \
                patch("pii_buddy.watcher._restore_input") as rest:
            assert watcher.process_file(src, _overwrite_settings()) is False
        rest.assert_not_called()
        assert src.stat().st_mtime_ns == before.st_mtime_ns

    def test_backup_never_deleted_on_failure(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_bytes(b"Contact Jane Fake\n")
        assert self._fail_midwrite(src, partial=b"Contact Jane Fake") is False
        assert len(list(cfg.ORIGINALS_DIR.iterdir())) == 1


class TestFailureAfterSuccessfulWrite:
    def test_mapping_failure_keeps_redacted_output_and_backup(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_bytes(b"Contact Jane Fake\n")
        with patch("pii_buddy.watcher.extract_text", return_value="redacted body"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                patch("pii_buddy.watcher.cfg.write_private_text",
                      side_effect=OSError("disk")):
            assert watcher.process_file(src, _overwrite_settings()) is False
        assert src.read_text(encoding="utf-8") == "redacted body"
        backups = list(cfg.ORIGINALS_DIR.iterdir())
        assert len(backups) == 1 and backups[0].read_bytes() == b"Contact Jane Fake\n"

    def test_mapping_failure_non_overwrite_keeps_output(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_text("fake body", encoding="utf-8")
        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                patch("pii_buddy.watcher.cfg.write_private_text",
                      side_effect=OSError("disk")):
            assert watcher.process_file(src, Settings.defaults()) is False
        assert [p.name for p in cfg.OUTPUT_DIR.iterdir()] == ["PII_FREE_c.txt"]
        assert len(list(cfg.ORIGINALS_DIR.iterdir())) == 1
