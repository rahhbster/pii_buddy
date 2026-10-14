"""PR #7 final fixes: own-output suppression by exact path only, input
restored byte-for-byte after a mid-write failure, loose private files
tightened."""
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


def _overwrite_settings():
    s = Settings.defaults()
    s.overwrite = True
    return s


def _event(path):
    return type("E", (), {"is_directory": False, "src_path": str(path),
                          "dest_path": str(path)})()


class TestUserNamesLookingLikeOutputs:
    @pytest.mark.parametrize("name", ["PII_FREE_x.txt", "report.20260101T101010.txt"])
    def test_dropped_file_is_processed(self, base, name):
        handler = watcher.NewFileHandler(Settings.defaults())
        with patch("pii_buddy.watcher.process_file") as pf, \
                patch("pii_buddy.watcher.time.sleep"):
            handler.on_created(_event(cfg.INPUT_DIR / name))
            handler.on_moved(_event(cfg.INPUT_DIR / name))
        assert pf.call_count == 2

    def test_end_to_end_both_names(self, base):
        for name in ("PII_FREE_x.txt", "report.20260101T101010.txt"):
            p = cfg.INPUT_DIR / name
            p.write_text("fake body", encoding="utf-8")
            with patch("pii_buddy.watcher.detect_pii", return_value=[]):
                assert watcher.process_file(p, Settings.defaults())
            assert not p.exists()

    @pytest.mark.parametrize("name", ["zqx_fake.txt", "zqx_fake.docx"])
    def test_overwrite_output_is_not_reprocessed(self, base, name, caplog):
        src = cfg.INPUT_DIR / name
        src.write_bytes(b"x")
        handler = watcher.NewFileHandler(_overwrite_settings())
        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]):
            assert watcher.process_file(src, _overwrite_settings())
        with patch("pii_buddy.watcher.process_file") as pf, \
                patch("pii_buddy.watcher.time.sleep"), \
                caplog.at_level("WARNING", logger="pii_buddy"):
            handler.on_created(_event(src))
        pf.assert_not_called()
        assert "own output" in caplog.text
        assert src.stem not in caplog.text

    def test_cross_extension_output_is_not_reprocessed(self, base):
        src = cfg.INPUT_DIR / "a.doc"
        src.write_bytes(b"x")
        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]):
            assert watcher.process_file(src, _overwrite_settings())
        out = cfg.INPUT_DIR / "a.docx"
        assert out.exists()
        handler = watcher.NewFileHandler(Settings.defaults())
        with patch("pii_buddy.watcher.process_file") as pf, \
                patch("pii_buddy.watcher.time.sleep"):
            handler.on_created(_event(out))
        pf.assert_not_called()

    def test_stale_entry_expires(self, base):
        out = cfg.INPUT_DIR / "late.txt"
        out.write_text("fake", encoding="utf-8")
        watcher._mark_written(out)
        for k in list(watcher._just_written):
            watcher._just_written[k] -= 3600
        assert not watcher._is_own_output(out)


class TestMidWriteFailureRestoresInput:
    @pytest.mark.parametrize("name,payload,target", [
        ("c.txt", b"Contact Jane Fake <jane@example.invalid>\n", "write_txt"),
        ("c.docx", b"PK\x03\x04\x00\xff\xfe\x80binary-ish\x00\x01", "write_docx"),
    ])
    def test_input_restored_backup_kept(self, base, name, payload, target):
        src = cfg.INPUT_DIR / name
        src.write_bytes(payload)

        def half_then_raise(text, path):
            Path(path).write_bytes(b"Contact <N")
            raise RuntimeError("secret text must not be logged: Jane Fake")

        with patch("pii_buddy.watcher.extract_text", return_value="Contact Jane Fake"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                patch(f"pii_buddy.writers.{target}", half_then_raise):
            assert watcher.process_file(src, _overwrite_settings()) is False

        assert src.read_bytes() == payload
        backups = list(cfg.ORIGINALS_DIR.iterdir())
        assert len(backups) == 1 and backups[0].read_bytes() == payload
        assert list(cfg.MAPPINGS_DIR.iterdir()) == []
        assert [p.name for p in cfg.INPUT_DIR.iterdir()] == [name]

    def test_log_has_type_only(self, base, caplog):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_text("Jane Fake")

        def boom(text, path):
            raise ValueError("Jane Fake leaked")

        with patch("pii_buddy.watcher.extract_text", return_value="Jane Fake"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                patch("pii_buddy.writers.write_txt", boom), \
                caplog.at_level("INFO", logger="pii_buddy"):
            watcher.process_file(src, _overwrite_settings())
        assert "ValueError" in caplog.text
        assert "Jane Fake leaked" not in caplog.text

    def test_failed_mapping_write_leaves_no_map_file(self, base):
        src = cfg.INPUT_DIR / "c.txt"
        src.write_text("fake body")

        def partial(path, text):
            Path(path).write_text("{")
            raise OSError("disk full")

        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]), \
                patch("pii_buddy.watcher.cfg.write_private_text", partial):
            assert watcher.process_file(src, Settings.defaults()) is False
        assert list(cfg.MAPPINGS_DIR.iterdir()) == []


class TestTightenExistingFiles:
    def test_loose_owned_files_tightened(self, base):
        for d in (cfg.ORIGINALS_DIR, cfg.MAPPINGS_DIR):
            f = d / "old.bin"
            f.write_text("x")
            f.chmod(0o644)
        cfg.tighten_private_files(cfg.ORIGINALS_DIR)
        cfg.tighten_private_files(cfg.MAPPINGS_DIR)
        for d in (cfg.ORIGINALS_DIR, cfg.MAPPINGS_DIR):
            assert stat.S_IMODE((d / "old.bin").stat().st_mode) == 0o600

    def test_never_loosens(self, base):
        f = cfg.ORIGINALS_DIR / "ro"
        f.write_text("x")
        f.chmod(0o400)
        cfg.tighten_private_files(cfg.ORIGINALS_DIR)
        assert stat.S_IMODE(f.stat().st_mode) == 0o400

    def test_symlink_target_untouched(self, base, tmp_path):
        target = tmp_path / "elsewhere.txt"
        target.write_text("x")
        target.chmod(0o644)
        (cfg.ORIGINALS_DIR / "link").symlink_to(target)
        cfg.tighten_private_files(cfg.ORIGINALS_DIR)
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    def test_missing_dir_and_errors_ignored(self, base, tmp_path):
        cfg.tighten_private_files(tmp_path / "nope")
        f = cfg.ORIGINALS_DIR / "f"
        f.write_text("x")
        f.chmod(0o644)
        with patch("pii_buddy.config.os.open", side_effect=PermissionError):
            cfg.tighten_private_files(cfg.ORIGINALS_DIR)
