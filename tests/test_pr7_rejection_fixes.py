"""PR #7 rejection fixes: case-variant extension data loss, salt race,
settings chmod tolerance, ensure_private_dir owner bits and symlinks."""
import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import pii_buddy.config as cfg
from pii_buddy import feedback, watcher
from pii_buddy.settings import Settings, seed_settings_file


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


def _run(path, settings):
    with patch("pii_buddy.watcher.detect_pii", return_value=[]):
        return watcher.process_file(path, settings)


class TestCaseVariantExtensionOverwrite:
    @pytest.mark.parametrize("name", ["CV.TXT", "CV.Txt"])
    def test_txt_variant_keeps_output(self, base, name):
        src = cfg.INPUT_DIR / name
        src.write_text("fake document body", encoding="utf-8")
        assert _run(src, _overwrite_settings())
        files = list(cfg.INPUT_DIR.iterdir())
        assert len(files) == 1
        assert files[0].name == name
        assert files[0].stat().st_size > 0

    @pytest.mark.parametrize("name,writer", [
        ("CV.PDF", "pii_buddy.writers.write_pdf"),
        ("CV.Docx", "pii_buddy.writers.write_docx"),
    ])
    def test_binary_variants_keep_output(self, base, name, writer):
        src = cfg.INPUT_DIR / name
        src.write_bytes(b"fake")

        def fake_writer(text, path):
            Path(path).write_bytes(b"redacted")

        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch(writer, side_effect=fake_writer), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]):
            assert watcher.process_file(src, _overwrite_settings())
        files = list(cfg.INPUT_DIR.iterdir())
        assert [f.name for f in files] == [name]
        assert files[0].read_bytes() == b"redacted"

    def test_case_sensitive_fs_simulation_never_unlinks_output(self, base):
        src = cfg.INPUT_DIR / "CV.TXT"
        src.write_text("fake document body", encoding="utf-8")
        with patch("os.path.samefile", return_value=False):
            assert _run(src, _overwrite_settings())
        files = list(cfg.INPUT_DIR.iterdir())
        assert len(files) == 1 and files[0].stat().st_size > 0

    def test_empty_output_does_not_unlink_input(self, base):
        src = cfg.INPUT_DIR / "old.doc"
        src.write_bytes(b"fake")
        orig = watcher.write_output

        def empty_out(*a, **k):
            out = orig(*a, **k)
            out.write_bytes(b"")
            return out

        with patch("pii_buddy.watcher.extract_text", return_value="fake body"), \
                patch("pii_buddy.watcher.write_output", side_effect=empty_out), \
                patch("pii_buddy.watcher.detect_pii", return_value=[]):
            try:
                watcher.process_file(src, _overwrite_settings())
            except Exception:
                pass
        assert src.exists()


class TestSaltRace:
    def test_threads_agree_on_salt(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cfg, "FEEDBACK_DIR", tmp_path / "fb")
        real_replace = os.replace
        barrier = threading.Barrier(2)

        def slow_replace(a, b):
            try:
                barrier.wait(timeout=2)
            except threading.BrokenBarrierError:
                pass
            return real_replace(a, b)

        cfg.ensure_private_dir(cfg.FEEDBACK_DIR)
        (cfg.FEEDBACK_DIR / ".salt").write_bytes(b"short")
        results = []
        with patch("os.replace", side_effect=slow_replace):
            ts = [threading.Thread(target=lambda: results.append(feedback._install_salt()))
                  for _ in range(2)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
        on_disk = (cfg.FEEDBACK_DIR / ".salt").read_bytes()
        assert len(results) == 2
        assert results[0] == results[1] == on_disk


class TestSeedSettingsChmod:
    def test_chmod_failure_is_tolerated(self, tmp_path):
        (tmp_path / "settings.conf").write_text("# fake\n")
        with patch("os.chmod", side_effect=PermissionError("foreign owner")):
            seed_settings_file(tmp_path)


class TestEnsurePrivateDir:
    def test_never_drops_owner_bits(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        os.chmod(d, 0o055)
        try:
            cfg.ensure_private_dir(d)
            assert (d.stat().st_mode & 0o777) == 0o700
        finally:
            os.chmod(d, 0o700)

    def test_symlink_left_alone(self, tmp_path):
        target = tmp_path / "t"
        target.mkdir()
        os.chmod(target, 0o755)
        link = tmp_path / "link"
        link.symlink_to(target)
        try:
            cfg.ensure_private_dir(link)
        except OSError:
            pass
        assert (target.stat().st_mode & 0o777) == 0o755
