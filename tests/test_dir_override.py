"""Regression tests for a pre-existing bug: `--once FILE --dir PATH` threw
FileNotFoundError copying the input file, because ensure_dirs() created
the *default* ~/PII_Buddy directories instead of the --dir-overridden
ones.

Root cause: main.py does `from pii_buddy.config import ALL_DIRS` at
import time, binding its own module-level `ALL_DIRS` name to the
default list. The `--dir` handling block reassigns `cfg.ALL_DIRS` to
new paths, but that reassignment only updates the `pii_buddy.config`
module's attribute — it does not change main.py's already-bound
`ALL_DIRS` name, which `ensure_dirs()` reads. So `ensure_dirs()` kept
creating the stale default directories, and the real (overridden)
input directory was never created before the file copy ran.
"""
from unittest.mock import patch

import pii_buddy.config as cfg


class TestEnsureDirsRespectsOverride:
    def test_ensure_dirs_uses_current_cfg_all_dirs(self, tmp_path, monkeypatch):
        """ensure_dirs() must create whatever pii_buddy.config.ALL_DIRS
        currently points at, not a stale value captured at import time."""
        import main

        new_dirs = [tmp_path / "input", tmp_path / "output", tmp_path / "mappings"]
        monkeypatch.setattr(cfg, "ALL_DIRS", new_dirs)

        main.ensure_dirs()

        for d in new_dirs:
            assert d.exists(), f"{d} was not created — ensure_dirs() used a stale ALL_DIRS"


class TestOnceWithDirOverride:
    def test_once_with_dir_copies_file_without_error(self, tmp_path):
        """--once FILE --dir PATH must not raise FileNotFoundError copying
        the input file into the (overridden) input directory."""
        source = tmp_path / "source"
        source.mkdir()
        input_file = source / "doc.txt"
        input_file.write_text("hello")

        watch_root = tmp_path / "watchroot"

        with patch("sys.argv", ["main.py", "--once", str(input_file), "--dir", str(watch_root)]), \
             patch("pii_buddy.watcher.process_file", return_value=True) as mock_process:
            from main import main
            try:
                main()
            except SystemExit as e:
                assert e.code == 0, f"main() exited with code {e.code}"

        mock_process.assert_called_once()
        assert (watch_root / "input" / "doc.txt").exists()
