"""main() log wiring and the py2app entry template."""

import logging
import logging.handlers
import re
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import pii_buddy.menubar as menubar


@pytest.fixture
def main_env(tmp_path, monkeypatch):
    monkeypatch.setattr(menubar, "_LOG_PATH", tmp_path / "logs" / "menubar.log")
    monkeypatch.setattr(logging, "basicConfig", lambda **kw: None)
    monkeypatch.setattr(menubar, "_exit_if_already_running", lambda: None)
    monkeypatch.setattr(menubar, "_refresh_stale_launchagent", lambda: False)
    monkeypatch.setattr(
        menubar, "PIIBuddyMenuBar", lambda: SimpleNamespace(run=lambda: None)
    )
    before = list(menubar.logger.handlers)
    yield
    for h in list(menubar.logger.handlers):
        if h not in before:
            menubar.logger.removeHandler(h)
            h.close()


def test_main_attaches_rotating_file_handler(main_env):
    menubar.main()

    added = [
        h for h in menubar.logger.handlers if isinstance(h, logging.FileHandler)
    ]
    assert added
    assert all(
        isinstance(h, logging.handlers.RotatingFileHandler) and h.maxBytes > 0
        for h in added
    )


def test_rotated_log_stays_owner_only(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "menubar.log"
    monkeypatch.setattr(menubar, "_LOG_PATH", path)
    handler = menubar._make_log_handler(max_bytes=64, backup_count=1)
    try:
        for i in range(20):
            handler.emit(
                logging.LogRecord(
                    "t", logging.INFO, "", 0, f"line {i} " * 4, None, None
                )
            )
    finally:
        handler.close()

    rotated = path.with_name("menubar.log.1")
    assert rotated.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(rotated.stat().st_mode) == 0o600


def test_py2app_entry_delegates_to_menubar_main(monkeypatch):
    script = Path(__file__).resolve().parents[2] / "extras" / "build_py2app.sh"
    match = re.search(
        r"_py2app_entry\.py\" << 'ENTRY'\n(.*?)\nENTRY\n",
        script.read_text(encoding="utf-8"),
        re.S,
    )
    assert match, "entry template not found in build_py2app.sh"

    called = []
    fake = SimpleNamespace(main=lambda: called.append("main"))
    monkeypatch.setitem(sys.modules, "pii_buddy.menubar", fake)
    monkeypatch.setattr(sys.modules["pii_buddy"], "menubar", fake, raising=False)
    ns = {"__name__": "not_main"}
    exec(compile(match.group(1), "_py2app_entry.py", "exec"), ns)

    ns["main"]()

    assert called == ["main"]
