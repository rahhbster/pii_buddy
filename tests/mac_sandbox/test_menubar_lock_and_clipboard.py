"""Regression tests for menubar single-instance lock, clipboard ordering,
error-message hygiene, dock-menu lookup and the login-item plist.

PIIBuddyMenuBar is built with ``__new__`` so no rumps.App is created; only
the attributes each method touches are provided.
"""

import errno
import fcntl
import logging
import logging.handlers
import plistlib
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import pii_buddy.menubar as menubar
from pii_buddy.menubar import PIIBuddyMenuBar

FAKE_PII = "jane.doe@example.com 555-01-0199"
_REAL_WRITE_CLIPBOARD = PIIBuddyMenuBar.__dict__["_write_clipboard"]


@pytest.fixture(autouse=True)
def no_appkit(monkeypatch):
    monkeypatch.setitem(sys.modules, "AppKit", None)


@pytest.fixture
def lock_path(tmp_path, monkeypatch):
    path = tmp_path / "app" / "menubar.lock"
    monkeypatch.setattr(menubar, "_LOCK_FILE_PATH", path)
    monkeypatch.setattr(
        menubar, "_USER_LOCK_FILE_PATH", tmp_path / "user" / "menubar.lock",
        raising=False,
    )
    monkeypatch.setattr(menubar, "_extra_lock_files", [], raising=False)
    monkeypatch.setattr(menubar, "_lock_file", None)
    return path


class TestSingleInstanceLock:
    def test_unwritable_lock_is_not_reported_as_already_running(
        self, lock_path, monkeypatch, capsys
    ):
        def deny(*args, **kwargs):
            raise PermissionError(errno.EPERM, "Operation not permitted")

        monkeypatch.setattr("builtins.open", deny)

        try:
            menubar._exit_if_already_running()
        except SystemExit as exc:
            assert exc.code not in (0, None)
        assert "already running" not in capsys.readouterr().err

    def test_held_lock_exits_zero_as_already_running(self, lock_path, capsys):
        lock_path.parent.mkdir(parents=True)
        holder = open(lock_path, "w")
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with pytest.raises(SystemExit) as exc:
                menubar._exit_if_already_running()
        finally:
            holder.close()
        assert exc.value.code == 0
        assert "already running" in capsys.readouterr().err

    def test_free_lock_is_acquired_and_does_not_exit(self, lock_path):
        menubar._exit_if_already_running()
        assert lock_path.exists()
        menubar._lock_file.close()

    def test_different_base_dirs_cannot_both_run(self, lock_path, tmp_path, monkeypatch):
        menubar._exit_if_already_running()
        first = menubar._lock_file
        other = tmp_path / "other" / "menubar.lock"
        monkeypatch.setattr(menubar, "_LOCK_FILE_PATH", other)
        monkeypatch.setattr(menubar, "_lock_file", None)
        try:
            with pytest.raises(SystemExit) as exc:
                menubar._exit_if_already_running()
        finally:
            first.close()
            for f in menubar._extra_lock_files:
                f.close()
        assert exc.value.code == 0
        assert menubar._lock_file is None

    def test_user_lock_path_is_fixed_and_independent_of_base_dir(self):
        import os
        assert str(menubar._USER_LOCK_FILE_PATH) == os.path.join(
            os.path.expanduser("~/Library/Application Support/PII Buddy"),
            "menubar.lock",
        )

    def test_default_lock_path_is_inside_configured_base_dir(self):
        assert menubar._LOCK_FILE_PATH == menubar.BASE_DIR / "menubar.lock"

    def test_held_flock_skips_bundle_check(self, lock_path, monkeypatch):
        # Two racing launches both see 2 running copies; the flock winner
        # must not exit on that count or both exit(0).
        fake = SimpleNamespace(
            NSRunningApplication=SimpleNamespace(
                runningApplicationsWithBundleIdentifier_=lambda bid: [1, 2]
            )
        )
        monkeypatch.setitem(sys.modules, "AppKit", fake)

        menubar._exit_if_already_running()

        assert menubar._lock_file is not None
        menubar._lock_file.close()

    def test_bundle_check_still_applies_when_lock_unavailable(
        self, lock_path, monkeypatch, capsys
    ):
        fake = SimpleNamespace(
            NSRunningApplication=SimpleNamespace(
                runningApplicationsWithBundleIdentifier_=lambda bid: [1, 2]
            )
        )
        monkeypatch.setitem(sys.modules, "AppKit", fake)
        real_open = open

        def deny(path, *a, **k):
            if str(path) in (str(lock_path), str(menubar._USER_LOCK_FILE_PATH)):
                raise PermissionError(errno.EPERM, "denied")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", deny)

        with pytest.raises(SystemExit) as exc:
            menubar._exit_if_already_running()
        assert exc.value.code == 0
        assert "bundle check" in capsys.readouterr().err


@pytest.fixture
def pipeline(monkeypatch, tmp_path):
    """Patch everything _do_remove_pii pulls in; returns clipboard writes."""
    import pii_buddy.config as cfg
    import pii_buddy.detector as detector
    import pii_buddy.redactor as redactor
    import pii_buddy.settings as settings

    monkeypatch.setattr(cfg, "BASE_DIR", tmp_path)
    monkeypatch.setattr(cfg, "MAPPINGS_DIR", tmp_path / "mappings")
    monkeypatch.setattr(settings, "seed_settings_file", lambda base: None)
    monkeypatch.setattr(
        settings, "resolve_settings",
        lambda base_dir: SimpleNamespace(verify_enabled=False, verify_api_key=None),
    )
    monkeypatch.setattr(detector, "detect_pii", lambda text: [object()])
    monkeypatch.setattr(
        redactor, "redact", lambda text, ents: ("<<EMAIL_1>>", {"entries": {}})
    )
    writes = []
    monkeypatch.setattr(
        PIIBuddyMenuBar, "_read_clipboard", staticmethod(lambda: FAKE_PII)
    )
    monkeypatch.setattr(
        PIIBuddyMenuBar, "_write_clipboard", staticmethod(writes.append)
    )
    return writes


@pytest.fixture
def bar():
    obj = PIIBuddyMenuBar.__new__(PIIBuddyMenuBar)
    obj.notifications = []
    obj._notify = obj.notifications.append
    obj._set_icon = lambda path: None
    obj._show_done_then_reset = lambda: None
    obj._processing = True
    obj._last_mapping_path = None
    obj._last_entities_found = 0
    return obj


class TestClipboardOrdering:
    def test_mapping_dir_failure_leaves_clipboard_untouched(
        self, bar, pipeline, monkeypatch
    ):
        def boom(self, *args, **kwargs):
            raise OSError(errno.EACCES, "denied")

        monkeypatch.setattr(Path, "mkdir", boom)

        bar._do_remove_pii(None)

        assert pipeline == []
        assert bar._processing is False

    def test_mapping_write_failure_leaves_clipboard_untouched(
        self, bar, pipeline, monkeypatch
    ):
        def boom(self, *args, **kwargs):
            raise OSError(errno.ENOSPC, "no space")

        monkeypatch.setattr(menubar.os, "open", boom)

        bar._do_remove_pii(None)

        assert pipeline == []

    def test_success_writes_mapping_then_clipboard(self, bar, pipeline):
        bar._do_remove_pii(None)

        assert pipeline == ["<<EMAIL_1>>"]
        assert bar._last_mapping_path.exists()

    def test_mapping_file_is_owner_only(self, bar, pipeline):
        bar._do_remove_pii(None)

        mode = stat.S_IMODE(bar._last_mapping_path.stat().st_mode)
        assert mode == 0o600

    def test_pbcopy_failure_is_not_reported_as_copied(
        self, bar, pipeline, monkeypatch, caplog
    ):
        def failing_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(1, cmd)

        monkeypatch.setattr(PIIBuddyMenuBar, "_write_clipboard", _REAL_WRITE_CLIPBOARD)
        monkeypatch.setattr(menubar.subprocess, "run", failing_run)

        with caplog.at_level("DEBUG", logger="pii_buddy"):
            bar._do_remove_pii(None)

        assert bar.notifications
        assert any("clipboard" in m.lower() for m in bar.notifications)
        assert all("Copied back" not in m for m in bar.notifications)
        assert all("jane.doe" not in m for m in bar.notifications)
        assert "jane.doe" not in caplog.text
        assert bar._last_mapping_path is None
        assert bar._processing is False

    def test_pbcopy_failure_removes_orphan_mapping(
        self, bar, pipeline, monkeypatch, tmp_path
    ):
        def failing_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(1, cmd)

        monkeypatch.setattr(PIIBuddyMenuBar, "_write_clipboard", _REAL_WRITE_CLIPBOARD)
        monkeypatch.setattr(menubar.subprocess, "run", failing_run)

        bar._do_remove_pii(None)

        assert list((tmp_path / "mappings").glob("clipboard_*.map.json")) == []

    def test_write_clipboard_uses_check_true(self, monkeypatch):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen.update(kwargs)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(menubar.subprocess, "run", fake_run)

        _REAL_WRITE_CLIPBOARD.__func__("x")

        assert seen.get("check") is True


class TestErrorHygiene:
    def test_exception_message_with_pii_never_reaches_notification(
        self, bar, pipeline, monkeypatch
    ):
        import pii_buddy.detector as detector

        def boom(text):
            raise ValueError(f"cannot parse {FAKE_PII}")

        monkeypatch.setattr(detector, "detect_pii", boom)

        bar._do_remove_pii(None)

        assert bar.notifications
        assert all("jane.doe" not in m and "555-01" not in m for m in bar.notifications)
        assert all(not m.startswith("Error:") for m in bar.notifications)

    def test_exception_message_with_pii_never_reaches_log(
        self, bar, pipeline, monkeypatch, caplog
    ):
        import pii_buddy.detector as detector

        def boom(text):
            raise ValueError(f"cannot parse {FAKE_PII}")

        monkeypatch.setattr(detector, "detect_pii", boom)

        with caplog.at_level("DEBUG", logger="pii_buddy"):
            bar._do_remove_pii(None)

        assert "jane.doe" not in caplog.text
        assert "ValueError" in caplog.text

    def test_restore_failure_does_not_leak_exception_message(
        self, bar, monkeypatch, tmp_path
    ):
        import pii_buddy.restorer as restorer

        monkeypatch.setattr(
            PIIBuddyMenuBar, "_read_clipboard", staticmethod(lambda: "x")
        )

        def boom(text, path):
            raise ValueError(FAKE_PII)

        monkeypatch.setattr(restorer, "restore", boom)
        bar._last_mapping_path = tmp_path / "m.json"

        bar._do_restore()

        assert bar.notifications
        assert all("jane.doe" not in m for m in bar.notifications)

    def test_verify_failure_logs_type_only(
        self, bar, pipeline, monkeypatch, caplog
    ):
        import pii_buddy.settings as settings
        verifier = SimpleNamespace()
        monkeypatch.setitem(sys.modules, "pii_buddy.verifier", verifier)
        monkeypatch.setattr(
            settings, "resolve_settings",
            lambda base_dir: SimpleNamespace(
                verify_enabled=True, verify_api_key="k"
            ),
        )

        def boom(*args, **kwargs):
            raise RuntimeError(f"upstream echoed {FAKE_PII}")

        verifier.verify_and_patch = boom

        with caplog.at_level("DEBUG", logger="pii_buddy"):
            bar._do_remove_pii(None)

        assert "jane.doe" not in caplog.text
        assert "RuntimeError" in caplog.text

    def test_private_log_is_owner_only(self, tmp_path, monkeypatch):
        path = tmp_path / "logs" / "menubar.log"
        monkeypatch.setattr(menubar, "_LOG_PATH", path)

        menubar._ensure_private_log()

        assert stat.S_IMODE(path.stat().st_mode) == 0o600


class TestDockLookup:
    def test_keyerror_on_menu_lookup_is_tolerated(self, bar):
        class Menu:
            def __getitem__(self, key):
                raise KeyError(key)

        bar.app = SimpleNamespace(menu=Menu())
        seen = []
        bar._on_remove_pii = seen.append

        bar._dock_remove_pii()

        assert seen == [None]


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setattr(menubar, "_LAUNCHAGENT_DIR", tmp_path / "LaunchAgents")
    monkeypatch.setattr(
        menubar, "_LAUNCHAGENT_PATH", tmp_path / "LaunchAgents" / "a.plist"
    )
    monkeypatch.setattr(menubar, "_LOG_PATH", tmp_path / "logs" / "menubar.log")
    monkeypatch.setattr(menubar, "PII_BUDDY_MAS_BUILD", False)
    return tmp_path / "LaunchAgents" / "a.plist"


class TestLoginItem:
    def test_special_characters_in_paths_produce_valid_plist(
        self, agent, monkeypatch
    ):
        monkeypatch.setattr(sys, "executable", "/opt/a&b <x>/python")
        monkeypatch.delattr(sys, "frozen", raising=False)

        assert menubar._set_login_item(True) is True

        data = plistlib.loads(agent.read_bytes())
        assert data["ProgramArguments"][0] == "/opt/a&b <x>/python"

    def test_frozen_bundle_uses_bundle_executable_only(self, agent, monkeypatch):
        exe = "/Applications/PII Buddy.app/Contents/MacOS/PII Buddy"
        monkeypatch.setattr(sys, "executable", exe)
        monkeypatch.setattr(sys, "frozen", "macosx_app", raising=False)

        menubar._set_login_item(True)

        data = plistlib.loads(agent.read_bytes())
        assert data["ProgramArguments"] == [exe]

    def test_unfrozen_uses_module_invocation(self, agent, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)

        menubar._set_login_item(True)

        args = plistlib.loads(agent.read_bytes())["ProgramArguments"]
        assert args[1:] == ["-m", "pii_buddy.menubar"]

    def test_plist_does_not_duplicate_the_file_log(self, agent):
        # main() already attaches a rotating file handler; routing
        # stdout/stderr to the same file doubles every line unrotated.
        menubar._set_login_item(True)

        data = plistlib.loads(agent.read_bytes())
        assert "StandardOutPath" not in data
        assert "StandardErrorPath" not in data

    def test_oserror_on_enable_does_not_raise_from_toggle(
        self, agent, bar, monkeypatch
    ):
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.setattr(menubar, "_save_prefs", lambda prefs: None)

        def deny(self, *a, **k):
            raise PermissionError(errno.EACCES, "denied")

        monkeypatch.setattr(Path, "write_bytes", deny)
        bar._prefs = {"start_at_login": False}
        sender = SimpleNamespace(state=False)

        bar._on_toggle_login(sender)

        assert sender.state is False
        assert bar.notifications

    def test_oserror_in_first_launch_prompt_still_sets_flag(
        self, agent, bar, monkeypatch
    ):
        monkeypatch.delattr(sys, "frozen", raising=False)
        saved = []
        monkeypatch.setattr(menubar, "_save_prefs", saved.append)

        def deny(self, *a, **k):
            raise PermissionError(errno.EACCES, "denied")

        monkeypatch.setattr(Path, "write_bytes", deny)
        bar._prefs = {"start_at_login": False, "prompted_login": False}
        bar._login_toggle = SimpleNamespace(state=False)
        bar._rumps = SimpleNamespace(alert=lambda **kw: 1)
        timer = SimpleNamespace(stop=lambda: None)

        bar._prompt_start_at_login(timer)

        assert bar._prefs["prompted_login"] is True
        assert saved
        assert bar._prefs["start_at_login"] is False
        assert bar.notifications

    def test_mas_build_skips_launchagent_and_says_so(self, agent, monkeypatch):
        monkeypatch.setattr(menubar, "PII_BUDDY_MAS_BUILD", True)

        assert menubar._set_login_item(True) is False
        assert not agent.exists()

    def test_toggle_in_mas_build_does_not_claim_enabled(
        self, agent, bar, monkeypatch
    ):
        monkeypatch.setattr(menubar, "PII_BUDDY_MAS_BUILD", True)
        monkeypatch.setattr(menubar, "_save_prefs", lambda prefs: None)
        bar._prefs = {"start_at_login": False}
        sender = SimpleNamespace(state=False)

        bar._on_toggle_login(sender)

        assert sender.state is False
        assert bar._prefs["start_at_login"] is False
        assert bar.notifications


class TestStaleLaunchAgent:
    def _write(self, agent, d):
        agent.parent.mkdir(parents=True, exist_ok=True)
        agent.write_bytes(plistlib.dumps(d))

    def test_tmp_log_path_plist_is_rewritten(self, agent, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        self._write(agent, {
            "Label": "dev.piibuddy.menubar",
            "ProgramArguments": [sys.executable, "-m", "pii_buddy.menubar"],
            "StandardOutPath": "/tmp/pii_buddy_menubar.log",
            "StandardErrorPath": "/tmp/pii_buddy_menubar.log",
        })

        assert menubar._refresh_stale_launchagent() is True

        data = plistlib.loads(agent.read_bytes())
        assert "StandardOutPath" not in data
        assert "/tmp/pii_buddy_menubar.log" not in str(data)

    def test_unreachable_interpreter_is_rewritten(self, agent, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        self._write(agent, {
            "Label": "dev.piibuddy.menubar",
            "ProgramArguments": ["/nonexistent/venv/bin/python", "-m", "x"],
        })

        assert menubar._refresh_stale_launchagent() is True
        args = plistlib.loads(agent.read_bytes())["ProgramArguments"]
        assert args[0] == sys.executable

    def test_current_plist_is_left_alone(self, agent, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        menubar._set_login_item(True)
        before = agent.read_bytes()

        assert menubar._refresh_stale_launchagent() is False
        assert agent.read_bytes() == before

    def test_missing_plist_is_not_created(self, agent):
        assert menubar._refresh_stale_launchagent() is False
        assert not agent.exists()

    def test_mas_build_never_rewrites(self, agent, monkeypatch):
        self._write(agent, {"ProgramArguments": ["/nonexistent/python"]})
        monkeypatch.setattr(menubar, "PII_BUDDY_MAS_BUILD", True)
        before = agent.read_bytes()

        assert menubar._refresh_stale_launchagent() is False
        assert agent.read_bytes() == before

    def test_main_refreshes_after_taking_lock(self, monkeypatch):
        order = []
        monkeypatch.setattr(
            menubar, "_exit_if_already_running", lambda: order.append("lock")
        )
        monkeypatch.setattr(
            menubar, "_refresh_stale_launchagent", lambda: order.append("refresh")
        )
        monkeypatch.setattr(menubar, "_make_log_handler", lambda: logging.NullHandler())
        monkeypatch.setattr(
            menubar, "PIIBuddyMenuBar",
            lambda: SimpleNamespace(run=lambda: order.append("run")),
        )

        menubar.main()

        assert order == ["lock", "refresh", "run"]


class TestPlistProgramArguments:
    def test_unfrozen_plist_is_pinned(self, agent, monkeypatch):
        monkeypatch.delattr(sys, "frozen", raising=False)
        monkeypatch.setattr(sys, "executable", "/opt/py/bin/python3")

        menubar._set_login_item(True)

        assert plistlib.loads(agent.read_bytes()) == {
            "Label": "dev.piibuddy.menubar",
            "ProgramArguments": ["/opt/py/bin/python3", "-m", "pii_buddy.menubar"],
            "WorkingDirectory": str(Path(menubar.__file__).parent.parent),
            "RunAtLoad": True,
            "KeepAlive": False,
        }

    def test_frozen_plist_is_pinned(self, agent, monkeypatch):
        exe = "/Applications/PII Buddy.app/Contents/MacOS/PII Buddy"
        monkeypatch.setattr(sys, "executable", exe)
        monkeypatch.setattr(sys, "frozen", "macosx_app", raising=False)

        menubar._set_login_item(True)

        assert plistlib.loads(agent.read_bytes()) == {
            "Label": "dev.piibuddy.menubar",
            "ProgramArguments": [exe],
            "RunAtLoad": True,
            "KeepAlive": False,
        }
