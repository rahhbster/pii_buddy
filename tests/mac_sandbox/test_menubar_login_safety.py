"""Login-item safety, lock dir perms, mapping-name uniqueness, bundle guard.

Everything runs against tmp paths (see conftest.py's hermetic fixture).
"""

import fcntl
import logging
import os
import plistlib
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import pii_buddy.menubar as menubar

LABEL = "dev.piibuddy.menubar"


@pytest.fixture(autouse=True)
def no_appkit(monkeypatch):
    monkeypatch.setitem(sys.modules, "AppKit", None)


@pytest.fixture
def agent(tmp_path, monkeypatch):
    d = tmp_path / "LaunchAgents"
    monkeypatch.setattr(menubar, "_LAUNCHAGENT_DIR", d)
    monkeypatch.setattr(menubar, "_LAUNCHAGENT_PATH", d / "a.plist")
    monkeypatch.setattr(menubar, "PII_BUDDY_MAS_BUILD", False)
    monkeypatch.delattr(sys, "frozen", raising=False)
    return d / "a.plist"


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(data))


class TestNoAutomaticRewrite:
    def test_rewrite_function_is_gone(self):
        assert not hasattr(menubar, "_refresh_stale_launchagent")

    @pytest.mark.parametrize("old", [
        {"Label": LABEL, "ProgramArguments": [sys.executable],
         "StandardOutPath": "/tmp/pii_buddy_menubar.log"},
        {"Label": LABEL, "ProgramArguments": ["/nonexistent/python", "-m", "x"],
         "WorkingDirectory": "/hand/set", "ThrottleInterval": 30,
         "EnvironmentVariables": {"PII_BUDDY_DIR": "/mine"}},
    ])
    def test_stale_plist_is_warned_about_and_untouched(
        self, agent, old, caplog
    ):
        _write(agent, old)
        before = agent.read_bytes()
        mtime = agent.stat().st_mtime_ns

        with caplog.at_level(logging.WARNING, logger="pii_buddy"):
            assert menubar._warn_if_stale_launchagent() is True

        assert agent.read_bytes() == before
        assert agent.stat().st_mtime_ns == mtime
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "\n" not in warnings[0].getMessage()

    def test_healthy_or_missing_plist_is_silent(self, agent, caplog):
        assert menubar._warn_if_stale_launchagent() is False
        assert not agent.exists()
        _write(agent, {"Label": LABEL, "ProgramArguments": [sys.executable]})
        with caplog.at_level(logging.WARNING, logger="pii_buddy"):
            assert menubar._warn_if_stale_launchagent() is False
        assert not caplog.records

    def test_mas_build_is_silent(self, agent, monkeypatch):
        _write(agent, {"ProgramArguments": ["/nonexistent/python"]})
        monkeypatch.setattr(menubar, "PII_BUDDY_MAS_BUILD", True)
        assert menubar._warn_if_stale_launchagent() is False

    def test_main_warns_after_lock_and_never_writes(self, agent, monkeypatch):
        order = []
        monkeypatch.setattr(
            menubar, "_exit_if_already_running", lambda: order.append("lock")
        )
        monkeypatch.setattr(
            menubar, "_warn_if_stale_launchagent", lambda: order.append("warn")
        )
        monkeypatch.setattr(menubar, "_make_log_handler", lambda: logging.NullHandler())
        monkeypatch.setattr(
            menubar, "PIIBuddyMenuBar",
            lambda: SimpleNamespace(run=lambda: order.append("run")),
        )
        menubar.main()
        assert order == ["lock", "warn", "run"]


class TestExplicitToggleWrite:
    def test_write_is_atomic_via_replace(self, agent, monkeypatch):
        calls = []
        real = os.replace
        monkeypatch.setattr(
            os, "replace", lambda s, d: (calls.append((str(s), str(d))), real(s, d))[1]
        )
        assert menubar._set_login_item(True) is True
        assert len(calls) == 1
        src, dst = calls[0]
        assert dst == str(agent) and src != dst
        assert Path(src).parent == agent.parent
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]

    def test_failed_write_keeps_existing_plist_and_leaves_no_temp(
        self, agent, monkeypatch
    ):
        _write(agent, {"Label": LABEL, "ProgramArguments": ["/old/python"]})
        before = agent.read_bytes()

        def boom(*a):
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            menubar._set_login_item(True)
        assert agent.read_bytes() == before
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]

    def test_no_bak_file_in_launchagents(self, agent):
        _write(agent, {"Label": LABEL, "ProgramArguments": ["/old/python"]})
        menubar._set_login_item(True)
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]

    def test_non_explicit_write_refuses_differing_plist_with_same_label(self, agent):
        _write(agent, {"Label": LABEL, "ProgramArguments": ["/old/python", "-m", "x"]})
        before = agent.read_bytes()
        assert menubar._write_launchagent_plist(explicit=False) is False
        assert agent.read_bytes() == before

    def test_non_explicit_write_creates_when_absent(self, agent):
        assert menubar._write_launchagent_plist(explicit=False) is True
        assert plistlib.loads(agent.read_bytes())["Label"] == LABEL

    def test_explicit_toggle_preserves_hand_set_keys(self, agent):
        _write(agent, {
            "Label": LABEL,
            "ProgramArguments": ["/old/python"],
            "StandardOutPath": "/tmp/pii_buddy_menubar.log",
            "ThrottleInterval": 30,
            "EnvironmentVariables": {"PII_BUDDY_DIR": "/mine"},
        })
        menubar._set_login_item(True)
        data = plistlib.loads(agent.read_bytes())
        assert data["ThrottleInterval"] == 30
        assert data["EnvironmentVariables"] == {"PII_BUDDY_DIR": "/mine"}
        assert data["ProgramArguments"][0] == sys.executable
        assert "StandardOutPath" not in data

    def test_foreign_label_plist_is_not_merged(self, agent):
        _write(agent, {"Label": "com.other", "ThrottleInterval": 5})
        menubar._set_login_item(True)
        assert "ThrottleInterval" not in plistlib.loads(agent.read_bytes())


class TestLockDirectories:
    @pytest.fixture
    def paths(self, tmp_path, monkeypatch):
        a = tmp_path / "base" / "menubar.lock"
        b = tmp_path / "user" / "PII Buddy" / "menubar.lock"
        monkeypatch.setattr(menubar, "_LOCK_FILE_PATH", a)
        monkeypatch.setattr(menubar, "_USER_LOCK_FILE_PATH", b)
        monkeypatch.setattr(menubar, "_lock_file", None)
        monkeypatch.setattr(menubar, "_extra_lock_files", [])
        return a, b

    def test_lock_dirs_are_0700(self, paths):
        a, b = paths
        menubar._exit_if_already_running()
        try:
            for p in (a, b):
                assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
        finally:
            menubar._lock_file.close()
            for f in menubar._extra_lock_files:
                f.close()

    def test_losing_instance_creates_nothing_new(self, paths):
        a, b = paths
        b.parent.mkdir(parents=True)
        holder = open(b, "w")
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with pytest.raises(SystemExit):
                menubar._exit_if_already_running()
        finally:
            holder.close()
        assert not a.exists()
        assert not a.parent.exists()


class TestMappingNameClaim:
    def test_same_second_claims_distinct_names(self, tmp_path):
        from datetime import datetime
        now = datetime(2026, 1, 2, 3, 4, 5, 123456)
        first = menubar._claim_mapping_path(tmp_path, now)
        second = menubar._claim_mapping_path(tmp_path, now)
        third = menubar._claim_mapping_path(tmp_path, now)
        assert len({first, second, third}) == 3
        for p in (first, second, third):
            assert p.name.startswith("clipboard_20260102_030405")
            assert p.name.endswith(".map.json")
            assert stat.S_IMODE(p.stat().st_mode) == 0o600

    def test_never_overwrites_existing_map(self, tmp_path):
        from datetime import datetime
        now = datetime(2026, 1, 2, 3, 4, 5, 0)
        first = menubar._claim_mapping_path(tmp_path, now)
        first.write_text("original restore map")
        second = menubar._claim_mapping_path(tmp_path, now)
        assert second != first
        assert first.read_text() == "original restore map"


class TestBundleGuardIsUnconditional:
    def _appkit(self, monkeypatch, apps_per_poll):
        polls = iter(apps_per_poll)
        last = [None]

        def running(bid):
            try:
                last[0] = next(polls)
            except StopIteration:
                pass
            return last[0]

        monkeypatch.setitem(sys.modules, "AppKit", SimpleNamespace(
            NSRunningApplication=SimpleNamespace(
                runningApplicationsWithBundleIdentifier_=running
            )
        ))

    @pytest.fixture(autouse=True)
    def locks(self, tmp_path, monkeypatch):
        monkeypatch.setattr(menubar, "_LOCK_FILE_PATH", tmp_path / "a" / "l")
        monkeypatch.setattr(menubar, "_USER_LOCK_FILE_PATH", tmp_path / "b" / "l")
        monkeypatch.setattr(menubar, "_lock_file", None)
        monkeypatch.setattr(menubar, "_extra_lock_files", [])
        monkeypatch.setattr(menubar.time, "sleep", lambda s: None)

    @staticmethod
    def _app(pid):
        return SimpleNamespace(processIdentifier=lambda: pid)

    def _close(self):
        menubar._lock_file.close()
        for f in menubar._extra_lock_files:
            f.close()

    def test_old_build_instance_is_caught_even_when_locks_acquired(
        self, monkeypatch, capsys
    ):
        mine, old = self._app(os.getpid()), self._app(os.getpid() + 1)
        self._appkit(monkeypatch, [[mine, old]])
        with pytest.raises(SystemExit) as exc:
            menubar._exit_if_already_running()
        assert exc.value.code == 0
        assert "bundle check" in capsys.readouterr().err

    def test_racing_loser_that_exits_does_not_take_the_winner_down(
        self, monkeypatch
    ):
        mine, loser = self._app(os.getpid()), self._app(os.getpid() + 1)
        self._appkit(monkeypatch, [[mine, loser], [mine]])
        menubar._exit_if_already_running()
        assert menubar._lock_file is not None
        self._close()

    def test_only_self_running_is_fine(self, monkeypatch):
        self._appkit(monkeypatch, [[self._app(os.getpid())]])
        menubar._exit_if_already_running()
        self._close()
