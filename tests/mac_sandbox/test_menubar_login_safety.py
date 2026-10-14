"""Login-item safety, lock dir perms, mapping-name uniqueness, bundle guard.

Everything runs against tmp paths (see conftest.py's hermetic fixture).
"""

import errno
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
            menubar._set_login_item(True, confirm_replace=lambda: True)
        assert agent.read_bytes() == before
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]

    def test_no_bak_file_in_launchagents(self, agent):
        _write(agent, {"Label": LABEL, "ProgramArguments": ["/old/python"]})
        menubar._set_login_item(True, confirm_replace=lambda: True)
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]

    def test_write_without_permission_refuses_differing_plist(self, agent):
        _write(agent, {"Label": LABEL, "ProgramArguments": ["/old/python", "-m", "x"]})
        before = agent.read_bytes()
        with pytest.raises(menubar.LoginItemRefused):
            menubar._write_launchagent_plist(allow_replace=False)
        assert agent.read_bytes() == before

    def test_write_creates_when_absent(self, agent):
        assert menubar._write_launchagent_plist(allow_replace=False) is True
        assert plistlib.loads(agent.read_bytes())["Label"] == LABEL

    def test_explicit_toggle_preserves_hand_set_keys(self, agent):
        _write(agent, {
            "Label": LABEL,
            "ProgramArguments": ["/old/python"],
            "StandardOutPath": "/tmp/pii_buddy_menubar.log",
            "ThrottleInterval": 30,
            "EnvironmentVariables": {"PII_BUDDY_DIR": "/mine"},
        })
        menubar._set_login_item(True, confirm_replace=lambda: True)
        data = plistlib.loads(agent.read_bytes())
        assert data["ThrottleInterval"] == 30
        assert data["EnvironmentVariables"] == {"PII_BUDDY_DIR": "/mine"}
        assert data["ProgramArguments"][0] == sys.executable
        assert "StandardOutPath" not in data


class TestLoginItemReportsHonestly:
    DIFFERENT = {"Label": LABEL, "ProgramArguments": ["/old/python", "-m", "x"]}

    def _same(self):
        return menubar._build_launchagent_plist()

    def test_differing_args_without_confirm_is_refused_and_unchanged(
        self, agent, caplog
    ):
        _write(agent, self.DIFFERENT)
        before = agent.read_bytes()
        with caplog.at_level(logging.INFO, logger="pii_buddy"):
            with pytest.raises(menubar.LoginItemRefused):
                menubar._set_login_item(True)
        assert agent.read_bytes() == before
        assert "Login item created" not in caplog.text
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]

    def test_differing_args_declined_is_refused_and_unchanged(self, agent):
        _write(agent, self.DIFFERENT)
        before = agent.read_bytes()
        asked = []
        with pytest.raises(menubar.LoginItemRefused):
            menubar._set_login_item(
                True, confirm_replace=lambda: asked.append(1) or False
            )
        assert asked == [1]
        assert agent.read_bytes() == before

    def test_differing_args_confirmed_replaces(self, agent):
        _write(agent, self.DIFFERENT)
        asked = []
        assert menubar._set_login_item(
            True, confirm_replace=lambda: asked.append(1) or True
        ) is True
        assert asked == [1]
        data = plistlib.loads(agent.read_bytes())
        assert data["ProgramArguments"] == self._same()["ProgramArguments"]

    def test_same_args_does_not_ask(self, agent):
        _write(agent, self._same())
        assert menubar._set_login_item(
            True, confirm_replace=lambda: pytest.fail("asked")
        ) is True

    def _rich(self):
        d = dict(self._same())
        d.update({
            "StandardOutPath": str(menubar.LOGS_DIR / "out.log"),
            "StandardErrorPath": str(menubar.LOGS_DIR / "err.log"),
            "ThrottleInterval": 30,
            "EnvironmentVariables": {"PII_BUDDY_DIR": "/mine"},
            "KeepAlive": True,
        })
        return d

    def test_same_label_and_args_is_a_noop_and_writes_nothing(
        self, agent, monkeypatch
    ):
        _write(agent, self._rich())
        before = agent.read_bytes()
        monkeypatch.setattr(
            os, "replace", lambda *a: pytest.fail("rewrote an identical login item")
        )
        monkeypatch.setattr(
            menubar.tempfile, "mkstemp", lambda *a, **k: pytest.fail("wrote temp")
        )
        assert menubar._write_launchagent_plist(allow_replace=False) is True
        assert menubar._set_login_item(
            True, confirm_replace=lambda: pytest.fail("asked")
        ) is True
        assert agent.read_bytes() == before

    def test_confirmed_replace_merges_and_keeps_every_other_key(self, agent):
        old = self._rich()
        old["ProgramArguments"] = ["/old/python", "-m", "x"]
        old["WorkingDirectory"] = "/old/dir"
        old["RunAtLoad"] = False
        _write(agent, old)
        assert menubar._set_login_item(True, confirm_replace=lambda: True) is True
        data = plistlib.loads(agent.read_bytes())
        new = self._same()
        assert data["ProgramArguments"] == new["ProgramArguments"]
        assert data.get("WorkingDirectory") == new.get("WorkingDirectory")
        assert data["RunAtLoad"] is True
        for k in ("StandardOutPath", "StandardErrorPath", "ThrottleInterval",
                  "EnvironmentVariables", "KeepAlive"):
            assert data[k] == old[k]

    def test_state_off_toggle_is_unaffected(self, agent):
        assert menubar._set_login_item(False) is True

    @pytest.mark.parametrize("old", [
        {"Label": "com.other", "ProgramArguments": ["/x"], "ThrottleInterval": 5},
        {"ProgramArguments": ["/x"]},
    ])
    def test_different_label_is_never_replaced(self, agent, old):
        _write(agent, old)
        before = agent.read_bytes()
        with pytest.raises(menubar.LoginItemRefused):
            menubar._set_login_item(True, confirm_replace=lambda: True)
        assert agent.read_bytes() == before

    def test_unparseable_plist_is_never_replaced(self, agent):
        agent.parent.mkdir(parents=True)
        agent.write_bytes(b"not a plist")
        with pytest.raises(menubar.LoginItemRefused):
            menubar._set_login_item(True, confirm_replace=lambda: True)
        assert agent.read_bytes() == b"not a plist"

    def _bar(self, monkeypatch, answer):
        bar = menubar.PIIBuddyMenuBar.__new__(menubar.PIIBuddyMenuBar)
        bar.notifications = []
        bar._notify = bar.notifications.append
        bar._prefs = {"start_at_login": False}
        bar._rumps = SimpleNamespace(alert=lambda **kw: answer)
        monkeypatch.setattr(menubar, "_save_prefs", lambda prefs: None)
        return bar

    def test_toggle_declined_keeps_state_off_and_tells_user(
        self, agent, monkeypatch
    ):
        _write(agent, self.DIFFERENT)
        before = agent.read_bytes()
        bar = self._bar(monkeypatch, 0)
        sender = SimpleNamespace(state=False)
        bar._on_toggle_login(sender)
        assert sender.state is False
        assert bar._prefs["start_at_login"] is False
        assert bar.notifications
        assert agent.read_bytes() == before

    def test_toggle_confirmed_replaces_and_turns_on(self, agent, monkeypatch):
        _write(agent, self.DIFFERENT)
        bar = self._bar(monkeypatch, 1)
        sender = SimpleNamespace(state=False)
        bar._on_toggle_login(sender)
        assert sender.state is True
        assert plistlib.loads(agent.read_bytes())["ProgramArguments"][0] == sys.executable

    def test_toggle_foreign_label_refused_without_asking(self, agent, monkeypatch):
        _write(agent, {"Label": "com.other", "ProgramArguments": ["/x"]})
        before = agent.read_bytes()
        bar = self._bar(monkeypatch, 1)
        sender = SimpleNamespace(state=False)
        bar._on_toggle_login(sender)
        assert sender.state is False
        assert bar.notifications
        assert agent.read_bytes() == before


class TestStaleLogPathsAreDropped:
    STALE = "/tmp/pii_buddy_menubar.log"
    KEEP = {
        "ThrottleInterval": 30,
        "EnvironmentVariables": {"PII_BUDDY_DIR": "/mine"},
        "KeepAlive": False,
    }

    def _old(self, **extra):
        return {"Label": LABEL, "ProgramArguments": ["/old/python", "-m", "x"],
                "RunAtLoad": True, **self.KEEP, **extra}

    def _same(self, **extra):
        return {**menubar._build_launchagent_plist(), **self.KEEP, **extra}

    @pytest.mark.parametrize("path", [
        "/tmp/pii_buddy_menubar.log", "/mine/out.log", "/private/tmp/x.log",
    ])
    def test_replace_drops_stale_and_outside_logs_keeps_rest(self, agent, path):
        _write(agent, self._old(StandardOutPath=path, StandardErrorPath=path))
        menubar._write_launchagent_plist(allow_replace=True)
        data = plistlib.loads(agent.read_bytes())
        assert "StandardOutPath" not in data
        assert "StandardErrorPath" not in data
        for k, v in self.KEEP.items():
            assert data[k] == v
        assert data["ProgramArguments"][0] == sys.executable

    def test_replace_keeps_log_inside_logs_dir(self, agent):
        inside = str(menubar.LOGS_DIR / "mine.log")
        _write(agent, self._old(StandardOutPath=inside))
        menubar._write_launchagent_plist(allow_replace=True)
        assert plistlib.loads(agent.read_bytes())["StandardOutPath"] == inside

    def test_symlink_escape_from_logs_dir_is_dropped(
        self, agent, tmp_path, monkeypatch
    ):
        logs = tmp_path / "logs"
        logs.mkdir()
        monkeypatch.setattr(menubar, "LOGS_DIR", logs)
        link = logs / "escape"
        outside = tmp_path / "outside"
        outside.mkdir()
        link.symlink_to(outside)
        _write(agent, self._old(StandardOutPath=str(link / "a.log")))
        menubar._write_launchagent_plist(allow_replace=True)
        assert "StandardOutPath" not in plistlib.loads(agent.read_bytes())

    def test_same_args_with_stale_logs_is_cleaned_without_prompt(
        self, agent, caplog
    ):
        _write(agent, self._same(
            StandardOutPath=self.STALE, StandardErrorPath=self.STALE
        ))
        with caplog.at_level(logging.INFO, logger="pii_buddy"):
            assert menubar._set_login_item(
                True, confirm_replace=lambda: pytest.fail("asked")
            ) is True
        data = plistlib.loads(agent.read_bytes())
        assert "StandardOutPath" not in data
        assert "StandardErrorPath" not in data
        for k, v in self.KEEP.items():
            assert data[k] == v
        assert data["ProgramArguments"] == menubar._build_launchagent_plist()[
            "ProgramArguments"
        ]
        assert sorted(p.name for p in agent.parent.iterdir()) == [agent.name]
        assert "unchanged" not in caplog.text

    def test_cleaned_plist_no_longer_warns(self, agent):
        _write(agent, self._same(StandardOutPath=self.STALE))
        assert menubar._warn_if_stale_launchagent() is True
        menubar._set_login_item(True)
        assert menubar._warn_if_stale_launchagent() is False

    def test_clean_identical_plist_is_noop_and_logs_unchanged(
        self, agent, monkeypatch, caplog
    ):
        _write(agent, self._same())
        before = agent.read_bytes()
        monkeypatch.setattr(
            os, "replace", lambda *a: pytest.fail("rewrote an identical item")
        )
        with caplog.at_level(logging.INFO, logger="pii_buddy"):
            assert menubar._set_login_item(True) is True
        assert agent.read_bytes() == before
        assert "unchanged" in caplog.text
        assert "Login item created" not in caplog.text


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

    def test_directory_a_winner_made_is_not_ours_to_remove(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / "race" / "menubar.lock"
        real = os.mkdir

        def racing(p, *a, **k):
            real(p, *a, **k)
            raise FileExistsError(errno.EEXIST, "made by the winner")

        monkeypatch.setattr(os, "mkdir", racing)
        created = []
        menubar._try_lock(path, created)
        assert path.parent not in created

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
        assert not a.exists() or a.read_bytes() == b""
        assert list(a.parent.iterdir()) in ([], [a])

    def test_lock_messages_do_not_print_the_path(
        self, tmp_path, monkeypatch, capsys
    ):
        secret = tmp_path / "secret-dir-name" / "menubar.lock"
        monkeypatch.setattr(os, "open", lambda *a, **k: (_ for _ in ()).throw(
            PermissionError(errno.EACCES, "denied", str(secret))
        ))
        assert menubar._try_lock(secret, [])[0] == "unavailable"
        err = capsys.readouterr().err
        assert "secret-dir-name" not in err
        assert "PermissionError" in err

    def test_flock_failure_message_does_not_print_the_path(
        self, tmp_path, monkeypatch, capsys
    ):
        secret = tmp_path / "secret-dir-name" / "menubar.lock"

        def boom(f, op):
            raise OSError(errno.EIO, "io", str(secret))

        monkeypatch.setattr(fcntl, "flock", boom)
        assert menubar._try_lock(secret, [])[0] == "unavailable"
        err = capsys.readouterr().err
        assert "secret-dir-name" not in err
        assert "OSError" in err

    def test_lock_file_is_never_unlinked(self, tmp_path, monkeypatch):
        path = tmp_path / "x" / "menubar.lock"
        monkeypatch.setattr(
            os, "unlink", lambda *a: pytest.fail("unlinked a lock file")
        )
        monkeypatch.setattr(
            Path, "unlink", lambda *a, **k: pytest.fail("unlinked a lock file")
        )
        created = []
        state, f = menubar._try_lock(path, created)
        assert state == "acquired"
        f.close()
        assert path not in created
        menubar._remove_created(created)
        assert path.exists()

    def test_creator_that_lost_flock_leaves_winners_inode_alone(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / "y" / "menubar.lock"
        real_flock = fcntl.flock
        winner = {}

        def racing(fobj, op):
            if "f" not in winner:
                winner["f"] = open(path, "a")
                real_flock(winner["f"], fcntl.LOCK_EX | fcntl.LOCK_NB)
            return real_flock(fobj, op)

        monkeypatch.setattr(fcntl, "flock", racing)
        created = []
        state, f = menubar._try_lock(path, created)
        assert state == "held"
        menubar._remove_created(created)
        try:
            assert path.exists()
            assert os.fstat(winner["f"].fileno()).st_ino == path.stat().st_ino
        finally:
            winner["f"].close()


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
