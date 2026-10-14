"""Hermetic guard for the menubar tests.

A previous test run rewrote the owner's real login-item plist.  Everything
here makes that impossible: ``Path.home`` / ``expanduser`` point at tmp
before ``pii_buddy.menubar`` is first imported, and every filesystem entry
point fails the test if it touches a real protected path.
"""

import builtins
import os
import plistlib
import pwd
import subprocess
import tempfile
from pathlib import Path

import pytest

_REAL_HOME = pwd.getpwuid(os.getuid()).pw_dir
_PROTECTED = (
    os.path.join(_REAL_HOME, "Library", "LaunchAgents"),
    os.path.join(_REAL_HOME, "PII_Buddy"),
    os.path.join(_REAL_HOME, "Library", "Application Support", "PII Buddy"),
    "/tmp/pii_buddy_menubar.",
    "/private/tmp/pii_buddy_menubar.",
)
_BANNED_COMMANDS = {"pbcopy", "pbpaste", "launchctl"}

_orig_home = Path.home
_orig_expanduser = os.path.expanduser
_import_home = Path(tempfile.mkdtemp(prefix="pii_buddy_import_"))
os.environ.setdefault("PII_BUDDY_DIR", str(_import_home / "PII_Buddy"))
Path.home = classmethod(lambda cls: _import_home)
os.path.expanduser = (
    lambda p: str(_import_home) + p[1:] if str(p).startswith("~") else p
)
try:
    import pii_buddy.menubar  # noqa: F401  (constants now resolve under tmp)
finally:
    Path.home = _orig_home
    os.path.expanduser = _orig_expanduser


def _protected(path) -> bool:
    try:
        text = os.path.abspath(os.fspath(path))
    except TypeError:
        return False
    return any(text == p or text.startswith(p) for p in _PROTECTED)


def _guard(path, what):
    if _protected(path):
        pytest.fail(f"test touched a real protected path via {what}: {path}")


@pytest.fixture(autouse=True)
def hermetic(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(
        os.path, "expanduser",
        lambda p: str(home) + p[1:] if str(p).startswith("~") else p,
    )

    real_open = builtins.open
    real_os_open = os.open
    real_replace = os.replace
    real_rename = os.rename
    real_unlink = os.unlink
    real_remove = os.remove
    real_write_bytes = Path.write_bytes
    real_write_text = Path.write_text
    real_unlink_p = Path.unlink
    real_dump = plistlib.dump
    real_run = subprocess.run

    def g_open(file, *a, **k):
        if not isinstance(file, int):
            _guard(file, "open")
        return real_open(file, *a, **k)

    def g_os_open(path, *a, **k):
        _guard(path, "os.open")
        return real_os_open(path, *a, **k)

    def g_two(real, name):
        def inner(src, dst, *a, **k):
            _guard(src, name)
            _guard(dst, name)
            return real(src, dst, *a, **k)
        return inner

    def g_one(real, name):
        def inner(path, *a, **k):
            _guard(path, name)
            return real(path, *a, **k)
        return inner

    def g_method(real, name):
        def inner(self, *a, **k):
            _guard(self, name)
            return real(self, *a, **k)
        return inner

    def g_dump(value, fp, *a, **k):
        _guard(getattr(fp, "name", ""), "plistlib.dump")
        return real_dump(value, fp, *a, **k)

    def g_run(args, *a, **k):
        cmd = args if isinstance(args, str) else (args[0] if args else "")
        if os.path.basename(str(cmd)) in _BANNED_COMMANDS:
            pytest.fail(f"test ran a real {cmd}")
        return real_run(args, *a, **k)

    monkeypatch.setattr(builtins, "open", g_open)
    monkeypatch.setattr(os, "open", g_os_open)
    monkeypatch.setattr(os, "replace", g_two(real_replace, "os.replace"))
    monkeypatch.setattr(os, "rename", g_two(real_rename, "os.rename"))
    monkeypatch.setattr(os, "unlink", g_one(real_unlink, "os.unlink"))
    monkeypatch.setattr(os, "remove", g_one(real_remove, "os.remove"))
    monkeypatch.setattr(Path, "write_bytes", g_method(real_write_bytes, "write_bytes"))
    monkeypatch.setattr(Path, "write_text", g_method(real_write_text, "write_text"))
    monkeypatch.setattr(Path, "unlink", g_method(real_unlink_p, "Path.unlink"))
    monkeypatch.setattr(plistlib, "dump", g_dump)
    monkeypatch.setattr(subprocess, "run", g_run)
    yield home
