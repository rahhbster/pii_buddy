"""Shared fixtures for PII Buddy tests, plus the suite-wide hermetic guard.

A previous test run rewrote the owner's real login-item plist.  The guard
below makes that impossible for every test: ``Path.home`` / ``expanduser``
point at tmp before ``pii_buddy.menubar`` is first imported, and every
filesystem mutation entry point fails the test if it touches a real
protected path (tests/test_fs_guard_meta.py proves it in a subprocess).
"""

import builtins
import io
import json
import os
import plistlib
import pwd
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _protected_prefixes():
    homes = {pwd.getpwuid(os.getuid()).pw_dir}
    if os.environ.get("HOME"):
        homes.add(os.environ["HOME"])
    out = []
    for home in sorted(homes):
        out += [
            os.path.join(home, "Library", "LaunchAgents"),
            os.path.join(home, "PII_Buddy"),
            os.path.join(home, "Library", "Application Support", "PII Buddy"),
        ]
    # Trailing "." marks a name prefix rather than a directory.
    out += ["/tmp/pii_buddy_menubar.", "/private/tmp/pii_buddy_menubar."]
    return out


_PROTECTED = _protected_prefixes()
_BANNED_COMMANDS = {"pbcopy", "pbpaste", "launchctl", "osascript", "gh"}

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


def _is_protected(path) -> bool:
    try:
        raw = os.fspath(path)
    except TypeError:
        return False
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    for text in {os.path.abspath(raw), os.path.realpath(raw)}:
        for p in _PROTECTED:
            if p.endswith("."):
                if text.startswith(p):
                    return True
            elif text == p or text.startswith(p + os.sep):
                return True
    return False


def _mentions_banned(*parts) -> bool:
    """True if any string in ``parts`` (nested, or a shell line) names a banned program."""
    for part in parts:
        if isinstance(part, (bytes, os.PathLike)):
            part = os.fsdecode(part)
        if isinstance(part, str):
            for tok in re.split(r"[\s;|&()<>]+", part):
                if tok and os.path.basename(tok) in _BANNED_COMMANDS:
                    return True
        elif isinstance(part, (list, tuple)):
            if _mentions_banned(*part):
                return True
        elif isinstance(part, dict):
            if _mentions_banned(*part.values()):
                return True
    return False


def _guard(path, what):
    if _is_protected(path):
        pytest.fail(f"test touched a real protected path via {what}: {path}")


def install_guards(monkeypatch):
    """Patch every filesystem-mutating entry point to refuse protected paths."""

    def wrap_one(owner, attr):
        real = getattr(owner, attr)
        label = f"{owner.__name__}.{attr}"

        def inner(path, *a, **k):
            _guard(path, label)
            return real(path, *a, **k)

        monkeypatch.setattr(owner, attr, inner)

    def wrap_two(owner, attr):
        real = getattr(owner, attr)
        label = f"{owner.__name__}.{attr}"

        def inner(src, dst, *a, **k):
            _guard(src, label)
            _guard(dst, label)
            return real(src, dst, *a, **k)

        monkeypatch.setattr(owner, attr, inner)

    def wrap_method(attr, second=False):
        real = getattr(Path, attr)
        label = f"Path.{attr}"

        def inner(self, *a, **k):
            _guard(self, label)
            if second and a:
                _guard(a[0], label)
            return real(self, *a, **k)

        monkeypatch.setattr(Path, attr, inner)

    real_open = builtins.open

    def g_open(file, *a, **k):
        if not isinstance(file, int):
            _guard(file, "open")
        return real_open(file, *a, **k)

    monkeypatch.setattr(builtins, "open", g_open)
    monkeypatch.setattr(io, "open", g_open)

    def wrap_dst(owner, attr):
        real = getattr(owner, attr)
        label = f"{owner.__name__}.{attr}"

        def inner(src, dst, *a, **k):
            _guard(dst, label)
            return real(src, dst, *a, **k)

        monkeypatch.setattr(owner, attr, inner)

    for attr in ("open", "mkdir", "makedirs", "chmod", "truncate", "unlink",
                 "remove", "rmdir", "removedirs", "utime", "chown",
                 "setxattr", "removexattr"):
        if hasattr(os, attr):  # the xattr calls are Linux-only
            wrap_one(os, attr)
    for attr in ("replace", "rename", "symlink", "link"):
        wrap_two(os, attr)
    wrap_one(shutil, "rmtree")
    wrap_two(shutil, "move")
    wrap_dst(shutil, "copytree")

    for attr in ("open", "write_bytes", "write_text", "unlink", "mkdir",
                 "touch", "chmod", "rmdir"):
        wrap_method(attr)
    for attr in ("rename", "replace", "symlink_to", "hardlink_to"):
        wrap_method(attr, second=True)

    real_dump = plistlib.dump

    def g_dump(value, fp, *a, **k):
        _guard(getattr(fp, "name", ""), "plistlib.dump")
        return real_dump(value, fp, *a, **k)

    monkeypatch.setattr(plistlib, "dump", g_dump)

    def wrap_exec(owner, attr):
        if not hasattr(owner, attr):
            return
        real = getattr(owner, attr)
        label = f"{owner.__name__}.{attr}"

        def inner(*a, **k):
            if _mentions_banned(*a, *k.values()):
                pytest.fail(f"test ran a real banned program via {label}")
            return real(*a, **k)

        monkeypatch.setattr(owner, attr, inner)

    for attr in ("run", "call", "check_call", "check_output"):
        wrap_exec(subprocess, attr)
    for attr in ("system", "popen", "posix_spawn", "posix_spawnp",
                 "execl", "execle", "execlp", "execlpe", "execv", "execve",
                 "execvp", "execvpe", "spawnl", "spawnle", "spawnlp",
                 "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        wrap_exec(os, attr)

    real_popen = subprocess.Popen

    class GuardedPopen(real_popen):
        def __init__(self, args, *a, **k):
            if _mentions_banned(args, k.get("executable")):
                pytest.fail("test ran a real banned program via subprocess.Popen")
            super().__init__(args, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", GuardedPopen)


@pytest.fixture(autouse=True)
def hermetic(tmp_path_factory, monkeypatch):
    # Outside tmp_path: tests that list their own tmp_path must not see it.
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(
        os.path, "expanduser",
        lambda p: str(home) + p[1:] if str(p).startswith("~") else p,
    )
    install_guards(monkeypatch)
    yield home


# ---------------------------------------------------------------------------
# Minimal entity dataclass (mirrors detector output)
# ---------------------------------------------------------------------------
@dataclass
class FakeEntity:
    text: str
    label: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Settings fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def default_settings():
    """Return a Settings instance with all defaults."""
    from pii_buddy.settings import Settings
    return Settings.defaults()


# ---------------------------------------------------------------------------
# Sample texts and mappings
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_text():
    """A raw text with PII."""
    return (
        "Dear Mr. Sample,\n\n"
        "This is to confirm that Alex Sample and Rory Mockdata "
        "will attend the meeting on March 5. Rory's assistant "
        "will prepare the agenda.\n\n"
        "Best,\nDr. Ava Testcase"
    )


@pytest.fixture
def sample_redacted_text():
    """Text after Pass 1 (spaCy + regex) — deliberately leaves some PII."""
    return (
        "Dear Mr. Sample,\n\n"
        "This is to confirm that <NAME AS> and <NAME RM> "
        "will attend the meeting on March 5. Rory's assistant "
        "will prepare the agenda.\n\n"
        "Best,\nDr. Ava Testcase"
    )


@pytest.fixture
def sample_mapping():
    """Mapping after Pass 1 — matches sample_redacted_text."""
    return {
        "tags": {
            "<NAME AS>": "Alex Sample",
            "<NAME RM>": "Rory Mockdata",
        },
        "persons": {
            "Alex Sample": "<NAME AS>",
            "Rory Mockdata": "<NAME RM>",
            "Alex": "<NAME AS>",
            "Sample": "<NAME AS>",
            "Rory": "<NAME RM>",
            "Mockdata": "<NAME RM>",
        },
    }


@pytest.fixture
def sample_redacted_clean():
    """Fully redacted text (all PII caught by Pass 1)."""
    return (
        "Dear Mr. <NAME AS>,\n\n"
        "This is to confirm that <NAME AS> and <NAME RM> "
        "will attend the meeting on March 5. <NAME RM>'s assistant "
        "will prepare the agenda.\n\n"
        "Best,\n<NAME AC>"
    )
