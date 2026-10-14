"""World-readable log roots are decided by filesystem identity, not spelling.

APFS is case-insensitive and Unicode-folding, so ``/PRIVATE/TMP`` and
``/Uſers/Shared`` are the same directories as the lexical roots even though
the strings differ.
"""

import os
import tempfile
from pathlib import Path

import pytest

import pii_buddy.menubar as menubar


def _fs_is_case_insensitive() -> bool:
    with tempfile.TemporaryDirectory(prefix="pii_buddy_case_") as td:
        (Path(td) / "probe").write_text("x")
        return (Path(td) / "PROBE").exists()


needs_case_insensitive = pytest.mark.skipif(
    not _fs_is_case_insensitive(),
    reason="filesystem is case-sensitive; differently-cased spellings of a "
    "world-readable root are not the same directory here",
)


@needs_case_insensitive
@pytest.mark.parametrize("path", [
    "/PRIVATE/TMP/x.log", "/private/TMP/x.log", "/Private/Var/Tmp/x.log",
    "/var/TMP/x.log", "/USERS/SHARED/x.log", "/users/shared/x.log",
    "/TMP/deep/er/x.log",
])
def test_case_variants_of_world_readable_roots_are_stale(path):
    assert menubar._is_stale_log_path(path) is True


@needs_case_insensitive
def test_unicode_fold_of_users_shared_is_stale():
    if not os.path.exists("/Uſers/Shared"):
        pytest.skip("filesystem does not fold U+017F to s")
    assert menubar._is_stale_log_path("/Uſers/Shared/x.log") is True


def test_symlink_to_root_with_missing_leaf_is_stale(tmp_path):
    link = tmp_path / "lnk"
    link.symlink_to("/tmp")
    assert menubar._is_stale_log_path(str(link / "new" / "x.log")) is True


def test_user_path_in_tmp_home_is_kept(tmp_path):
    mine = tmp_path / "home" / "Library" / "Logs"
    mine.mkdir(parents=True)
    real = os.path.realpath(str(mine))
    for root in ("/tmp", "/var/tmp"):
        if real.startswith(os.path.realpath(root) + os.sep):
            pytest.skip("pytest tmp_path itself lives under a world-readable root")
    assert menubar._is_stale_log_path(str(mine / "x.log")) is False


def test_identity_logic_with_fake_stat(monkeypatch):
    real_stat = os.stat
    root = real_stat("/tmp")

    def fake_stat(path, *a, **kw):
        if isinstance(path, str) and path == "/Fake/CASED/TMP":
            return root
        return real_stat(path, *a, **kw)

    monkeypatch.setattr(os, "stat", fake_stat)
    assert menubar._is_stale_log_path("/Fake/CASED/TMP/x.log") is True
    assert menubar._is_stale_log_path("/Fake/CASED/TMP/sub/x.log") is True
    assert menubar._is_stale_log_path("/Fake/OTHER/x.log") is False
