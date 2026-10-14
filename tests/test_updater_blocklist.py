"""Hardening tests for the blocklist updater and loader. All network access
is mocked; no real download happens."""
import base64
import io
import os
import stat
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import pii_buddy.updater as updater
from pii_buddy import validation

OLD = "# header\nskills\neducation\nsummary\n"


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "PACKAGE_BLOCKLISTS_DIR", tmp_path)
    path = tmp_path / "person_blocklist.txt"
    path.write_text(OLD, encoding="utf-8")
    monkeypatch.setattr(updater, "_fetch_via_gh_cli", lambda: None)
    return path


def serve_raw(monkeypatch, payload: bytes):
    mock = MagicMock(side_effect=lambda *a, **k: FakeResp(payload))
    monkeypatch.setattr(updater.urllib.request, "urlopen", mock)
    return mock


class TestLoaderToleratesBadBytes:
    def test_non_utf8_byte_does_not_raise(self, tmp_path):
        f = tmp_path / "bl.txt"
        f.write_bytes(b"alpha\nbad\xff\xfeline\nbeta\n")
        entries = validation._load_blocklist(f)
        assert {"alpha", "beta"} <= entries
        assert not any("�" in e for e in entries)


class TestFetchHardening:
    def test_oversized_download_rejected_and_old_kept(self, target, monkeypatch):
        serve_raw(monkeypatch, b"word\n" * (updater.MAX_DOWNLOAD_BYTES // 5 + 10))
        assert updater.update_blocklists() is False
        assert target.read_text(encoding="utf-8") == OLD

    def test_truncated_non_utf8_download_old_kept(self, target, monkeypatch):
        serve_raw(monkeypatch, b"\xff\xfe\xfa\xfb")
        assert updater.update_blocklists() is False
        assert target.read_text(encoding="utf-8") == OLD

    def test_bad_lines_dropped_good_lines_kept(self, target, monkeypatch):
        payload = b"skills\nok term\nbad\xffline\n" + b"x" * 500 + b"\n\x00ctl\n"
        serve_raw(monkeypatch, payload)
        assert updater.update_blocklists() is True
        lines = target.read_text(encoding="utf-8").splitlines()
        assert "ok term" in lines
        assert all(len(l) <= updater.MAX_LINE_LENGTH for l in lines)
        assert not any("�" in l or "\x00" in l for l in lines)

    def test_empty_remote_refused(self, target, monkeypatch):
        serve_raw(monkeypatch, b"# only a comment\n\n")
        assert updater.update_blocklists() is False
        assert target.read_text(encoding="utf-8") == OLD


class TestGhCliDecodeErrors:
    def _run(self, stdout):
        return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")

    def test_bad_base64_fails_soft(self, monkeypatch):
        monkeypatch.setattr(updater.subprocess, "run",
                            lambda *a, **k: self._run("!!!not base64!!!"))
        assert updater._fetch_via_gh_cli() is None

    def test_non_utf8_payload_does_not_raise_and_yields_no_entries(self, monkeypatch):
        b64 = base64.b64encode(b"\xff\xfe\xfd").decode()
        monkeypatch.setattr(updater.subprocess, "run",
                            lambda *a, **k: self._run(b64))
        text = updater._fetch_via_gh_cli()
        assert updater._sanitize(text or "") == []

    def test_update_keeps_old_when_gh_garbage_and_raw_down(self, tmp_path, monkeypatch):
        monkeypatch.setattr(updater, "PACKAGE_BLOCKLISTS_DIR", tmp_path)
        path = tmp_path / "person_blocklist.txt"
        path.write_text(OLD, encoding="utf-8")
        monkeypatch.setattr(updater.subprocess, "run",
                            lambda *a, **k: self._run("%%%"))
        monkeypatch.setattr(updater.urllib.request, "urlopen",
                            MagicMock(side_effect=OSError("down")))
        assert updater.update_blocklists() is False
        assert path.read_text(encoding="utf-8") == OLD


class TestAtomicWrite:
    def test_failure_mid_write_leaves_old_file_and_no_temp(self, target, monkeypatch):
        serve_raw(monkeypatch, b"skills\nnewterm\n")
        monkeypatch.setattr(updater.os, "replace",
                            MagicMock(side_effect=OSError("boom")))
        with pytest.raises(OSError):
            updater.update_blocklists()
        assert target.read_text(encoding="utf-8") == OLD
        leftovers = [p.name for p in target.parent.iterdir()
                     if p.name != target.name and ".backup_" not in p.name]
        assert leftovers == []

    def test_written_file_is_0600(self, target, monkeypatch):
        serve_raw(monkeypatch, b"skills\nnewterm\n")
        assert updater.update_blocklists() is True
        assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
        assert "newterm" in target.read_text(encoding="utf-8")


class TestRemoteCannotMassUnRedact:
    def test_too_many_new_entries_refused(self, target, monkeypatch):
        names = "\n".join(f"person{i} surname{i}" for i in range(updater.MAX_NEW_ENTRIES + 1))
        serve_raw(monkeypatch, ("skills\n" + names + "\n").encode())
        assert updater.update_blocklists() is False
        assert target.read_text(encoding="utf-8") == OLD

    def test_small_addition_allowed(self, target, monkeypatch):
        serve_raw(monkeypatch, b"skills\neducation\nsummary\nhobbies\n")
        assert updater.update_blocklists() is True
        assert "hobbies" in target.read_text(encoding="utf-8")


class TestTlsAndTimeout:
    def test_default_tls_and_timeout(self, target, monkeypatch):
        mock = serve_raw(monkeypatch, b"skills\nnewterm\n")
        with patch("ssl._create_unverified_context",
                   side_effect=AssertionError("insecure context")) as insecure:
            updater.update_blocklists()
        insecure.assert_not_called()
        assert mock.call_count == 1
        _, kwargs = mock.call_args
        assert "context" not in kwargs
        assert kwargs.get("timeout")
