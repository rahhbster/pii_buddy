"""--update / --force-update exit codes and force passthrough (mocked updater)."""

from unittest.mock import patch

import pytest

from pii_buddy.updater import UpdateResult


def _run(tmp_path, extra, result):
    base = tmp_path / "base"
    for d in ("input", "output", "mappings", "originals", "logs", "blocklists"):
        (base / d).mkdir(parents=True, exist_ok=True)
    argv = ["main.py", "--dir", str(base), *extra]
    with patch("sys.argv", argv), \
            patch("pii_buddy.updater.update_blocklists", return_value=result) as upd, \
            patch("pii_buddy.validation.reload_blocklist") as reload_:
        from main import main
        code = 0
        try:
            main()
        except SystemExit as e:
            code = e.code or 0
    return code, upd, reload_


@pytest.mark.parametrize("status,code", [
    ("updated", 0), ("unchanged", 0), ("refused", 1), ("failed", 1),
])
def test_update_exit_codes(tmp_path, status, code):
    got, upd, _ = _run(tmp_path, ["--update"], UpdateResult(status, "because"))
    assert got == code
    upd.assert_called_once_with(force=False)


def test_force_update_passes_force(tmp_path):
    got, upd, reload_ = _run(tmp_path, ["--force-update"], UpdateResult("updated", ""))
    assert got == 0
    upd.assert_called_once_with(force=True)
    reload_.assert_called_once()


def test_refused_prints_status_not_reason_again(tmp_path, capsys):
    got, _, reload_ = _run(tmp_path, ["--update"], UpdateResult("refused", "too many new entries"))
    assert got == 1
    err = capsys.readouterr().err
    assert "refused" in err
    assert "too many new entries" not in err
    reload_.assert_not_called()


# --- real updater behind the CLI (fetch mocked, no network) ---------------

OLD_LIST = "# header\nskills\neducation\nsummary\n"


@pytest.fixture
def real_updater(tmp_path, monkeypatch):
    import pii_buddy.updater as updater
    blocklists = tmp_path / "pkg_blocklists"
    blocklists.mkdir()
    (blocklists / "person_blocklist.txt").write_text(OLD_LIST, encoding="utf-8")
    (blocklists / updater.BASELINE_NAME).write_text(OLD_LIST, encoding="utf-8")
    monkeypatch.setattr(updater, "PACKAGE_BLOCKLISTS_DIR", blocklists)
    over = updater.MAX_NEW_ENTRIES + 7
    names = "\n".join(f"person{i} surname{i}" for i in range(over))
    monkeypatch.setattr(updater, "_fetch_via_gh_cli", lambda: "skills\n" + names + "\n")
    return updater, blocklists / "person_blocklist.txt", over


def _run_real(tmp_path, extra):
    base = tmp_path / "base"
    for d in ("input", "output", "mappings", "originals", "logs", "blocklists"):
        (base / d).mkdir(parents=True, exist_ok=True)
    argv = ["main.py", "--dir", str(base), *extra]
    code = 0
    with patch("sys.argv", argv), patch("pii_buddy.validation.reload_blocklist"):
        from main import main
        try:
            main()
        except SystemExit as e:
            code = e.code or 0
    return code


def test_refusal_reason_is_printed_once(tmp_path, real_updater, capsys, caplog):
    _, target, over = real_updater
    with caplog.at_level("DEBUG"):
        code = _run_real(tmp_path, ["--update"])
    out = capsys.readouterr()
    text = caplog.text + out.out + out.err
    assert code == 1
    assert text.count(f"{over} new entries exceeds cap") == 1
    assert "refused: refused" not in text
    assert target.read_text(encoding="utf-8") == OLD_LIST


def test_force_update_warns_with_count_before_applying(tmp_path, real_updater, capsys, caplog):
    updater, target, over = real_updater
    real_write = updater._write_atomic
    seen = {}

    def spy(path, content, mode):
        seen["warned"] = f"{over} new entries" in caplog.text
        return real_write(path, content, mode=mode)

    with caplog.at_level("DEBUG"), patch.object(updater, "_write_atomic", spy):
        code = _run_real(tmp_path, ["--force-update"])
    out = capsys.readouterr()
    text = caplog.text + out.out + out.err
    assert code == 0
    assert seen.get("warned") is True
    assert text.count(f"{over} new entries") == 1
    assert "person0 surname0" in target.read_text(encoding="utf-8")
