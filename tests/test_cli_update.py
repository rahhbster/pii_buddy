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


def test_refused_prints_reason(tmp_path, capsys):
    got, _, reload_ = _run(tmp_path, ["--update"], UpdateResult("refused", "too many new entries"))
    assert got == 1
    assert "too many new entries" in capsys.readouterr().err
    reload_.assert_not_called()
