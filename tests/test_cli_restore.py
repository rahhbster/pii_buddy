"""--restore end to end through main()."""

import json
from unittest.mock import patch


def test_restore_cli_restores_text(tmp_path):
    base = tmp_path / "base"
    for d in ("input", "output", "mappings", "originals", "logs", "blocklists"):
        (base / d).mkdir(parents=True)

    redacted = tmp_path / "PII_FREE_note.txt"
    redacted.write_text("Hello <<PERSON_1>>, mail <<EMAIL_1>>.", encoding="utf-8")
    mapping = tmp_path / "note.map.json"
    mapping.write_text(
        json.dumps(
            {
                "tags": {"<<PERSON_1>>": "Jane Doe", "<<EMAIL_1>>": "jane@example.test"},
                "metadata": {"original_file": "note.txt"},
            }
        ),
        encoding="utf-8",
    )

    argv = ["main.py", "--dir", str(base), "--restore", str(redacted), str(mapping)]
    with patch("sys.argv", argv):
        from main import main
        main()

    out = tmp_path / "RESTORED_note.txt"
    assert out.read_text(encoding="utf-8") == "Hello Jane Doe, mail jane@example.test."


import stat

import pytest


def _run_restore(tmp_path, redacted, mapping):
    base = tmp_path / "base"
    for d in ("input", "output", "mappings", "originals", "logs", "blocklists"):
        (base / d).mkdir(parents=True, exist_ok=True)
    argv = ["main.py", "--dir", str(base), "--restore", str(redacted), str(mapping)]
    with patch("sys.argv", argv):
        from main import main
        main()


def test_restored_file_is_owner_only(tmp_path):
    redacted = tmp_path / "PII_FREE_note.txt"
    redacted.write_text("Hello <<PERSON_1>>.", encoding="utf-8")
    mapping = tmp_path / "note.map.json"
    mapping.write_text(json.dumps({"tags": {"<<PERSON_1>>": "Jane Doe"}}), encoding="utf-8")
    pre = tmp_path / "RESTORED_note.txt"
    pre.write_text("stale", encoding="utf-8")
    pre.chmod(0o644)
    _run_restore(tmp_path, redacted, mapping)
    assert stat.S_IMODE(pre.stat().st_mode) == 0o600
    assert pre.read_text(encoding="utf-8") == "Hello Jane Doe."


@pytest.mark.parametrize("case", ["no_mapping", "no_redacted", "bad_json"])
def test_restore_errors_exit_1_without_traceback(tmp_path, case, capsys, caplog):
    redacted = tmp_path / "PII_FREE_note.txt"
    mapping = tmp_path / "note.map.json"
    redacted.write_text("Hello <<PERSON_1>>.", encoding="utf-8")
    if case == "no_mapping":
        pass
    elif case == "no_redacted":
        redacted.unlink()
        mapping.write_text("{}", encoding="utf-8")
    else:
        mapping.write_text('{"tags": {"<<PERSON_1>>": "Jane Doe"', encoding="utf-8")
    with caplog.at_level("DEBUG"), pytest.raises(SystemExit) as exc:
        _run_restore(tmp_path, redacted, mapping)
    assert exc.value.code == 1
    out = capsys.readouterr()
    text = out.out + out.err + caplog.text
    assert "Traceback" not in text
    assert "Jane Doe" not in text
    assert "Hello" not in text
    assert text.strip(), "an error message must be shown"
    assert not (tmp_path / "RESTORED_note.txt").exists()
