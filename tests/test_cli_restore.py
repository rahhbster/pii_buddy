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


def _plant(tmp_path, mapping_payload=None):
    redacted = tmp_path / "PII_FREE_note.txt"
    redacted.write_text("Hello <<PERSON_1>>.", encoding="utf-8")
    mapping = tmp_path / "note.map.json"
    if mapping_payload is None:
        mapping_payload = json.dumps({"tags": {"<<PERSON_1>>": "Jane Doe"}})
    mapping.write_text(mapping_payload, encoding="utf-8")
    return redacted, mapping


def test_restored_file_is_owner_only(tmp_path):
    redacted, mapping = _plant(tmp_path)
    _run_restore(tmp_path, redacted, mapping)
    out = tmp_path / "RESTORED_note.txt"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert out.read_text(encoding="utf-8") == "Hello Jane Doe."


def test_existing_output_is_not_overwritten(tmp_path):
    redacted, mapping = _plant(tmp_path)
    pre = tmp_path / "RESTORED_note.txt"
    pre.write_text("stale", encoding="utf-8")
    _run_restore(tmp_path, redacted, mapping)
    assert pre.read_text(encoding="utf-8") == "stale"
    new = [p for p in tmp_path.glob("RESTORED_note*.txt") if p != pre]
    assert len(new) == 1
    assert new[0].read_text(encoding="utf-8") == "Hello Jane Doe."
    assert stat.S_IMODE(new[0].stat().st_mode) == 0o600


def test_symlink_target_is_not_overwritten(tmp_path):
    redacted, mapping = _plant(tmp_path)
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    link = tmp_path / "RESTORED_note.txt"
    link.symlink_to(victim)
    _run_restore(tmp_path, redacted, mapping)
    assert victim.read_text(encoding="utf-8") == "precious"
    assert link.is_symlink()
    new = [p for p in tmp_path.glob("RESTORED_note*.txt") if p != link]
    assert len(new) == 1 and not new[0].is_symlink()
    assert new[0].read_text(encoding="utf-8") == "Hello Jane Doe."


def test_dangling_symlink_is_not_followed(tmp_path):
    redacted, mapping = _plant(tmp_path)
    target = tmp_path / "nowhere.txt"
    (tmp_path / "RESTORED_note.txt").symlink_to(target)
    _run_restore(tmp_path, redacted, mapping)
    assert not target.exists()


@pytest.mark.parametrize(
    "payload",
    ['{"persons": 5}', '{"tags": []}', '{"tags": "x"}', '{"tags": {"<<A>>": 5}}',
     '{"tags": {"<<A>>": null}}', "{}", "[]", '{"metadata": {}}'],
)
def test_invalid_mapping_shape_exits_1(tmp_path, payload, capsys, caplog):
    redacted, mapping = _plant(tmp_path, payload)
    with caplog.at_level("DEBUG"), pytest.raises(SystemExit) as exc:
        _run_restore(tmp_path, redacted, mapping)
    assert exc.value.code == 1
    out = capsys.readouterr()
    text = out.out + out.err + caplog.text
    assert "Restored" not in text
    assert "Traceback" not in text
    assert not list(tmp_path.glob("RESTORED_*"))


def test_empty_tags_dict_is_valid(tmp_path):
    redacted, mapping = _plant(tmp_path, '{"tags": {}}')
    _run_restore(tmp_path, redacted, mapping)
    assert (tmp_path / "RESTORED_note.txt").read_text(encoding="utf-8") == "Hello <<PERSON_1>>."


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
