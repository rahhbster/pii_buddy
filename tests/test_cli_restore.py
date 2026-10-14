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
