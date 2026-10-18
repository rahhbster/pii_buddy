"""Restore PII from a redacted file using its mapping."""

import json
from pathlib import Path

from . import core


def restore(redacted_text: str, mapping_path: Path) -> str:
    """
    Reverse the redaction using the mapping file.

    Replaces tags like <<SJ>>, <<EMAIL_1>> back with original values.

    Raises core.CoreError (a ValueError) for a mapping file that is not valid
    JSON or not a JSON object; OSError for a file that cannot be read.
    """
    parsed = False
    mapping = None
    try:
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        parsed = True
    except (ValueError, RecursionError):
        pass
    # Raised outside the except block so the parser error, which quotes the
    # file, is not left behind as __context__.
    if not parsed:
        raise core.CoreError("invalid_json", "mapping file is not valid JSON")
    if type(mapping) is not dict:
        raise core.CoreError("invalid_mapping", "mapping must be an object")
    tags = mapping.get("tags", {})

    if not tags:
        return redacted_text

    return core._restore_unchecked(redacted_text, tags)
