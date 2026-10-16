"""Restore PII from a redacted file using its mapping."""

import json
from pathlib import Path

from . import core


def restore(redacted_text: str, mapping_path: Path) -> str:
    """
    Reverse the redaction using the mapping file.

    Replaces tags like <<SJ>>, <<EMAIL_1>> back with original values.
    """
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    tags = mapping.get("tags", {})

    if not tags:
        return redacted_text

    return core.restore_text(redacted_text, tags, trusted=True)
