"""Restore PII from a redacted file using its mapping."""

import json
import re
from pathlib import Path


def restore(redacted_text: str, mapping_path: Path) -> str:
    """
    Reverse the redaction using the mapping file.

    Replaces tags like <<SJ>>, <<EMAIL_1>> back with original values.
    """
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    tags = mapping.get("tags", {})

    restored = redacted_text

    # Replace longest tags first to avoid partial matches
    for tag in sorted(tags, key=len, reverse=True):
        restored = restored.replace(tag, tags[tag])

    return restored
