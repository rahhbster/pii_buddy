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

    if not tags:
        return redacted_text

    # One pass, longest tag first: restored values are never re-scanned.
    pattern = re.compile(
        "|".join(re.escape(t) for t in sorted(tags, key=len, reverse=True))
    )
    return pattern.sub(lambda m: tags[m.group()], redacted_text)
