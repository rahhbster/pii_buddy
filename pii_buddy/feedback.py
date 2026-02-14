from __future__ import annotations

"""Feedback collection and storage for PII Buddy.

Stores quality ratings and detection feedback locally as JSON lines.
All feedback is privacy-safe — no raw PII is stored, only hashes,
entity counts, and user-provided comments.
"""

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .config import FEEDBACK_DIR

logger = logging.getLogger("pii_buddy")


@dataclass
class FeedbackEntry:
    """A single feedback submission."""

    timestamp: str = ""
    file_hash: str = ""          # SHA-256 of the original filename (not contents)
    source: str = ""             # "cli", "menubar", "watch", "paste", "clipboard"
    doc_type: str = ""           # "resume", "transcript", "general"
    entities_found: int = 0
    audit_additions: int = 0
    rating: int = 0              # 1-5, 0 = not rated
    comment: str = ""            # User's feedback comment
    accepted: bool = False       # True if user implicitly accepted (e.g., clicked away)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


def _hash_filename(filename: str) -> str:
    """Hash a filename for privacy-safe storage."""
    return hashlib.sha256(filename.encode()).hexdigest()[:16]


def save_feedback(entry: FeedbackEntry) -> Path:
    """Append a feedback entry to the JSONL log. Returns the log path."""
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    log_path = FEEDBACK_DIR / "feedback.jsonl"

    line = json.dumps(asdict(entry), ensure_ascii=False)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    logger.info(f"Feedback saved to {log_path.name}")
    return log_path


def record_rating(
    rating: int,
    comment: str = "",
    source: str = "cli",
    filename: str = "",
    entities_found: int = 0,
    audit_additions: int = 0,
    doc_type: str = "",
) -> Path:
    """Convenience function to record a quality rating."""
    entry = FeedbackEntry(
        file_hash=_hash_filename(filename) if filename else "",
        source=source,
        doc_type=doc_type,
        entities_found=entities_found,
        audit_additions=audit_additions,
        rating=rating,
        comment=comment,
    )
    return save_feedback(entry)


def record_acceptance(
    source: str = "menubar",
    filename: str = "",
    entities_found: int = 0,
    audit_additions: int = 0,
) -> Path:
    """Record an implicit acceptance (user used the output without complaint)."""
    entry = FeedbackEntry(
        file_hash=_hash_filename(filename) if filename else "",
        source=source,
        entities_found=entities_found,
        audit_additions=audit_additions,
        accepted=True,
    )
    return save_feedback(entry)


def load_feedback(limit: int = 100) -> list[dict]:
    """Load recent feedback entries. Returns newest first."""
    log_path = FEEDBACK_DIR / "feedback.jsonl"
    if not log_path.exists():
        return []

    entries = []
    for line in log_path.read_text(encoding="utf-8").strip().splitlines():
        if line.strip():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return entries[-limit:][::-1]


def feedback_summary() -> dict:
    """Return aggregate feedback stats."""
    entries = load_feedback(limit=10000)
    if not entries:
        return {"total": 0, "avg_rating": 0, "rated": 0, "accepted": 0}

    rated = [e for e in entries if e.get("rating", 0) > 0]
    accepted = [e for e in entries if e.get("accepted")]

    return {
        "total": len(entries),
        "rated": len(rated),
        "avg_rating": round(sum(e["rating"] for e in rated) / len(rated), 1) if rated else 0,
        "accepted": len(accepted),
    }
