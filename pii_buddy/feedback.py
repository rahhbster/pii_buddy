from __future__ import annotations

"""Feedback collection and storage for PII Buddy.

Stores quality ratings and detection feedback locally as JSON lines.
All feedback is privacy-safe — no raw PII is stored, only hashes,
entity counts, and user-provided comments.
"""

import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from . import config as cfg

logger = logging.getLogger("pii_buddy")


@dataclass
class FeedbackEntry:
    """A single feedback submission."""

    timestamp: str = ""
    file_hash: str = ""          # salted HMAC of the original filename (not contents)
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


_SALT_BYTES = 32


def _install_salt() -> bytes:
    """Per-install random salt, created 0600 on first use and never uploaded.

    Without it, a bare hash of a filename such as `jane_testperson_resume.pdf`
    can be confirmed by anyone who can guess the name.
    """
    cfg.ensure_private_dir(cfg.FEEDBACK_DIR)
    salt_path = cfg.FEEDBACK_DIR / ".salt"
    lock_fd = os.open(cfg.FEEDBACK_DIR, os.O_RDONLY)  # lock the dir: no stray lock file
    try:
        # Serialises creation across threads and processes so every caller
        # returns the salt that actually ends up on disk.
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            existing = salt_path.read_bytes()
        except FileNotFoundError:
            existing = b""
        if len(existing) == _SALT_BYTES:
            return existing

        # Fully written and 0600 before it becomes visible as .salt, so a
        # concurrent reader or a crash never sees a short file.
        tmp = cfg.FEEDBACK_DIR / f".salt.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(_SALT_BYTES))
            os.replace(tmp, salt_path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        return salt_path.read_bytes()
    finally:
        os.close(lock_fd)


def _hash_filename(filename: str) -> str:
    """Hash a filename for privacy-safe storage."""
    digest = hmac.new(_install_salt(), filename.encode(), hashlib.sha256)
    return digest.hexdigest()[:16]


def save_feedback(entry: FeedbackEntry) -> Path:
    """Append a feedback entry to the JSONL log. Returns the log path."""
    cfg.ensure_private_dir(cfg.FEEDBACK_DIR)
    log_path = cfg.FEEDBACK_DIR / "feedback.jsonl"

    line = json.dumps(asdict(entry), ensure_ascii=False)
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
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
    log_path = cfg.FEEDBACK_DIR / "feedback.jsonl"
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
