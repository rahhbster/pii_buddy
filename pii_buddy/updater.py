"""Download latest blocklists from GitHub."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import shutil
import subprocess
import tempfile
import urllib.request
from datetime import datetime
from pathlib import Path

from pii_buddy.config import GITHUB_REPO, GITHUB_BRANCH, GITHUB_BLOCKLIST_PATH

logger = logging.getLogger("pii_buddy")

PACKAGE_BLOCKLISTS_DIR = Path(__file__).parent / "data" / "blocklists"

MAX_DOWNLOAD_BYTES = 256 * 1024
MAX_LINES = 5000
MAX_LINE_LENGTH = 100
# A remote list that un-redacts people is the threat: cap how many entries one
# update may introduce so a poisoned list cannot suppress a whole roster.
MAX_NEW_ENTRIES = 25

RAW_URL = (
    f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{GITHUB_BLOCKLIST_PATH}"
)

API_URL = (
    f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_BLOCKLIST_PATH}"
    f"?ref={GITHUB_BRANCH}"
)


def _fetch_via_gh_cli() -> str | None:
    """Try fetching via gh CLI (handles private repo auth)."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{GITHUB_REPO}/contents/{GITHUB_BLOCKLIST_PATH}",
             "-q", ".content"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            content_b64 = result.stdout.strip().replace("\n", "")
            if len(content_b64) > MAX_DOWNLOAD_BYTES * 4 // 3 + 8:
                logger.error("Blocklist from GitHub CLI exceeds the size limit.")
                return None
            return base64.b64decode(content_b64, validate=True).decode("utf-8", errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    except (binascii.Error, ValueError):
        logger.error("GitHub CLI returned a blocklist that is not valid base64.")
    return None


def _fetch_via_raw_url() -> str | None:
    """Try fetching via raw.githubusercontent.com (public repos only)."""
    try:
        req = urllib.request.Request(RAW_URL, headers={"User-Agent": "PII-Buddy-Updater"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
        if len(data) > MAX_DOWNLOAD_BYTES:
            logger.error("Downloaded blocklist exceeds the size limit.")
            return None
        return data.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _sanitize(text: str) -> list[str]:
    """Keep comments and plain printable entries; drop anything else."""
    kept = []
    for line in text.splitlines()[:MAX_LINES]:
        line = line.strip()
        if not line or len(line) > MAX_LINE_LENGTH or not line.isprintable() or "\ufffd" in line:
            continue
        kept.append(line)
    return kept


def _entries(lines) -> set[str]:
    return {l.lower() for l in lines if not l.startswith("#")}


def _write_atomic(target: Path, content: str) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".blocklist_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def update_blocklists() -> bool:
    """
    Fetch the latest person_blocklist.txt from GitHub and replace the local copy.
    Uses gh CLI for private repos, falls back to raw URL for public repos.
    Returns True if the blocklist was updated, False if already up to date.
    """
    target = PACKAGE_BLOCKLISTS_DIR / "person_blocklist.txt"

    logger.info("Fetching latest blocklist from GitHub...")

    # Try gh CLI first (works with private repos), then raw URL
    remote_content = _fetch_via_gh_cli()
    if remote_content:
        logger.info("  Downloaded via GitHub CLI.")
    else:
        remote_content = _fetch_via_raw_url()
        if remote_content:
            logger.info("  Downloaded via raw URL.")
        else:
            logger.error("Failed to download blocklist. Check your internet connection.")
            logger.error("  If the repo is private, make sure `gh auth login` is set up.")
            return False

    remote_lines = _sanitize(remote_content)
    if not _entries(remote_lines):
        logger.error("Downloaded blocklist has no valid entries; keeping the current one.")
        return False
    remote_content = "\n".join(remote_lines) + "\n"

    # Read current content
    current_content = ""
    if target.exists():
        current_content = target.read_text(encoding="utf-8", errors="replace")
        added = _entries(remote_lines) - _entries(_sanitize(current_content))
        if len(added) > MAX_NEW_ENTRIES:
            logger.error(
                f"Update would add {len(added)} entries (limit {MAX_NEW_ENTRIES}); "
                "refusing and keeping the current blocklist."
            )
            return False

    if current_content.strip() == remote_content.strip():
        logger.info("Blocklist is already up to date.")
        return False

    # Count entries in each
    def count_entries(text):
        return sum(1 for line in text.splitlines()
                   if line.strip() and not line.strip().startswith("#"))

    old_count = count_entries(current_content)
    new_count = count_entries(remote_content)

    # Back up old version
    if target.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = target.with_suffix(f".backup_{timestamp}.txt")
        shutil.copy2(str(target), str(backup))
        logger.info(f"  Backed up previous version: {backup.name}")

    _write_atomic(target, remote_content)

    diff = new_count - old_count
    if diff > 0:
        logger.info(f"  Updated: {old_count} -> {new_count} entries (+{diff} new)")
    elif diff < 0:
        logger.info(f"  Updated: {old_count} -> {new_count} entries ({diff} removed)")
    else:
        logger.info(f"  Updated: {new_count} entries (content changed)")

    return True
