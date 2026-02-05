"""Download latest blocklists from GitHub."""

from __future__ import annotations

import base64
import json
import logging
import shutil
import subprocess
import urllib.request
from datetime import datetime
from pathlib import Path

from pii_buddy.config import GITHUB_REPO, GITHUB_BRANCH, GITHUB_BLOCKLIST_PATH

logger = logging.getLogger("pii_buddy")

PACKAGE_BLOCKLISTS_DIR = Path(__file__).parent / "data" / "blocklists"

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
            return base64.b64decode(content_b64).decode("utf-8")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _fetch_via_raw_url() -> str | None:
    """Try fetching via raw.githubusercontent.com (public repos only)."""
    try:
        req = urllib.request.Request(RAW_URL, headers={"User-Agent": "PII-Buddy-Updater"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8")
    except Exception:
        pass
    return None


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

    # Read current content
    current_content = ""
    if target.exists():
        current_content = target.read_text(encoding="utf-8")

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

    # Write new version
    target.write_text(remote_content, encoding="utf-8")

    diff = new_count - old_count
    if diff > 0:
        logger.info(f"  Updated: {old_count} -> {new_count} entries (+{diff} new)")
    elif diff < 0:
        logger.info(f"  Updated: {old_count} -> {new_count} entries ({diff} removed)")
    else:
        logger.info(f"  Updated: {new_count} entries (content changed)")

    return True
