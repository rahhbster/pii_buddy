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
from dataclasses import dataclass
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
BASELINE_NAME = "person_blocklist.baseline.txt"

# Threat model: the cap bounds blast radius; it is NOT provenance. It does not
# prove the list came from the maintainers, only that one update cannot add
# more than MAX_NEW_ENTRIES names beyond the baseline shipped with the package.
# A hostile remote can still inject up to that many names, and anyone who can
# write the baseline file defeats the cap. Real provenance (signed releases or
# a pinned hash of the list) is an owner decision.
#
# The baseline is only ever read, never written, by this module. If it is
# missing the update is refused rather than re-derived from untrusted content.

RAW_URL = (
    f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{GITHUB_BLOCKLIST_PATH}"
)

API_URL = (
    f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_BLOCKLIST_PATH}"
    f"?ref={GITHUB_BRANCH}"
)


@dataclass(frozen=True)
class UpdateResult:
    """Outcome of update_blocklists(). Truthy only when the file was replaced,
    so `if update_blocklists():` keeps its old meaning."""
    status: str  # "updated" | "unchanged" | "refused" | "failed"
    reason: str = ""

    @property
    def message(self) -> str:
        return self.reason

    def __bool__(self) -> bool:
        return self.status == "updated"


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
    text = text.lstrip("\ufeff")
    for line in text.splitlines()[:MAX_LINES]:
        line = line.replace("\xa0", " ").replace("\t", " ").strip()
        if not line or len(line) > MAX_LINE_LENGTH or not line.isprintable() or "\ufffd" in line:
            continue
        kept.append(line)
    return kept


def _entries(lines) -> set[str]:
    return {l.lower() for l in lines if not l.startswith("#")}


def _write_atomic(target: Path, content: str, mode: int = 0o644) -> None:
    """mkstemp creates 0600; set the mode explicitly so replacing a shared
    package file does not make it owner-only. Pass 0o600 for private lists."""
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".blocklist_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _baseline_entries() -> set[str] | None:
    """Entries of the packaged baseline, or None when it is missing or
    unreadable. Never creates the file: it must not be derived from the
    current or remote list."""
    baseline = PACKAGE_BLOCKLISTS_DIR / BASELINE_NAME
    try:
        text = baseline.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _entries(_sanitize(text))


def update_blocklists(force: bool = False) -> UpdateResult:
    """
    Fetch the latest person_blocklist.txt from GitHub and replace the local copy.
    Uses gh CLI for private repos, falls back to raw URL for public repos.
    Truthy result means the blocklist was updated. Statuses: "updated",
    "unchanged", "refused" (cap exceeded or baseline missing), "failed"
    (download or content problem). force=True skips ONLY the cap; size, UTF-8
    and line sanitation and the baseline-missing refusal always apply.
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
            msg = "Failed to download blocklist. Check your internet connection."
            logger.error(msg)
            logger.error("  If the repo is private, make sure `gh auth login` is set up.")
            return UpdateResult("failed", msg)

    remote_lines = _sanitize(remote_content)
    if not _entries(remote_lines):
        msg = "Downloaded blocklist has no valid entries; keeping the current one."
        logger.error(msg)
        return UpdateResult("failed", msg)
    remote_content = "\n".join(remote_lines) + "\n"

    baseline = _baseline_entries()
    if baseline is None:
        msg = (
            "baseline missing; reinstall or restore "
            f"pii_buddy/data/blocklists/{BASELINE_NAME}"
        )
        logger.error("refused: " + msg)
        return UpdateResult("refused", msg)

    added = _entries(remote_lines) - baseline
    if len(added) > MAX_NEW_ENTRIES:
        msg = (
            f"refused: {len(added)} new entries exceeds cap of {MAX_NEW_ENTRIES} "
            "over the packaged baseline; review the list upstream "
            "(force=True overrides)."
        )
        if not force:
            logger.error(msg)
            return UpdateResult("refused", msg)
        logger.warning(msg.replace("refused:", "forced past cap:", 1))

    current_content = ""
    if target.exists():
        current_content = target.read_text(encoding="utf-8", errors="replace")

    if current_content.strip() == remote_content.strip():
        logger.info("Blocklist is already up to date.")
        return UpdateResult("unchanged", "Blocklist is already up to date.")

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

    _write_atomic(target, remote_content, mode=0o644)

    diff = new_count - old_count
    if diff > 0:
        logger.info(f"  Updated: {old_count} -> {new_count} entries (+{diff} new)")
    elif diff < 0:
        logger.info(f"  Updated: {old_count} -> {new_count} entries ({diff} removed)")
    else:
        logger.info(f"  Updated: {new_count} entries (content changed)")

    return UpdateResult("updated", f"{old_count} -> {new_count} entries")
