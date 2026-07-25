"""Security-scoped bookmark persistence for the sandboxed MAS build.

``BookmarkStore`` never touches PyObjC/Foundation directly -- it drives an
injected ``SandboxBridge`` (see ``bridge.py``). This keeps all of the
serialize/deserialize/staleness/re-grant-prompt logic testable with plain
pytest, using ``FakeSandboxBridge`` in place of real NSOpenPanel/NSURL
calls.

Bookmark bytes persist as base64 in a small JSON file (by default
``~/Library/Application Support/PII Buddy/folder_bookmark.json``) alongside
metadata (chosen path, saved date) for UI display. The store path is
injectable so tests point it at ``tmp_path``.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

from .bridge import SandboxBridge

logger = logging.getLogger("pii_buddy")

# Default location for the real (non-test) app.
DEFAULT_STORE_PATH = (
    Path.home() / "Library" / "Application Support" / "PII Buddy" / "folder_bookmark.json"
)


@dataclass(frozen=True)
class ResolveResult:
    """Outcome of attempting to resolve the persisted bookmark.

    ``needs_regrant`` is True whenever there is no usable bookmark at all
    (nothing saved yet, corrupt data, or the bridge failed to resolve it).
    Callers should respond by directing the user to
    "Choose Watch Folder..." rather than raising/crashing.
    """

    path: Optional[Path]
    is_stale: bool
    needs_regrant: bool


class BookmarkStore:
    """Persists and resolves a single security-scoped folder bookmark."""

    def __init__(self, bridge: SandboxBridge, store_path: Path = DEFAULT_STORE_PATH):
        self.bridge = bridge
        self.store_path = Path(store_path)
        self._accessing: Set[str] = set()

    # -- public API -------------------------------------------------

    def request_folder_access(self) -> Optional[Path]:
        """Drive the "choose a folder" flow and persist the bookmark.

        Returns the chosen ``Path``, or ``None`` if the user cancelled or
        bookmark creation failed.
        """
        chosen = self.bridge.open_panel()
        if not chosen:
            return None

        bookmark_data = self.bridge.create_bookmark(chosen)
        if bookmark_data is None:
            logger.warning("Failed to create security-scoped bookmark for %s", chosen)
            return None

        self.save_bookmark(chosen, bookmark_data)
        return Path(chosen)

    def save_bookmark(self, path: str | Path, bookmark_data: bytes) -> None:
        """Persist bookmark bytes + metadata for ``path`` to disk."""
        payload = {
            "path": str(path),
            "bookmark_b64": base64.b64encode(bookmark_data).decode("ascii"),
            "saved_at": datetime.now().isoformat(),
        }
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    def resolve_bookmark(self) -> ResolveResult:
        """Resolve the persisted bookmark, if any.

        Never raises -- any failure (missing file, corrupt JSON, corrupt
        base64, or a bridge resolution failure) surfaces as
        ``needs_regrant=True`` so callers can prompt the user again.
        """
        raw = self._load_raw()
        if raw is None:
            return ResolveResult(path=None, is_stale=False, needs_regrant=True)

        try:
            bookmark_data = base64.b64decode(raw["bookmark_b64"], validate=True)
        except Exception:
            logger.warning("Bookmark file has corrupt/invalid base64 data.")
            return ResolveResult(path=None, is_stale=False, needs_regrant=True)

        try:
            resolved = self.bridge.resolve_bookmark(bookmark_data)
        except Exception:
            logger.warning("Bridge raised while resolving bookmark.", exc_info=True)
            resolved = None

        if resolved is None:
            return ResolveResult(path=None, is_stale=False, needs_regrant=True)

        path_str, is_stale = resolved
        return ResolveResult(path=Path(path_str), is_stale=is_stale, needs_regrant=False)

    def start_accessing(self, path: Path) -> bool:
        """Begin using a security-scoped resource. Returns success."""
        ok = self.bridge.start_accessing(str(path))
        if ok:
            self._accessing.add(str(path))
        return ok

    def stop_accessing(self, path: Path) -> None:
        """Stop using a security-scoped resource."""
        self.bridge.stop_accessing(str(path))
        self._accessing.discard(str(path))

    def metadata(self) -> Optional[dict]:
        """Return ``{"path": ..., "saved_at": ...}`` for UI display, or None."""
        raw = self._load_raw()
        if raw is None:
            return None
        return {"path": raw.get("path"), "saved_at": raw.get("saved_at")}

    @property
    def currently_accessing(self) -> Set[str]:
        """Paths currently under an active start/stop-accessing pair."""
        return set(self._accessing)

    # -- internal -----------------------------------------------------

    def _load_raw(self) -> Optional[dict]:
        if not self.store_path.exists():
            return None
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            logger.warning("Bookmark file at %s is corrupt.", self.store_path)
            return None
        if not isinstance(data, dict) or "bookmark_b64" not in data:
            return None
        return data
