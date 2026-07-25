"""In-memory SandboxBridge test double.

Kept in the main package (not under tests/) so it's importable by the
menu bar module for an optional "MAS dry-run" dev mode -- exercising the
"Choose Watch Folder..." flow on a non-sandboxed dev machine without any
real NSOpenPanel/security-scoped bookmark calls.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple


class FakeSandboxBridge:
    """Fake implementation of :class:`pii_buddy.mac_sandbox.bridge.SandboxBridge`.

    "Bookmark bytes" are just an opaque token encoding the chosen path,
    so tests can assert round-trip behavior without any real PyObjC/NSURL
    involvement.
    """

    def __init__(self) -> None:
        self._panel_choice: Optional[str] = None
        self._stale_paths: Set[str] = set()
        self._denied_start_paths: Set[str] = set()
        self._resolve_fails: bool = False

        self.start_calls: List[str] = []
        self.stop_calls: List[str] = []
        self.create_bookmark_calls: List[str] = []
        self.resolve_calls: int = 0

    # -- test configuration helpers -----------------------------------

    def set_panel_choice(self, path: Optional[str]) -> None:
        """Configure what the next ``open_panel()`` call returns."""
        self._panel_choice = path

    def mark_stale(self, path: str) -> None:
        """Make subsequent ``resolve_bookmark`` calls for ``path`` report stale."""
        self._stale_paths.add(path)

    def deny_start(self, path: str) -> None:
        """Make ``start_accessing(path)`` return False."""
        self._denied_start_paths.add(path)

    def force_resolve_failure(self) -> None:
        """Make the next ``resolve_bookmark`` call return None (unresolvable)."""
        self._resolve_fails = True

    # -- SandboxBridge protocol -----------------------------------------

    def open_panel(self) -> Optional[str]:
        return self._panel_choice

    def create_bookmark(self, path: str) -> Optional[bytes]:
        self.create_bookmark_calls.append(path)
        return f"FAKE-BOOKMARK:{path}".encode("utf-8")

    def resolve_bookmark(self, data: bytes) -> Optional[Tuple[str, bool]]:
        self.resolve_calls += 1
        if self._resolve_fails:
            self._resolve_fails = False
            return None
        try:
            decoded = data.decode("utf-8")
        except Exception:
            return None
        prefix = "FAKE-BOOKMARK:"
        if not decoded.startswith(prefix):
            return None
        path = decoded[len(prefix):]
        return path, path in self._stale_paths

    def start_accessing(self, path: str) -> bool:
        self.start_calls.append(path)
        return path not in self._denied_start_paths

    def stop_accessing(self, path: str) -> None:
        self.stop_calls.append(path)
