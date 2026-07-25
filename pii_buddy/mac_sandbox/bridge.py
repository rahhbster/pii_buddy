"""SandboxBridge protocol — isolates all NSURL/NSOpenPanel calls.

``BookmarkStore`` (see ``bookmark_store.py``) never imports PyObjC itself.
It only talks to an object satisfying this protocol, which lets the
persistence/staleness/re-grant logic run under plain pytest anywhere,
including headless Linux CI, by injecting ``FakeSandboxBridge`` instead.

``PyObjCSandboxBridge`` is the real, macOS-only implementation. It imports
Foundation/AppKit lazily inside each method (not at module import time) so
that importing this module never requires PyObjC to be installed — only
actually *calling* a method on ``PyObjCSandboxBridge`` does.
"""

from __future__ import annotations

from typing import Optional, Protocol, Tuple


class SandboxBridge(Protocol):
    """Minimal surface needed to drive macOS security-scoped bookmarks."""

    def open_panel(self) -> Optional[str]:
        """Show an NSOpenPanel restricted to directories.

        Returns the chosen absolute path, or ``None`` if the user
        cancelled.
        """
        ...

    def create_bookmark(self, path: str) -> Optional[bytes]:
        """Create security-scoped bookmark data for ``path``.

        Returns the bookmark bytes, or ``None`` on failure.
        """
        ...

    def resolve_bookmark(self, data: bytes) -> Optional[Tuple[str, bool]]:
        """Resolve previously-created bookmark ``data``.

        Returns ``(path, is_stale)`` on success, or ``None`` if the
        bookmark could not be resolved at all (e.g. the folder was
        deleted, permissions were revoked, or the data is invalid).
        """
        ...

    def start_accessing(self, path: str) -> bool:
        """Call ``startAccessingSecurityScopedResource`` for ``path``.

        Returns whether access was granted.
        """
        ...

    def stop_accessing(self, path: str) -> None:
        """Call ``stopAccessingSecurityScopedResource`` for ``path``."""
        ...


class PyObjCSandboxBridge:
    """Real bridge backed by Foundation/AppKit. macOS + PyObjC only.

    All Foundation/AppKit imports happen inside the methods below (lazy),
    never at module import time, so this module can be imported freely
    on any platform/CI without PyObjC installed.
    """

    def open_panel(self) -> Optional[str]:
        from AppKit import NSOpenPanel

        panel = NSOpenPanel.openPanel()
        panel.setCanChooseDirectories_(True)
        panel.setCanChooseFiles_(False)
        panel.setAllowsMultipleSelection_(False)
        panel.setPrompt_("Choose Watch Folder")

        response = panel.runModal()
        # NSModalResponseOK == 1
        if response != 1:
            return None
        urls = panel.URLs()
        if not urls or len(urls) == 0:
            return None
        return str(urls[0].path())

    def create_bookmark(self, path: str) -> Optional[bytes]:
        from Foundation import NSURL, NSURLBookmarkCreationWithSecurityScope

        url = NSURL.fileURLWithPath_(path)
        data, error = url.bookmarkDataWithOptions_includingResourceValuesForKeys_relativeToURL_error_(
            NSURLBookmarkCreationWithSecurityScope,
            None,
            None,
            None,
        )
        if error is not None or data is None:
            return None
        return bytes(data)

    def resolve_bookmark(self, data: bytes) -> Optional[Tuple[str, bool]]:
        from Foundation import (
            NSData,
            NSURL,
            NSURLBookmarkResolutionWithSecurityScope,
        )

        ns_data = NSData.dataWithBytes_length_(data, len(data))
        result = NSURL.URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
            ns_data,
            NSURLBookmarkResolutionWithSecurityScope,
            None,
            None,
            None,
        )
        # PyObjC returns a tuple (url, is_stale, error)
        url, is_stale, error = result
        if error is not None or url is None:
            return None
        return str(url.path()), bool(is_stale)

    def start_accessing(self, path: str) -> bool:
        from Foundation import NSURL

        url = NSURL.fileURLWithPath_(path)
        return bool(url.startAccessingSecurityScopedResource())

    def stop_accessing(self, path: str) -> None:
        from Foundation import NSURL

        url = NSURL.fileURLWithPath_(path)
        url.stopAccessingSecurityScopedResource()
