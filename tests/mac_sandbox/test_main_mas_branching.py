"""Tests for main.py's MAS-build watch-root resolution branching.

_mas_resolve_watch_root() decides what Path (if any) to hand to
watcher.watch() when running as the sandboxed MAS build. It takes a
BookmarkStore via dependency injection so these tests never touch
PyObjC/NSURL/rumps — a MagicMock stands in for BookmarkStore, and an
injected alert_fn stands in for the real rumps alert.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from main import _mas_resolve_watch_root
from pii_buddy.mac_sandbox.bookmark_store import ResolveResult


class TestMasResolveWatchRoot:
    def test_successful_resolution_starts_accessing_and_returns_path(self):
        store = MagicMock()
        store.resolve_bookmark.return_value = ResolveResult(
            path=Path("/Users/tester/Documents/Watch"),
            is_stale=False,
            needs_regrant=False,
        )
        store.start_accessing.return_value = True
        alert_fn = MagicMock()

        result = _mas_resolve_watch_root(store=store, alert_fn=alert_fn)

        assert result == Path("/Users/tester/Documents/Watch")
        store.start_accessing.assert_called_once_with(Path("/Users/tester/Documents/Watch"))
        alert_fn.assert_not_called()

    def test_needs_regrant_shows_alert_and_returns_none(self):
        store = MagicMock()
        store.resolve_bookmark.return_value = ResolveResult(
            path=None, is_stale=False, needs_regrant=True
        )
        alert_fn = MagicMock()

        result = _mas_resolve_watch_root(store=store, alert_fn=alert_fn)

        assert result is None
        alert_fn.assert_called_once()
        store.start_accessing.assert_not_called()

    def test_stale_bookmark_still_proceeds_but_logs(self, caplog):
        store = MagicMock()
        store.resolve_bookmark.return_value = ResolveResult(
            path=Path("/Volumes/External/Watch"),
            is_stale=True,
            needs_regrant=False,
        )
        store.start_accessing.return_value = True
        alert_fn = MagicMock()

        result = _mas_resolve_watch_root(store=store, alert_fn=alert_fn)

        assert result == Path("/Volumes/External/Watch")
        alert_fn.assert_not_called()

    def test_start_accessing_failure_shows_alert_and_returns_none(self):
        store = MagicMock()
        store.resolve_bookmark.return_value = ResolveResult(
            path=Path("/Users/tester/Documents/Watch"),
            is_stale=False,
            needs_regrant=False,
        )
        store.start_accessing.return_value = False
        alert_fn = MagicMock()

        result = _mas_resolve_watch_root(store=store, alert_fn=alert_fn)

        assert result is None
        alert_fn.assert_called_once()
