"""Tests for the MAS-only "Choose Watch Folder…" menu callback logic.

WatchFolderMenuController is deliberately decoupled from rumps.App /
AppKit's event loop so its callback logic can run under plain pytest with
FakeSandboxBridge standing in for NSOpenPanel/NSURL, and a bare
SimpleNamespace standing in for a real rumps.MenuItem (only .title/.state
are touched). No real UI is created anywhere in this file.
"""

from types import SimpleNamespace

import pytest

from pii_buddy.mac_sandbox.bookmark_store import BookmarkStore
from pii_buddy.mac_sandbox.fake_bridge import FakeSandboxBridge
from pii_buddy.menubar import WatchFolderMenuController


@pytest.fixture
def bridge():
    return FakeSandboxBridge()


@pytest.fixture
def store(bridge, tmp_path):
    return BookmarkStore(bridge=bridge, store_path=tmp_path / "folder_bookmark.json")


@pytest.fixture
def menu_item():
    """Stand-in for rumps.MenuItem — only .title/.state are used."""
    return SimpleNamespace(title="Choose Watch Folder…", state=False)


@pytest.fixture
def notifications():
    """Collects messages passed to the controller's notify callback."""
    return []


@pytest.fixture
def controller(store, notifications):
    return WatchFolderMenuController(store=store, notify=notifications.append)


class TestWatchFolderMenuController:
    def test_choosing_a_folder_updates_menu_item_title_and_state(
        self, controller, bridge, menu_item, notifications
    ):
        bridge.set_panel_choice("/Users/tester/Documents/Watch")

        result = controller.on_choose_folder(menu_item)

        assert result is not None
        assert str(result) == "/Users/tester/Documents/Watch"
        assert menu_item.state is True
        assert "Watch" in menu_item.title
        assert any("Watch" in msg for msg in notifications)

    def test_cancelling_the_panel_leaves_menu_state_unchanged(
        self, controller, bridge, menu_item, notifications
    ):
        bridge.set_panel_choice(None)
        original_title = menu_item.title

        result = controller.on_choose_folder(menu_item)

        assert result is None
        assert menu_item.state is False
        assert menu_item.title == original_title
        assert notifications  # some feedback was given, even on cancel

    def test_choosing_a_folder_persists_bookmark_for_later_resolution(
        self, controller, bridge, store, menu_item
    ):
        bridge.set_panel_choice("/Users/tester/Documents/Watch")

        controller.on_choose_folder(menu_item)

        resolved = store.resolve_bookmark()
        assert resolved.needs_regrant is False
        assert str(resolved.path) == "/Users/tester/Documents/Watch"


class TestMasMenuItemGating:
    def test_menu_item_absent_by_default_non_mas_build(self, monkeypatch):
        monkeypatch.delenv("PII_BUDDY_MAS_BUILD", raising=False)
        import importlib
        import pii_buddy.config as cfg
        importlib.reload(cfg)
        assert cfg.PII_BUDDY_MAS_BUILD is False

    def test_mas_build_flag_true_when_env_set(self, monkeypatch):
        monkeypatch.setenv("PII_BUDDY_MAS_BUILD", "1")
        import importlib
        import pii_buddy.config as cfg
        importlib.reload(cfg)
        try:
            assert cfg.PII_BUDDY_MAS_BUILD is True
        finally:
            monkeypatch.delenv("PII_BUDDY_MAS_BUILD", raising=False)
            importlib.reload(cfg)
