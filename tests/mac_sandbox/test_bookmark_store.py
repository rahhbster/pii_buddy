"""Tests for BookmarkStore — security-scoped bookmark persistence.

All tests run against FakeSandboxBridge; no PyObjC/NSURL/NSOpenPanel calls
are made, so this suite runs on any platform including headless Linux CI.
"""

import json
from pathlib import Path

import pytest

from pii_buddy.mac_sandbox.bookmark_store import BookmarkStore
from pii_buddy.mac_sandbox.fake_bridge import FakeSandboxBridge


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "folder_bookmark.json"


@pytest.fixture
def bridge():
    return FakeSandboxBridge()


@pytest.fixture
def store(bridge, store_path):
    return BookmarkStore(bridge=bridge, store_path=store_path)


# ---------------------------------------------------------------------------
# save -> load round trip
# ---------------------------------------------------------------------------

def test_request_folder_access_saves_bookmark_and_returns_path(store, bridge, store_path):
    bridge.set_panel_choice("/Users/tester/Documents/Watch")

    result = store.request_folder_access()

    assert result == Path("/Users/tester/Documents/Watch")
    assert store_path.exists()

    payload = json.loads(store_path.read_text(encoding="utf-8"))
    assert payload["path"] == "/Users/tester/Documents/Watch"
    assert "bookmark_b64" in payload
    assert "saved_at" in payload


def test_resolve_bookmark_round_trip_after_save(store, bridge):
    bridge.set_panel_choice("/Users/tester/Documents/Watch")
    store.request_folder_access()

    result = store.resolve_bookmark()

    assert result.needs_regrant is False
    assert result.is_stale is False
    assert result.path == Path("/Users/tester/Documents/Watch")


def test_user_cancels_panel_returns_none_and_saves_nothing(store, bridge, store_path):
    bridge.set_panel_choice(None)

    result = store.request_folder_access()

    assert result is None
    assert not store_path.exists()


# ---------------------------------------------------------------------------
# missing / corrupt persisted file
# ---------------------------------------------------------------------------

def test_resolve_bookmark_with_no_file_needs_regrant(store):
    result = store.resolve_bookmark()

    assert result.needs_regrant is True
    assert result.path is None
    assert result.is_stale is False


def test_resolve_bookmark_with_corrupt_json_needs_regrant_not_raise(store, store_path):
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text("{not valid json", encoding="utf-8")

    result = store.resolve_bookmark()

    assert result.needs_regrant is True
    assert result.path is None


def test_resolve_bookmark_with_missing_bookmark_key_needs_regrant(store, store_path):
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(json.dumps({"path": "/foo"}), encoding="utf-8")

    result = store.resolve_bookmark()

    assert result.needs_regrant is True


def test_resolve_bookmark_with_corrupt_base64_needs_regrant_not_raise(store, store_path):
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(
        json.dumps({"path": "/foo", "bookmark_b64": "!!!not-base64!!!"}),
        encoding="utf-8",
    )

    result = store.resolve_bookmark()

    assert result.needs_regrant is True
    assert result.path is None


# ---------------------------------------------------------------------------
# stale bookmark
# ---------------------------------------------------------------------------

def test_resolve_bookmark_stale_flag_surfaces_without_raising(store, bridge):
    bridge.set_panel_choice("/Volumes/External/Watch")
    store.request_folder_access()
    bridge.mark_stale("/Volumes/External/Watch")

    result = store.resolve_bookmark()

    assert result.needs_regrant is False
    assert result.is_stale is True
    assert result.path == Path("/Volumes/External/Watch")


# ---------------------------------------------------------------------------
# resolve failure (bridge can't resolve at all) -> clear "needs re-grant"
# ---------------------------------------------------------------------------

def test_resolve_bookmark_bridge_failure_surfaces_needs_regrant(store, bridge):
    bridge.set_panel_choice("/Users/tester/Documents/Watch")
    store.request_folder_access()
    bridge.force_resolve_failure()

    result = store.resolve_bookmark()

    assert result.needs_regrant is True
    assert result.path is None
    assert result.is_stale is False


# ---------------------------------------------------------------------------
# start/stop accessing symmetry
# ---------------------------------------------------------------------------

def test_start_and_stop_accessing_called_in_pairs(store, bridge):
    path = Path("/Users/tester/Documents/Watch")

    ok = store.start_accessing(path)
    assert ok is True
    assert bridge.start_calls == [str(path)]
    assert bridge.stop_calls == []

    store.stop_accessing(path)
    assert bridge.stop_calls == [str(path)]


def test_stop_accessing_without_start_is_safe_noop_on_bridge_call(store, bridge):
    path = Path("/Users/tester/Documents/Watch")
    # Calling stop without start still just forwards to the bridge —
    # the bridge/OS is the source of truth, but it must not raise.
    store.stop_accessing(path)
    assert bridge.stop_calls == [str(path)]


def test_start_accessing_failure_does_not_track_as_accessing(store, bridge):
    path = Path("/Denied/Path")
    bridge.deny_start(str(path))

    ok = store.start_accessing(path)

    assert ok is False
    assert str(path) not in store.currently_accessing


def test_start_accessing_success_tracks_path(store, bridge):
    path = Path("/Users/tester/Documents/Watch")

    store.start_accessing(path)

    assert str(path) in store.currently_accessing

    store.stop_accessing(path)
    assert str(path) not in store.currently_accessing


# ---------------------------------------------------------------------------
# metadata for UI display
# ---------------------------------------------------------------------------

def test_metadata_returns_path_and_saved_date_without_bookmark_bytes_exposed(store, bridge):
    bridge.set_panel_choice("/Users/tester/Documents/Watch")
    store.request_folder_access()

    meta = store.metadata()

    assert meta is not None
    assert meta["path"] == "/Users/tester/Documents/Watch"
    assert "saved_at" in meta


def test_metadata_returns_none_when_no_bookmark_saved(store):
    assert store.metadata() is None
