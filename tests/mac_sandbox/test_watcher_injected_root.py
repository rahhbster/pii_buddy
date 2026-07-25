"""Tests confirming watcher.watch() accepts an injected root path.

This is the "small injection point" the sandboxed MAS build needs: on
launch it resolves a security-scoped bookmark to a Path and hands that
pre-resolved Path to watch() instead of always deriving it from config.

watch() already accepts ``input_dir`` as a parameter defaulting to
``INPUT_DIR`` (see pii_buddy/watcher.py) -- these tests pin down that the
non-MAS default behavior is unchanged, and that a different injected path
is actually what gets scheduled on the watchdog Observer.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def stop_watch_after_first_sleep():
    """Make watch()'s blocking loop return immediately via KeyboardInterrupt."""
    def _raise(*args, **kwargs):
        raise KeyboardInterrupt()
    return _raise


class TestWatcherInjectedRoot:
    def test_watch_defaults_to_config_input_dir(self, stop_watch_after_first_sleep):
        """Non-MAS behavior: no root passed -> uses INPUT_DIR from config, unchanged."""
        from pii_buddy import watcher
        from pii_buddy.config import INPUT_DIR

        with patch.object(watcher, "Observer") as mock_observer_cls, \
             patch.object(watcher.time, "sleep", side_effect=stop_watch_after_first_sleep):
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            watcher.watch()

            mock_observer.schedule.assert_called_once()
            _, args, kwargs = mock_observer.schedule.mock_calls[0]
            scheduled_path = args[1] if len(args) > 1 else kwargs.get("path")
            assert scheduled_path == str(INPUT_DIR)

    def test_watch_uses_injected_root_instead_of_input_dir(self, tmp_path, stop_watch_after_first_sleep):
        """MAS behavior: an explicit (pre-resolved) Path overrides INPUT_DIR."""
        from pii_buddy import watcher

        injected_root = tmp_path / "mas_resolved_watch_folder"
        injected_root.mkdir()

        with patch.object(watcher, "Observer") as mock_observer_cls, \
             patch.object(watcher.time, "sleep", side_effect=stop_watch_after_first_sleep):
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            watcher.watch(injected_root)

            mock_observer.schedule.assert_called_once()
            _, args, kwargs = mock_observer.schedule.mock_calls[0]
            scheduled_path = args[1] if len(args) > 1 else kwargs.get("path")
            assert scheduled_path == str(injected_root)

    def test_watch_starts_and_joins_observer(self, tmp_path, stop_watch_after_first_sleep):
        from pii_buddy import watcher

        with patch.object(watcher, "Observer") as mock_observer_cls, \
             patch.object(watcher.time, "sleep", side_effect=stop_watch_after_first_sleep):
            mock_observer = MagicMock()
            mock_observer_cls.return_value = mock_observer

            watcher.watch(tmp_path)

            mock_observer.start.assert_called_once()
            mock_observer.stop.assert_called_once()
            mock_observer.join.assert_called_once()
