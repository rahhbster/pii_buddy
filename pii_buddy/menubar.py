"""Optional Mac menu bar app for PII Buddy.

Sits in the macOS menu bar and provides one-click PII removal from
the clipboard.  Not required for normal PII Buddy operation.

Requires:  pip install rumps

Usage:
    python main.py --menubar
    python -m pii_buddy.menubar
"""

import errno
import fcntl
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import plistlib
import tempfile
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("pii_buddy")

# --- MAS sandbox: "Choose Watch Folder…" (additive, opt-in) ---
#
# Only wired into the menu when PII_BUDDY_MAS_BUILD is set (see
# setup_py2app.py's MAS variant / extras/entitlements_mas.plist). The
# existing direct-download build never references this.
from .config import BASE_DIR, LOGS_DIR, PII_BUDDY_MAS_BUILD  # noqa: E402
from .mac_sandbox.bookmark_store import BookmarkStore  # noqa: E402


class WatchFolderMenuController:
    """Owns the "Choose Watch Folder…" menu item's callback logic.

    Deliberately decoupled from rumps/AppKit: it only touches a
    ``BookmarkStore`` (itself decoupled from PyObjC via the injected
    ``SandboxBridge``) and whatever menu-item-like object it's given
    (only ``.title``/``.state`` are used). This lets the callback logic
    be unit tested with ``FakeSandboxBridge`` and a plain stand-in
    object instead of a real rumps.App event loop.
    """

    def __init__(self, store: BookmarkStore, notify=None):
        self.store = store
        self._notify = notify or (lambda message: None)

    def on_choose_folder(self, menu_item):
        """Drive the folder picker; update ``menu_item`` on success.

        Returns the chosen Path, or None if the user cancelled (in which
        case the menu item is left unchanged).
        """
        path = self.store.request_folder_access()
        if path is None:
            self._notify("No folder selected — watch folder unchanged.")
            return None

        menu_item.title = f"Watch Folder: {path.name}"
        menu_item.state = True
        self._notify(f"Now watching: {path}")
        return path


# --- Single-instance guard ---

_LOCK_FILE_PATH = BASE_DIR / "menubar.lock"
# Fixed per-user path (the container's home in the MAS build) so instances
# started with different PII_BUDDY_DIR values still exclude each other.
_USER_LOCK_FILE_PATH = (
    Path(os.path.expanduser("~/Library/Application Support/PII Buddy"))
    / "menubar.lock"
)
_lock_file = None  # keep reference alive to hold the lock
_extra_lock_files = []
_BUNDLE_POLLS = 5
_BUNDLE_POLL_INTERVAL = 0.2

_LOG_PATH = LOGS_DIR / "menubar.log"


def _ensure_private_log() -> Path:
    """Create the menubar log owner-readable only and return its path."""
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(_LOG_PATH, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.close(fd)
    os.chmod(_LOG_PATH, 0o600)
    return _LOG_PATH


class _PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating handler whose files, including rotated ones, stay 0600."""

    def _open(self):
        stream = super()._open()
        os.chmod(self.baseFilename, 0o600)
        return stream


def _make_log_handler(max_bytes=1_000_000, backup_count=3):
    handler = _PrivateRotatingFileHandler(
        _ensure_private_log(),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
    return handler


def _write_private_text(path: Path, text: str):
    """Write ``text`` to ``path`` owner-readable only (mappings hold PII)."""
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            f.write(text)
    finally:
        if fd != -1:
            os.close(fd)


def _claim_mapping_path(directory: Path, now: datetime) -> Path:
    """Reserve a unique, owner-only mapping file name (O_EXCL, no overwrite)."""
    stem = f"clipboard_{now.strftime('%Y%m%d_%H%M%S')}"
    counter = 0
    while True:
        suffix = f"_{counter}" if counter else ""
        path = directory / f"{stem}{suffix}.map.json"
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            counter += 1
            continue
        os.close(fd)
        return path


def _log_failure(message: str, exc: BaseException):
    """Log the exception type and frames only; messages can carry user text."""
    frames = "".join(traceback.format_tb(exc.__traceback__))
    logger.error(f"{message}: {type(exc).__name__}\n{frames}")


def _try_lock(path: Path, created: list):
    """Take an exclusive flock on ``path``.

    Returns ``(state, file)``: "acquired" with the open file, "held" when
    another process owns it, "unavailable" when it can't be used.  Every
    directory this call creates is appended to ``created`` so a losing
    instance can remove it if still empty.  The lock file itself is never
    unlinked: a racing opener may hold a flock on that inode.
    """
    try:
        # Only directories whose mkdir succeeds here are ours to remove; one
        # a racing winner made first must survive our cleanup.
        for d in reversed([path.parent, *path.parent.parents]):
            if d.exists():
                continue
            try:
                os.mkdir(d, 0o700)
            except FileExistsError:
                continue
            created.append(d)
        # O_APPEND so a losing instance doesn't truncate the holder's PID.
        flags = os.O_WRONLY | os.O_APPEND
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            fd = os.open(path, flags, 0o600)
        lock_file = os.fdopen(fd, "a")
    except OSError as e:
        logger.error(f"Single-instance lock unavailable: {type(e).__name__}")
        print(
            f"PII Buddy could not create its lock file ({type(e).__name__}); "
            "continuing without the file-lock guard.",
            file=sys.stderr,
        )
        return "unavailable", None
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        lock_file.close()
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            return "held", None
        logger.error(f"Single-instance lock failed: {type(e).__name__}")
        print(
            f"PII Buddy could not take its lock ({type(e).__name__}); "
            "continuing without the file-lock guard.",
            file=sys.stderr,
        )
        return "unavailable", None
    lock_file.truncate(0)
    lock_file.write(str(os.getpid()))
    lock_file.flush()
    return "acquired", lock_file


def _remove_created(created: list):
    """Remove directories a losing instance made, if empty (deepest first)."""
    for p in sorted(created, key=lambda p: len(p.parts), reverse=True):
        try:
            p.rmdir()
        except OSError:
            pass


def _other_bundle_instances() -> int:
    """Count other running copies of this bundle; 0 when AppKit is absent."""
    try:
        from AppKit import NSRunningApplication
    except ImportError:
        return 0
    running = list(
        NSRunningApplication.runningApplicationsWithBundleIdentifier_(
            "dev.piibuddy.menubar"
        )
    )
    pids = []
    for app in running:
        getter = getattr(app, "processIdentifier", None)
        pids.append(getter() if callable(getter) else None)
    if all(pid is None for pid in pids):
        return max(len(running) - 1, 0)
    return sum(1 for pid in pids if pid != os.getpid())


def _exit_if_already_running():
    """Prevent multiple instances using two independent checks.

    Option A — file locks (work everywhere, survive crashes):
      Exclusive flocks on a lock under BASE_DIR and on one at a fixed
      per-user path, so launches with different PII_BUDDY_DIR values still
      collide.  The OS releases them when the process exits.

    Option B — NSRunningApplication (native macOS, bundle-aware):
      Counts other running processes that share our bundle identifier,
      always, as a second guard behind the locks.  Only effective when
      running as a .app bundle; a no-op without PyObjC.
    """
    global _lock_file

    # --- Option A: file locks (BASE_DIR one, then the fixed per-user one) ---
    paths = [_LOCK_FILE_PATH]
    if _USER_LOCK_FILE_PATH != _LOCK_FILE_PATH:
        paths.append(_USER_LOCK_FILE_PATH)

    acquired = []
    created = []
    for path in paths:
        state, lock_file = _try_lock(path, created)
        if state == "held":
            for f in acquired:
                # Leave an empty file, not our PID, once we step aside.
                try:
                    f.truncate(0)
                except OSError:
                    pass
                f.close()
            _remove_created(created)
            print("PII Buddy is already running (lock held).", file=sys.stderr)
            sys.exit(0)
        if state == "acquired":
            acquired.append(lock_file)

    if acquired:
        _lock_file = acquired[0]
        _extra_lock_files[:] = acquired[1:]

    # --- Option B: NSRunningApplication check (always) ---
    # An old build only holds the old lock path, so winning our flocks
    # doesn't prove we're alone.  A racing launch that lost the flock is
    # still visible for a few ms before it exits, so re-poll briefly: it
    # vanishes, an old-build holder doesn't.
    for attempt in range(_BUNDLE_POLLS):
        if _other_bundle_instances() == 0:
            return
        if attempt < _BUNDLE_POLLS - 1:
            time.sleep(_BUNDLE_POLL_INTERVAL)
    print("PII Buddy is already running (bundle check).", file=sys.stderr)
    sys.exit(0)

# Icon paths (relative to this file)
_ICONS_DIR = Path(__file__).parent / "data" / "icons"
_ICON_READY = str(_ICONS_DIR / "arbie_ready.png")
_ICON_PROCESSING = str(_ICONS_DIR / "arbie_processing.png")
_ICON_DONE = str(_ICONS_DIR / "arbie_done.png")

# Seconds to show the "done" icon before reverting to "ready"
_DONE_DISPLAY_SECONDS = 5

# Preferences file path
_PREFS_DIR = Path.home() / "PII_Buddy"
_PREFS_PATH = _PREFS_DIR / "menubar_prefs.json"

_GENERIC_ERROR_MESSAGE = (
    "Something went wrong. See the logs folder in your PII Buddy "
    "directory for details."
)

_LOGIN_UNAVAILABLE_MESSAGE = (
    "Start at Login isn't available in the App Store version. "
    "Add PII Buddy under System Settings > General > Login Items."
)

_LOGIN_FAILED_MESSAGE = (
    "Couldn't change the Start at Login setting. "
    "You can add PII Buddy under System Settings > General > Login Items."
)

# LaunchAgent for "Start at Login"
_LAUNCHAGENT_DIR = Path.home() / "Library" / "LaunchAgents"
_LAUNCHAGENT_LABEL = "dev.piibuddy.menubar"
_LAUNCHAGENT_PATH = _LAUNCHAGENT_DIR / f"{_LAUNCHAGENT_LABEL}.plist"


def _require_rumps():
    try:
        import rumps
        return rumps
    except ImportError:
        raise SystemExit(
            "Menu bar app requires 'rumps'. Install with:  pip install rumps"
        )


# --- Preferences persistence ---

def _load_prefs() -> dict:
    """Load menubar preferences from JSON file."""
    defaults = {
        "show_in_menubar": True,
        "show_in_dock": False,
        "start_at_login": False,
        "prompted_login": False,
    }
    try:
        if _PREFS_PATH.exists():
            stored = json.loads(_PREFS_PATH.read_text(encoding="utf-8"))
            defaults.update(stored)
    except Exception:
        pass
    return defaults


def _save_prefs(prefs: dict):
    """Save menubar preferences to JSON file."""
    try:
        _PREFS_DIR.mkdir(parents=True, exist_ok=True)
        _PREFS_PATH.write_text(
            json.dumps(prefs, indent=2), encoding="utf-8"
        )
    except Exception as e:
        logger.warning(f"Could not save preferences: {type(e).__name__}")


# --- LaunchAgent for login item ---

_STALE_LOG_PATH = "/tmp/pii_buddy_menubar.log"
_LOG_KEYS = ("StandardOutPath", "StandardErrorPath")


def _is_stale_log_path(value) -> bool:
    """True for a launchd log path that is the old /tmp file or outside LOGS_DIR."""
    if value is None:
        return False
    if not isinstance(value, str) or value == _STALE_LOG_PATH:
        return True
    try:
        root = os.path.realpath(LOGS_DIR)
        return os.path.commonpath([root, os.path.realpath(value)]) != root
    except ValueError:
        return True


def _build_launchagent_plist() -> dict:
    if getattr(sys, "frozen", False):
        # py2app bundle: sys.executable is the app's own launcher and
        # "-m pii_buddy.menubar" is meaningless to it.
        program_args = [sys.executable]
        extra = {}
    else:
        program_args = [sys.executable, "-m", "pii_buddy.menubar"]
        extra = {"WorkingDirectory": str(Path(__file__).parent.parent)}
    # No StandardOut/ErrorPath: main() logs to a rotating file itself,
    # and pointing launchd at the same file duplicates every line.
    return {
        "Label": _LAUNCHAGENT_LABEL,
        "ProgramArguments": program_args,
        **extra,
        "RunAtLoad": True,
        "KeepAlive": False,
    }


def _warn_if_stale_launchagent() -> bool:
    """Log one line when the login-item plist looks left over by an old build.

    Read-only: the plist is the user's and is only ever rewritten by the
    explicit "Start at login" toggle.  Returns True when it warned.
    """
    if PII_BUDDY_MAS_BUILD or not _LAUNCHAGENT_PATH.exists():
        return False
    try:
        old = plistlib.loads(_LAUNCHAGENT_PATH.read_bytes())
        args = old.get("ProgramArguments") or []
        stale = (
            any(_is_stale_log_path(old.get(k)) for k in _LOG_KEYS)
            or not args
            or not os.path.exists(args[0])
        )
    except Exception as e:
        logger.warning(f"Could not inspect login item: {type(e).__name__}")
        return False
    if stale:
        logger.warning(
            "Login item plist looks outdated; toggle Start at login off and on."
        )
    return stale


class LoginItemRefused(Exception):
    """The login-item plist was left alone; ``str(exc)`` is user-facing."""


_LOGIN_FOREIGN_MESSAGE = (
    "Another login item already uses PII Buddy's file in LaunchAgents, so "
    "it was left alone. Add PII Buddy under System Settings > General > "
    "Login Items instead."
)

_LOGIN_DIFFERS_MESSAGE = (
    "A different PII Buddy login item already exists and was left as it is."
)


def _write_launchagent_plist(allow_replace: bool) -> bool:
    """Atomically write the login-item plist; True once it is on disk.

    Never returns False: when the existing file is not ours to replace it
    raises ``LoginItemRefused`` and touches nothing.  A plist whose Label is
    not ours (or that can't be parsed) is never replaced.  One with our Label
    but different ProgramArguments is replaced only with ``allow_replace``,
    and then only ProgramArguments/WorkingDirectory/RunAtLoad change; every
    other key (log paths, EnvironmentVariables, ThrottleInterval, ...) stays.
    StandardOutPath/StandardErrorPath are dropped when they point at the old
    /tmp log or outside LOGS_DIR, since that file is world-readable.  An
    identical Label and ProgramArguments is left untouched, except that such
    log keys alone are removed (no confirmation: it only hardens the file).
    """
    _apply_launchagent_plist(allow_replace)
    return True


def _apply_launchagent_plist(allow_replace: bool) -> bool:
    """Do the work of ``_write_launchagent_plist``; True if the file changed."""
    new = _build_launchagent_plist()
    if _LAUNCHAGENT_PATH.exists():
        try:
            old = plistlib.loads(_LAUNCHAGENT_PATH.read_bytes())
        except Exception:
            old = {}
        if not isinstance(old, dict) or old.get("Label") != _LAUNCHAGENT_LABEL:
            logger.warning("Login item file is not ours; not overwriting it.")
            raise LoginItemRefused(_LOGIN_FOREIGN_MESSAGE)
        if old.get("ProgramArguments") != new["ProgramArguments"]:
            if not allow_replace:
                logger.warning("Login item differs; not overwriting it.")
                raise LoginItemRefused(_LOGIN_DIFFERS_MESSAGE)
            merged = dict(old)
            merged.pop("WorkingDirectory", None)
            for k in ("ProgramArguments", "WorkingDirectory", "RunAtLoad"):
                if k in new:
                    merged[k] = new[k]
        elif any(_is_stale_log_path(old.get(k)) for k in _LOG_KEYS):
            merged = dict(old)
        else:
            return False
        for k in _LOG_KEYS:
            if _is_stale_log_path(merged.get(k)):
                merged.pop(k, None)
        new = merged
    _LAUNCHAGENT_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=_LAUNCHAGENT_DIR, prefix=f".{_LAUNCHAGENT_PATH.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(plistlib.dumps(new))
        os.chmod(tmp, 0o644)
        os.replace(tmp, _LAUNCHAGENT_PATH)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def _set_login_item(enabled: bool, confirm_replace=None) -> bool:
    """Create or remove a LaunchAgent plist for auto-start at login.

    Returns False when enabling is not possible (MAS sandbox).  Raises
    ``LoginItemRefused`` when an existing plist is not ours to replace, or
    is ours but differs and ``confirm_replace`` (a no-argument callable
    asking the user) is absent or answers False.  Never reports success
    for a file it did not write.
    """
    if enabled:
        if PII_BUDDY_MAS_BUILD:
            # A LaunchAgent written into the sandbox container is never
            # read by launchd; honouring the toggle would be a lie.
            logger.warning("Start at Login is unavailable in the sandboxed build.")
            return False
        allow = False
        if _LAUNCHAGENT_PATH.exists() and confirm_replace is not None:
            try:
                differs = (
                    plistlib.loads(_LAUNCHAGENT_PATH.read_bytes()).get("ProgramArguments")
                    != _build_launchagent_plist()["ProgramArguments"]
                )
            except Exception:
                differs = False  # unparseable/foreign: the writer refuses it
            allow = bool(confirm_replace()) if differs else False
        if _apply_launchagent_plist(allow_replace=allow):
            logger.info(f"Login item written: {_LAUNCHAGENT_PATH}")
        else:
            logger.info("Login item unchanged.")
        return True
    else:
        if _LAUNCHAGENT_PATH.exists():
            # Unload first, then remove
            subprocess.run(
                ["launchctl", "unload", str(_LAUNCHAGENT_PATH)],
                capture_output=True,
            )
            _LAUNCHAGENT_PATH.unlink()
            logger.info("Login item removed.")
        return True


# --- Dock visibility ---

def _set_dock_visible(visible: bool):
    """Toggle Dock icon visibility via PyObjC."""
    try:
        from AppKit import NSApplication, NSImage
        # 0 = NSApplicationActivationPolicyRegular (show in Dock)
        # 1 = NSApplicationActivationPolicyAccessory (hide from Dock)
        policy = 0 if visible else 1
        NSApplication.sharedApplication().setActivationPolicy_(policy)
        if visible:
            icon = NSImage.alloc().initWithContentsOfFile_(_ICON_READY)
            if icon:
                NSApplication.sharedApplication().setApplicationIconImage_(icon)
    except ImportError:
        logger.warning("PyObjC not available — cannot toggle Dock visibility")


class PIIBuddyMenuBar:
    """macOS menu bar app for quick clipboard PII removal."""

    def __init__(self):
        rumps = _require_rumps()
        self._rumps = rumps
        self._last_mapping_path: Path | None = None
        self._processing = False
        self._done_timer = None
        self._last_entities_found = 0
        self._prefs = _load_prefs()

        # Use Arbie icon; title=None hides text label
        self.app = rumps.App(
            "PII Buddy", icon=_ICON_READY, title=None, quit_button=None
        )

        # Build Preferences submenu with checkable items
        self._menubar_toggle = rumps.MenuItem(
            "Show in Menu Bar", callback=self._on_toggle_menubar
        )
        self._menubar_toggle.state = self._prefs["show_in_menubar"]

        self._dock_toggle = rumps.MenuItem(
            "Show in Dock", callback=self._on_toggle_dock
        )
        self._dock_toggle.state = self._prefs["show_in_dock"]

        self._login_toggle = rumps.MenuItem(
            "Start at Login", callback=self._on_toggle_login
        )
        self._login_toggle.state = self._prefs["start_at_login"]

        prefs_menu = rumps.MenuItem("Preferences")
        prefs_menu[self._menubar_toggle.title] = self._menubar_toggle
        prefs_menu[self._dock_toggle.title] = self._dock_toggle
        prefs_menu[self._login_toggle.title] = self._login_toggle

        # Build rate submenu
        rate_menu = rumps.MenuItem("Rate Last Redaction")
        for stars in range(1, 6):
            label = "\u2605" * stars + "\u2606" * (5 - stars)
            rate_menu[label] = rumps.MenuItem(
                label, callback=lambda sender, s=stars: self._on_rate(s)
            )

        menu_items = [
            rumps.MenuItem(
                "Remove PII from Clipboard", callback=self._on_remove_pii
            ),
            rumps.MenuItem(
                "Restore Last Clipboard", callback=self._on_restore
            ),
            None,
        ]

        # MAS build only: sandboxed apps can't watch an arbitrary folder
        # without an explicit, user-granted, security-scoped bookmark.
        if PII_BUDDY_MAS_BUILD:
            from .mac_sandbox.bridge import PyObjCSandboxBridge

            self._watch_folder_store = BookmarkStore(bridge=PyObjCSandboxBridge())
            self._watch_folder_controller = WatchFolderMenuController(
                store=self._watch_folder_store, notify=self._notify
            )
            self._watch_folder_item = rumps.MenuItem(
                "Choose Watch Folder…",
                callback=self._watch_folder_controller.on_choose_folder,
            )
            existing = self._watch_folder_store.metadata()
            if existing and existing.get("path"):
                self._watch_folder_item.title = f"Watch Folder: {Path(existing['path']).name}"
                self._watch_folder_item.state = True
            menu_items.append(self._watch_folder_item)
            menu_items.append(None)

        menu_items += [
            rate_menu,
            rumps.MenuItem(
                "Report Missed PII...", callback=self._on_report_missed
            ),
            None,
            prefs_menu,
            None,
            rumps.MenuItem("Quit", callback=self._on_quit),
        ]

        self.app.menu = menu_items

        # Apply saved preferences
        _set_dock_visible(self._prefs["show_in_dock"])

        # Always set Arbie as the app icon (used by alerts and Dock)
        try:
            from AppKit import NSApplication, NSImage
            icon = NSImage.alloc().initWithContentsOfFile_(_ICON_READY)
            if icon:
                NSApplication.sharedApplication().setApplicationIconImage_(icon)
        except ImportError:
            pass

        # Pre-load spaCy in background so first click is fast
        threading.Thread(target=self._preload, daemon=True).start()

        # Set up Dock right-click menu after a short delay
        threading.Thread(target=self._setup_dock_menu, daemon=True).start()

        # Prompt to start at login on first launch (fires once after 2s)
        if not self._prefs.get("prompted_login") and not PII_BUDDY_MAS_BUILD:
            self._login_prompt_timer = rumps.Timer(
                self._prompt_start_at_login, 2
            )
            self._login_prompt_timer.start()

    def _preload(self):
        try:
            from .detector import get_nlp
            get_nlp()
        except Exception:
            pass

    def _prompt_start_at_login(self, _timer):
        """Ask user once whether to enable Start at Login."""
        _timer.stop()
        # Build NSAlert directly so we can set the Arbie icon on it
        try:
            from AppKit import NSAlert, NSImage, NSAlertFirstButtonReturn
            alert = NSAlert.alloc().init()
            alert.setMessageText_("Start at Login?")
            alert.setInformativeText_(
                "Would you like PII Buddy to start automatically "
                "when you log in?"
            )
            alert.addButtonWithTitle_("Yes")
            alert.addButtonWithTitle_("No")
            icon = NSImage.alloc().initWithContentsOfFile_(_ICON_READY)
            if icon:
                alert.setIcon_(icon)
            response = alert.runModal()
            clicked_yes = response == NSAlertFirstButtonReturn
        except ImportError:
            # Fallback to rumps if AppKit unavailable
            response = self._rumps.alert(
                title="Start at Login?",
                message=(
                    "Would you like PII Buddy to start automatically "
                    "when you log in?"
                ),
                ok="Yes",
                cancel="No",
            )
            clicked_yes = response == 1
        if clicked_yes:
            try:
                enabled = _set_login_item(True, self._confirm_replace_login_item)
            except LoginItemRefused as e:
                self._notify(str(e))
            except OSError as e:
                logger.error(f"Login item failed: {type(e).__name__}")
                self._notify(_LOGIN_FAILED_MESSAGE)
            else:
                if enabled:
                    self._login_toggle.state = True
                    self._prefs["start_at_login"] = True
                else:
                    self._notify(_LOGIN_UNAVAILABLE_MESSAGE)
        self._prefs["prompted_login"] = True
        _save_prefs(self._prefs)

    # --- Dock right-click menu (PyObjC) ---

    def _setup_dock_menu(self):
        """Add a right-click menu to the Dock icon via PyObjC."""
        import time
        time.sleep(1)  # wait for rumps to finish NSApp setup

        try:
            from AppKit import NSApplication, NSMenu, NSMenuItem
            from Foundation import NSObject
            import objc

            # Create dock menu
            dock_menu = NSMenu.alloc().init()

            # We use a simple NSObject subclass as the action target
            _app_ref = self

            class _Target(NSObject):
                @objc.typedSelector(b'v@:@')
                def removePII_(self, sender):
                    _app_ref._dock_remove_pii()

                @objc.typedSelector(b'v@:@')
                def restoreLast_(self, sender):
                    _app_ref._on_restore(None)

            target = _Target.alloc().init()
            self._dock_target = target  # prevent GC

            remove_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Remove PII from Clipboard", b"removePII:", ""
            )
            remove_item.setTarget_(target)
            dock_menu.addItem_(remove_item)

            restore_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Restore Last Clipboard", b"restoreLast:", ""
            )
            restore_item.setTarget_(target)
            dock_menu.addItem_(restore_item)

            # Store and patch the delegate
            self._dock_menu = dock_menu
            nsapp = NSApplication.sharedApplication()
            delegate = nsapp.delegate()
            _menu_ref = dock_menu

            def applicationDockMenu_(delegate_self, app):
                return _menu_ref

            objc.classAddMethod(
                type(delegate),
                b"applicationDockMenu:",
                applicationDockMenu_,
            )
        except Exception as e:
            logger.debug(f"Dock menu setup skipped: {type(e).__name__}")

    def _dock_remove_pii(self):
        # rumps keys menu items by title, which reads "Processing..." mid-run.
        try:
            item = self.app.menu["Remove PII from Clipboard"]
        except KeyError:
            item = None
        self._on_remove_pii(item)

    # --- Icon state management ---

    def _set_icon(self, icon_path: str):
        self.app.icon = icon_path

    def _show_done_then_reset(self):
        """Show done icon, then revert to ready after a delay."""
        self._set_icon(_ICON_DONE)
        if self._done_timer:
            self._done_timer.cancel()
        self._done_timer = threading.Timer(
            _DONE_DISPLAY_SECONDS, self._set_icon, args=[_ICON_READY]
        )
        self._done_timer.daemon = True
        self._done_timer.start()

    # --- Preference toggles ---

    def _on_toggle_menubar(self, sender):
        new_state = not sender.state
        # Must keep at least one visible
        if not new_state and not self._dock_toggle.state:
            self._notify("Enable 'Show in Dock' first.")
            return
        sender.state = new_state
        self._prefs["show_in_menubar"] = new_state
        _save_prefs(self._prefs)
        if new_state:
            self._set_icon(_ICON_READY)
        else:
            # Hide menu bar icon (set to tiny transparent; keeps app alive)
            self.app.icon = None
            self.app.title = ""

    def _on_toggle_dock(self, sender):
        new_state = not sender.state
        # Must keep at least one visible
        if not new_state and not self._menubar_toggle.state:
            self._notify("Enable 'Show in Menu Bar' first.")
            return
        sender.state = new_state
        self._prefs["show_in_dock"] = new_state
        _save_prefs(self._prefs)
        _set_dock_visible(new_state)

    def _confirm_replace_login_item(self) -> bool:
        response = self._rumps.alert(
            title="Replace existing login item?",
            message=(
                "A different PII Buddy login item is already installed. "
                "Replace it with this copy?"
            ),
            ok="Replace",
            cancel="Keep existing",
        )
        return response == 1

    def _on_toggle_login(self, sender):
        new_state = not sender.state
        try:
            changed = _set_login_item(new_state, self._confirm_replace_login_item)
        except LoginItemRefused as e:
            self._notify(str(e))
            return
        except OSError as e:
            logger.error(f"Login item failed: {type(e).__name__}")
            self._notify(_LOGIN_FAILED_MESSAGE)
            return
        if not changed:
            self._notify(_LOGIN_UNAVAILABLE_MESSAGE)
            return
        sender.state = new_state
        self._prefs["start_at_login"] = new_state
        _save_prefs(self._prefs)

    # --- Feedback callbacks ---

    def _on_rate(self, stars: int):
        """Record a star rating for the last redaction."""
        from .feedback import record_rating

        record_rating(
            rating=stars,
            source="menubar",
            entities_found=self._last_entities_found if hasattr(self, "_last_entities_found") else 0,
        )
        self._notify(f"Rated {'*' * stars} — thanks for the feedback!")

    def _on_report_missed(self, _sender):
        """Open GitHub issue template for reporting missed PII."""
        import webbrowser

        url = "https://github.com/rahhbster/pii_buddy/issues/new?template=missed-pii.md&labels=detection-quality"
        webbrowser.open(url)

    # --- Menu callbacks ---

    def _on_remove_pii(self, sender):
        if self._processing:
            return
        self._processing = True
        if sender:
            sender.title = "Processing..."
        self._set_icon(_ICON_PROCESSING)
        threading.Thread(
            target=self._do_remove_pii,
            args=(sender,),
            daemon=True,
        ).start()

    def _on_restore(self, _sender):
        if self._processing:
            return
        if not self._last_mapping_path or not self._last_mapping_path.exists():
            self._notify("No recent mapping to restore from.")
            return
        self._processing = True
        self._set_icon(_ICON_PROCESSING)
        threading.Thread(target=self._do_restore, daemon=True).start()

    def _on_quit(self, _sender):
        if self._done_timer:
            self._done_timer.cancel()
        self._rumps.quit_application()

    # --- Processing (background thread) ---

    def _do_remove_pii(self, sender):
        try:
            text = self._read_clipboard()
            if not text:
                self._notify("Clipboard is empty.")
                self._set_icon(_ICON_READY)
                return

            from .config import BASE_DIR, MAPPINGS_DIR
            from .detector import detect_pii
            from .redactor import redact
            from .settings import resolve_settings, seed_settings_file

            seed_settings_file(BASE_DIR)
            settings = resolve_settings(base_dir=BASE_DIR)

            entities = detect_pii(text)
            if not entities:
                self._notify("No PII detected in clipboard text.")
                self._set_icon(_ICON_READY)
                return

            redacted_text, mapping = redact(text, entities)

            # Cloud verification if configured
            if settings.verify_enabled and settings.verify_api_key:
                try:
                    from .verifier import verify_and_patch
                    redacted_text, mapping = verify_and_patch(
                        redacted_text, mapping, settings
                    )
                except Exception as e:
                    logger.warning(f"Verify skipped: {type(e).__name__}")

            # Mapping first: if it can't be saved the clipboard still holds
            # the original, which is otherwise unrecoverable.
            MAPPINGS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            mapping["metadata"] = {
                "source": "menubar",
                "processed_at": datetime.now().isoformat(),
                "entities_found": len(entities),
            }
            mapping_path = _claim_mapping_path(MAPPINGS_DIR, datetime.now())
            try:
                _write_private_text(
                    mapping_path, json.dumps(mapping, indent=2, ensure_ascii=False)
                )
            except BaseException:
                try:
                    mapping_path.unlink()
                except OSError:
                    pass
                raise
            if not self._copy_back(redacted_text):
                # The clipboard still holds the original, so the mapping is
                # useless and would sit on disk holding the PII.
                try:
                    mapping_path.unlink()
                except OSError:
                    pass
                return
            self._last_mapping_path = mapping_path
            self._last_entities_found = len(entities)

            self._notify(
                f"PII Removed! {len(entities)} items redacted. "
                f"Copied back to clipboard."
            )
            self._show_done_then_reset()
        except Exception as e:
            self._notify(_GENERIC_ERROR_MESSAGE)
            _log_failure("Menu bar error", e)
            self._set_icon(_ICON_READY)
        finally:
            if sender:
                sender.title = "Remove PII from Clipboard"
            self._processing = False

    def _do_restore(self):
        try:
            text = self._read_clipboard()
            if not text:
                self._notify("Clipboard is empty.")
                self._set_icon(_ICON_READY)
                return

            from .restorer import restore
            restored = restore(text, self._last_mapping_path)
            if not self._copy_back(restored):
                return
            self._notify("PII Restored! Original text copied to clipboard.")
            self._show_done_then_reset()
        except Exception as e:
            self._notify(_GENERIC_ERROR_MESSAGE)
            _log_failure("Menu bar restore error", e)
            self._set_icon(_ICON_READY)
        finally:
            self._processing = False

    # --- Helpers ---

    @staticmethod
    def _read_clipboard() -> str:
        result = subprocess.run(
            ["pbpaste"], capture_output=True, text=True
        )
        return result.stdout.strip()

    @staticmethod
    def _write_clipboard(text: str):
        subprocess.run(["pbcopy"], input=text, text=True, check=True)

    def _copy_back(self, text: str) -> bool:
        """Write to the clipboard; on failure say so without the text."""
        try:
            self._write_clipboard(text)
        except (subprocess.CalledProcessError, OSError) as e:
            logger.error(f"Clipboard write failed: {type(e).__name__}")
            self._notify(
                "Couldn't copy to the clipboard. Your clipboard is unchanged."
            )
            self._set_icon(_ICON_READY)
            return False
        return True

    def _notify(self, message: str):
        self._rumps.notification("PII Buddy", "", message)

    def run(self):
        self.app.run()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        logger.addHandler(_make_log_handler())
    except OSError as e:
        print(f"PII Buddy could not open its log file: {e}", file=sys.stderr)
    _exit_if_already_running()
    _warn_if_stale_launchagent()
    app = PIIBuddyMenuBar()
    app.run()


if __name__ == "__main__":
    main()
