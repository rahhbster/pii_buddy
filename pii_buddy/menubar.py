"""Optional Mac menu bar app for PII Buddy.

Sits in the macOS menu bar and provides one-click PII removal from
the clipboard.  Not required for normal PII Buddy operation.

Requires:  pip install rumps

Usage:
    python main.py --menubar
    python -m pii_buddy.menubar
"""

import json
import logging
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("pii_buddy")

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
        logger.warning(f"Could not save preferences: {e}")


# --- LaunchAgent for login item ---

def _set_login_item(enabled: bool):
    """Create or remove a LaunchAgent plist for auto-start at login."""
    if enabled:
        python_path = sys.executable
        project_dir = str(Path(__file__).parent.parent)
        plist = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_LAUNCHAGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>-m</string>
        <string>pii_buddy.menubar</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{project_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/tmp/pii_buddy_menubar.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/pii_buddy_menubar.log</string>
</dict>
</plist>
"""
        _LAUNCHAGENT_DIR.mkdir(parents=True, exist_ok=True)
        _LAUNCHAGENT_PATH.write_text(plist, encoding="utf-8")
        logger.info(f"Login item created: {_LAUNCHAGENT_PATH}")
    else:
        if _LAUNCHAGENT_PATH.exists():
            # Unload first, then remove
            subprocess.run(
                ["launchctl", "unload", str(_LAUNCHAGENT_PATH)],
                capture_output=True,
            )
            _LAUNCHAGENT_PATH.unlink()
            logger.info("Login item removed.")


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

        self.app.menu = [
            rumps.MenuItem(
                "Remove PII from Clipboard", callback=self._on_remove_pii
            ),
            rumps.MenuItem(
                "Restore Last Clipboard", callback=self._on_restore
            ),
            None,
            prefs_menu,
            None,
            rumps.MenuItem("Quit", callback=self._on_quit),
        ]

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
        if not self._prefs.get("prompted_login"):
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
            self._login_toggle.state = True
            self._prefs["start_at_login"] = True
            _set_login_item(True)
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
                    _app_ref._on_remove_pii(
                        _app_ref.app.menu["Remove PII from Clipboard"]
                    )

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
            logger.debug(f"Dock menu setup skipped: {e}")

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

    def _on_toggle_login(self, sender):
        new_state = not sender.state
        sender.state = new_state
        self._prefs["start_at_login"] = new_state
        _save_prefs(self._prefs)
        _set_login_item(new_state)

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
                    logger.warning(f"Verify skipped: {e}")

            self._write_clipboard(redacted_text)

            # Save mapping
            MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            mapping["metadata"] = {
                "source": "menubar",
                "processed_at": datetime.now().isoformat(),
                "entities_found": len(entities),
            }
            mapping_path = MAPPINGS_DIR / f"clipboard_{timestamp}.map.json"
            mapping_path.write_text(
                json.dumps(mapping, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self._last_mapping_path = mapping_path

            self._notify(
                f"PII Removed! {len(entities)} items redacted. "
                f"Copied back to clipboard."
            )
            self._show_done_then_reset()
        except Exception as e:
            self._notify(f"Error: {e}")
            logger.error(f"Menu bar error: {e}", exc_info=True)
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
            self._write_clipboard(restored)
            self._notify("PII Restored! Original text copied to clipboard.")
            self._show_done_then_reset()
        except Exception as e:
            self._notify(f"Error: {e}")
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
        subprocess.run(["pbcopy"], input=text, text=True)

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
    app = PIIBuddyMenuBar()
    app.run()


if __name__ == "__main__":
    main()
