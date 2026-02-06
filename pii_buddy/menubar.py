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
import threading
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("pii_buddy")


def _require_rumps():
    try:
        import rumps
        return rumps
    except ImportError:
        raise SystemExit(
            "Menu bar app requires 'rumps'. Install with:  pip install rumps"
        )


class PIIBuddyMenuBar:
    """macOS menu bar app for quick clipboard PII removal."""

    def __init__(self):
        rumps = _require_rumps()
        self._rumps = rumps
        self._last_mapping_path: Path | None = None
        self._processing = False

        self.app = rumps.App("PII Buddy", title="PII", quit_button=None)
        self.app.menu = [
            rumps.MenuItem(
                "Remove PII from Clipboard", callback=self._on_remove_pii
            ),
            rumps.MenuItem(
                "Restore Last Clipboard", callback=self._on_restore
            ),
            None,  # separator
            rumps.MenuItem("Quit", callback=self._on_quit),
        ]

        # Pre-load spaCy in background so first click is fast
        threading.Thread(target=self._preload, daemon=True).start()

    def _preload(self):
        try:
            from .detector import get_nlp
            get_nlp()
        except Exception:
            pass

    # --- Menu callbacks ---

    def _on_remove_pii(self, sender):
        if self._processing:
            return
        self._processing = True
        sender.title = "Processing..."
        threading.Thread(
            target=self._do_remove_pii,
            args=(sender,),
            daemon=True,
        ).start()

    def _on_restore(self, _sender):
        if self._processing:
            return
        if not self._last_mapping_path or not self._last_mapping_path.exists():
            self._rumps.notification(
                "PII Buddy", "", "No recent mapping to restore from."
            )
            return
        self._processing = True
        threading.Thread(target=self._do_restore, daemon=True).start()

    def _on_quit(self, _sender):
        self._rumps.quit_application()

    # --- Processing (runs on background thread) ---

    def _do_remove_pii(self, sender):
        try:
            text = self._read_clipboard()
            if not text:
                self._notify("Clipboard is empty.")
                return

            from .config import BASE_DIR, MAPPINGS_DIR
            from .detector import detect_pii
            from .redactor import redact
            from .settings import resolve_settings, seed_settings_file

            # Load settings (picks up verify config from settings.conf)
            seed_settings_file(BASE_DIR)
            settings = resolve_settings(base_dir=BASE_DIR)

            entities = detect_pii(text)
            if not entities:
                self._notify("No PII detected in clipboard text.")
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

            # Write redacted text back to clipboard
            self._write_clipboard(redacted_text)

            # Save mapping for reversibility
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
        except Exception as e:
            self._notify(f"Error: {e}")
            logger.error(f"Menu bar error: {e}", exc_info=True)
        finally:
            sender.title = "Remove PII from Clipboard"
            self._processing = False

    def _do_restore(self):
        try:
            text = self._read_clipboard()
            if not text:
                self._notify("Clipboard is empty.")
                return

            from .restorer import restore
            restored = restore(text, self._last_mapping_path)
            self._write_clipboard(restored)
            self._notify("PII Restored! Original text copied to clipboard.")
        except Exception as e:
            self._notify(f"Error: {e}")
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
